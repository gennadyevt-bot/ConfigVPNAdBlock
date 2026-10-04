package mitm

import (
	"configadblock/mitm/internal/quicfast"
	"fmt"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
	"io"
)

func attachQuicFastPath(tun *tunCounter) {
	wgUpstreamMu.RLock()
	defer wgUpstreamMu.RUnlock()
	u := wgUpstream
	if u == nil {
		return
	}
	r := quicfast.New(quicfast.Config{
		Reserve: func(v6 bool) (quicfast.Reservation, error) {
			protocol := ipv4.ProtocolNumber
			if v6 {
				protocol = ipv6.ProtocolNumber
			}
			ep, err := u.st.NewEndpoint(udp.ProtocolNumber, protocol, &waiter.Queue{})
			if err != nil {
				return quicfast.Reservation{}, fmt.Errorf("UDP port reserve: %s", err)
			}
			if v6 {
				ep.SocketOptions().SetV6Only(true)
			}
			// Reserve an existing-stack port, with no gonet/socket dial or UDP relay.
			if err := ep.Bind(tcpip.FullAddress{NIC: 1}); err != nil {
				ep.Close()
				return quicfast.Reservation{}, fmt.Errorf("UDP bind: %s", err)
			}
			local, err := ep.GetLocalAddress()
			if err != nil {
				ep.Close()
				return quicfast.Reservation{}, fmt.Errorf("UDP port: %s", err)
			}
			return quicfast.Reservation{Port: local.Port, Close: ep.Close}, nil
		},
		Send: func(b []byte) error {
			n, err := u.f.Write(b)
			if err != nil {
				u.trace.PacketTxDropped.Add(1)
				return err
			}
			if n != len(b) {
				u.trace.PacketTxDropped.Add(1)
				return io.ErrShortWrite
			}
			u.counts.tx.Add(1)
			return nil
		},
		Deliver: func(b []byte) error {
			n, err := tun.Write(b)
			if err != nil {
				u.trace.PacketRxDropped.Add(1)
				return err
			}
			if n != len(b) {
				u.trace.PacketRxDropped.Add(1)
				return io.ErrShortWrite
			}
			return nil
		},
		// Authenticated SNI is authoritative; shared/stale DNS IP mappings
		// must not widen the bypass or block an unrelated video hostname.
		Blocked: func(host, ip string) bool { return isBlocked(host) }, Log: flowLog,
	})
	tun.fast = r
	u.link.rawMu.Lock()
	u.link.raw = r
	u.link.rawMu.Unlock()
	flowLog("QUIC_FAST_READY packet_socket video_domains_only DNS_BLOCK_AND_TCP_MITM_ON")
}

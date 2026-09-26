package mitm

// wgstack.go — исходящий gVisor-стек поверх WG socketpair (проект №4,
// integration-unified-adblock). Когда активен, dialTCP/dialUDP движка идут
// через WireGuard-туннель, а не через прямые защищённые сокеты:
// Apps -> TUN -> AdBlock filter/MITM -> WG stack -> WireGuard -> Internet.

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

var (
	wgUpstreamMu sync.RWMutex
	wgUpstream   *wgUpstreamStack
)

type wgUpstreamStack struct {
	st    *stack.Stack
	local string
}

func startWgUpstream(fd int64, mtu int64, localIP string) error {
	wgUpstreamMu.Lock()
	defer wgUpstreamMu.Unlock()
	stopWgUpstreamLocked()
	if fd < 0 {
		return fmt.Errorf("wg fd invalid: %d", fd)
	}
	f := os.NewFile(uintptr(fd), "wg-tun")
	if f == nil {
		return fmt.Errorf("wg fd open failed: %d", fd)
	}
	ep, err := iobased.New(&tunCounter{f: f}, uint32(mtu), 0)
	if err != nil {
		f.Close()
		return fmt.Errorf("wg iobased: %w", err)
	}
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if terr := st.CreateNICWithOptions(1, ep, stack.NICOptions{Disabled: false, QDisc: nil}); terr != nil {
		f.Close()
		return fmt.Errorf("wg nic: %s", terr)
	}
	if terr := st.SetPromiscuousMode(1, true); terr != nil {
		f.Close()
		return fmt.Errorf("wg promisc: %s", terr)
	}
	if terr := st.SetSpoofing(1, true); terr != nil {
		f.Close()
		return fmt.Errorf("wg spoofing: %s", terr)
	}
	ip := net.ParseIP(localIP)
	if ip == nil {
		f.Close()
		return fmt.Errorf("wg local ip invalid: %q", localIP)
	}
	if ip4 := ip.To4(); ip4 != nil {
		var a4 [4]byte
		copy(a4[:], ip4)
		st.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4(a4), PrefixLen: 32},
		}, stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint})
	} else if ip16 := ip.To16(); ip16 != nil {
		var a16 [16]byte
		copy(a16[:], ip16)
		st.AddProtocolAddress(1, tcpip.ProtocolAddress{
			Protocol:          ipv6.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16(a16), PrefixLen: 128},
		}, stack.AddressProperties{PEB: stack.CanBePrimaryEndpoint})
	} else {
		f.Close()
		return fmt.Errorf("wg local ip invalid: %q", localIP)
	}
	st.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	wgUpstream = &wgUpstreamStack{st: st, local: localIP}
	flowLog("UNIFIED_WG_UPSTREAM_READY local=" + localIP)
	return nil
}

func stopWgUpstreamLocked() {
	if wgUpstream != nil {
		wgUpstream.st.Close()
		wgUpstream = nil
	}
}

func stopWgUpstream() {
	wgUpstreamMu.Lock()
	defer wgUpstreamMu.Unlock()
	stopWgUpstreamLocked()
}

func wgUpstreamActive() bool {
	wgUpstreamMu.RLock()
	defer wgUpstreamMu.RUnlock()
	return wgUpstream != nil
}

func wgStackRef() *stack.Stack {
	wgUpstreamMu.RLock()
	defer wgUpstreamMu.RUnlock()
	if wgUpstream == nil {
		return nil
	}
	return wgUpstream.st
}

func wgSplitAddr(addr string) (string, uint16, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return "", 0, fmt.Errorf("wg bad port: %q", port)
	}
	return host, uint16(p), nil
}

func wgDialTCP(addr string) (net.Conn, error) {
	st := wgStackRef()
	if st == nil {
		return nil, fmt.Errorf("wg upstream not active")
	}
	host, port, err := wgSplitAddr(addr)
	if err != nil {
		return nil, err
	}
	ip, err := wgResolve(host)
	if err != nil {
		return nil, err
	}
	fa := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip), Port: port}
	return gonet.DialTCP(st, fa, nil)
}

func wgDialUDP(addr string) (net.Conn, error) {
	st := wgStackRef()
	if st == nil {
		return nil, fmt.Errorf("wg upstream not active")
	}
	host, port, err := wgSplitAddr(addr)
	if err != nil {
		return nil, err
	}
	ip, err := wgResolve(host)
	if err != nil {
		return nil, err
	}
	fa := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip), Port: port}
	return gonet.DialUDP(st, nil, &fa, ipv4.ProtocolNumber)
}

// wgResolve: hostname -> IP через DNS A-запрос через WG-стек (8.8.8.8:53).
// Нужен, потому что в unified-режиме прямого интернета у процесса нет.
func wgResolve(host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	st := wgStackRef()
	if st == nil {
		return nil, fmt.Errorf("wg upstream not active")
	}
	fa := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{8, 8, 8, 8}), Port: 53}
	c, err := gonet.DialUDP(st, nil, &fa, ipv4.ProtocolNumber)
	if err != nil {
		return nil, fmt.Errorf("wg dns dial: %w", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := c.Write(buildDNSQueryA(host)); err != nil {
		return nil, err
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseDNSA(buf[:n])
}

func buildDNSQueryA(host string) []byte {
	qname := make([]byte, 0, len(host)+2)
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 {
			continue
		}
		if len(label) > 63 {
			label = label[:63]
		}
		qname = append(qname, byte(len(label)))
		qname = append(qname, label...)
	}
	qname = append(qname, 0)
	msg := make([]byte, 12+len(qname)+4)
	binary.BigEndian.PutUint16(msg[0:2], 0xCAB1) // ID
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT
	copy(msg[12:], qname)
	off := 12 + len(qname)
	binary.BigEndian.PutUint16(msg[off:off+2], 1)   // QTYPE A
	binary.BigEndian.PutUint16(msg[off+2:off+4], 1) // QCLASS IN
	return msg
}

func parseDNSA(msg []byte) (net.IP, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("dns: short")
	}
	ancount := int(binary.BigEndian.Uint16(msg[6:8]))
	if ancount == 0 {
		return nil, fmt.Errorf("dns: no answers")
	}
	off := 12
	for off < len(msg) && msg[off] != 0 {
		off += 1 + int(msg[off])
	}
	if off >= len(msg) {
		return nil, fmt.Errorf("dns: bad question")
	}
	off++  // null-terminator
	off += 4 // QTYPE + QCLASS
	for i := 0; i < ancount && off+12 <= len(msg); i++ {
		if msg[off]&0xC0 == 0xC0 {
			off += 2
		} else {
			for off < len(msg) && msg[off] != 0 {
				off += 1 + int(msg[off])
			}
			off++
		}
		if off+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		rdataOff := off + 10
		if typ == 1 && rdlen == 4 && rdataOff+4 <= len(msg) {
			return net.IPv4(msg[rdataOff], msg[rdataOff+1], msg[rdataOff+2], msg[rdataOff+3]), nil
		}
		off = rdataOff + rdlen
	}
	return nil, fmt.Errorf("dns: no A record")
}

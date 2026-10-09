package mitm

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// Metadata only; tracing must never make a packet or hostname policy decision.
func appScopeTCPEvent(stage, client, dst, sni, decision, reason string) {
	if !AppScopeContentAllowlistEnabled() {
		return
	}
	host, source := sni, "sni"
	if host == "" {
		source = "unknown"
		ip, _, err := net.SplitHostPort(dst)
		if err == nil {
			if name, known := dnsIPMapGet(ip); known {
				host, source = name, "dns"
			}
		}
	}
	flowLog(fmt.Sprintf("APP_SCOPE_TCP stage=%s client=%s dst=%s host=%q hostSource=%s decision=%s reason=%q", stage, client, dst, host, source, decision, reason))
}

func appScopeTraceTCPPacket(b []byte, toApp bool) {
	if !AppScopeContentAllowlistEnabled() {
		return
	}
	p, ok := parseBrowserPacket(b)
	if !ok || p.proto != 6 {
		return
	}
	flags := b[p.off+13]
	// SYN/retransmissions, SYN-ACK and RST locate a missing handshake without
	// flooding the ring with data packets or recording any payload.
	if flags&(2|4) == 0 {
		return
	}
	client, dst, stage := p.src.String(), p.dst.String(), "tun_read"
	if toApp {
		client, dst, stage = p.dst.String(), p.src.String(), "tun_write"
	}
	appScopeTCPEvent(stage, client, dst, "", "observe", fmt.Sprintf("tcp_flags=0x%02x bytes=%d", flags, len(b)))
}

func appScopeDNSDelivery(host, source string, reply []byte, written int, err error) {
	if !AppScopeContentAllowlistEnabled() {
		return
	}
	var m dnsmessage.Message
	var addresses []string
	var rcode any = "unparsed"
	if m.Unpack(reply) == nil {
		rcode = m.RCode
		for _, answer := range m.Answers {
			switch a := answer.Body.(type) {
			case *dnsmessage.AResource:
				addresses = append(addresses, netip.AddrFrom4(a.A).String())
			case *dnsmessage.AAAAResource:
				addresses = append(addresses, netip.AddrFrom16(a.AAAA).String())
			}
		}
	}
	flowLog(fmt.Sprintf("APP_SCOPE_DNS_DELIVERY host=%q source=%s rcode=%v answers=%q written=%d expected=%d err=%v", host, source, rcode, strings.Join(addresses, ","), written, len(reply), err))
}

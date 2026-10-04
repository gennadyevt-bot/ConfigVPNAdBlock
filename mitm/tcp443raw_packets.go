package mitm

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Observation only. A relay Write can just enqueue bytes in gVisor. Observe
// successful writes to the Android TUN separately, and subsequent app ACKs.
// Payload totals here include retransmissions; ACK/window values are raw TCP.
var raw443PacketFlows = struct {
	sync.RWMutex
	flows map[string]*raw443Flow
}{flows: make(map[string]*raw443Flow)}

func raw443PacketKey(app, remote netip.AddrPort) string { return app.String() + ">" + remote.String() }
func raw443AttachPackets(f *raw443Flow, id stack.TransportEndpointID) {
	a, err := netip.ParseAddr(id.RemoteAddress.String())
	if err != nil {
		return
	}
	d, err := netip.ParseAddr(id.LocalAddress.String())
	if err != nil {
		return
	}
	key := raw443PacketKey(netip.AddrPortFrom(a, id.RemotePort), netip.AddrPortFrom(d, id.LocalPort))
	f.packetKey = key
	raw443PacketFlows.Lock()
	raw443PacketFlows.flows[key] = f
	raw443PacketFlows.Unlock()
}
func raw443DetachPackets(f *raw443Flow) {
	raw443PacketFlows.Lock()
	if raw443PacketFlows.flows[f.packetKey] == f {
		delete(raw443PacketFlows.flows, f.packetKey)
	}
	raw443PacketFlows.Unlock()
}
func raw443ObserveTunPacket(p []byte, toApp bool) {
	// Fast exit when no diagnostic flow exists. Never intercept or mutate packets.
	raw443PacketFlows.RLock()
	if len(raw443PacketFlows.flows) == 0 {
		raw443PacketFlows.RUnlock()
		return
	}
	raw443PacketFlows.RUnlock()
	if len(p) < 20 {
		return
	}
	var src, dst netip.Addr
	var off, total int
	switch p[0] >> 4 {
	case 4:
		off = int(p[0]&15) * 4
		total = int(binary.BigEndian.Uint16(p[2:4]))
		if off < 20 || p[9] != 6 || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return
		}
		src = netip.AddrFrom4([4]byte(p[12:16]))
		dst = netip.AddrFrom4([4]byte(p[16:20]))
	case 6:
		if len(p) < 40 || p[6] != 6 {
			return
		} // extension headers deliberately unobserved
		off = 40
		total = 40 + int(binary.BigEndian.Uint16(p[4:6]))
		src = netip.AddrFrom16([16]byte(p[8:24]))
		dst = netip.AddrFrom16([16]byte(p[24:40]))
	default:
		return
	}
	if total > len(p) || total < off+20 {
		return
	}
	h := p[off:total]
	hlen := int(h[12]>>4) * 4
	if hlen < 20 || hlen > len(h) {
		return
	}
	a := netip.AddrPortFrom(src, binary.BigEndian.Uint16(h[:2]))
	d := netip.AddrPortFrom(dst, binary.BigEndian.Uint16(h[2:4]))
	if toApp {
		a, d = d, a
	}
	if d.Port() != 443 {
		return
	}
	raw443PacketFlows.RLock()
	f := raw443PacketFlows.flows[raw443PacketKey(a, d)]
	raw443PacketFlows.RUnlock()
	if f == nil {
		return
	}
	now := time.Now().UnixMilli()
	f.mu.Lock()
	if toApp {
		f.summary.TunPacketsToApp++
		f.summary.TunPayloadBytesToApp += int64(len(h) - hlen)
		f.summary.TunLastWriteAt = now
		if h[13]&4 != 0 {
			f.summary.TunRST = true
		}
	} else {
		f.summary.AppWindow = binary.BigEndian.Uint16(h[14:16])
		if h[13]&16 != 0 {
			f.summary.AppACKCount++
			f.summary.AppLastACKAt = now
			f.summary.AppLastACK = binary.BigEndian.Uint32(h[8:12])
		}
		if h[13]&4 != 0 {
			f.summary.AppRST = true
		}
	}
	f.mu.Unlock()
}

package mitm

import (
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net/netip"
	"sync"
	"time"
)

// Passive TCP delivery evidence. Payload totals include retransmissions.
// ACKs prove acceptance by the app TCP stack, not consumption by Chrome or HTTP success.
var safeTLSPackets = struct {
	sync.RWMutex
	flows map[string]*safeTLSFlow
}{flows: make(map[string]*safeTLSFlow)}

func safeTLSHasPackets() bool {
	safeTLSPackets.RLock()
	defer safeTLSPackets.RUnlock()
	return len(safeTLSPackets.flows) > 0
}
func safeTLSAttachPackets(f *safeTLSFlow, id stack.TransportEndpointID) {
	a, e := netip.ParseAddr(id.RemoteAddress.String())
	if e != nil {
		return
	}
	d, e := netip.ParseAddr(id.LocalAddress.String())
	if e != nil {
		return
	}
	f.packetKey = raw443PacketKey(netip.AddrPortFrom(a, id.RemotePort), netip.AddrPortFrom(d, id.LocalPort))
	safeTLSPackets.Lock()
	safeTLSPackets.flows[f.packetKey] = f
	safeTLSPackets.Unlock()
}
func safeTLSDetachPackets(f *safeTLSFlow) {
	safeTLSPackets.Lock()
	if safeTLSPackets.flows[f.packetKey] == f {
		delete(safeTLSPackets.flows, f.packetKey)
	}
	safeTLSPackets.Unlock()
}
func safeTLSObservePacket(key string, h []byte, hlen int, toApp bool) {
	safeTLSPackets.RLock()
	f := safeTLSPackets.flows[key]
	safeTLSPackets.RUnlock()
	if f == nil {
		return
	}
	now := time.Now().UnixMilli()
	f.mu.Lock()
	defer f.mu.Unlock()
	v := &f.v
	if toApp {
		v.TunPackets++
		v.TunPayload += int64(len(h) - hlen)
		v.TunLastAt = now
		v.TunRST = v.TunRST || h[13]&4 != 0
		v.TunFIN = v.TunFIN || h[13]&1 != 0
		if n := len(h) - hlen; n > 0 {
			end := binary.BigEndian.Uint32(h[4:8]) + uint32(n)
			if !f.dataSeen || int32(end-v.TunDataEnd) > 0 {
				v.TunDataEnd = end
			}
			f.dataSeen = true
		}
	} else {
		v.AppWindow = binary.BigEndian.Uint16(h[14:16])
		v.AppRST = v.AppRST || h[13]&4 != 0
		v.AppFIN = v.AppFIN || h[13]&1 != 0
		if h[13]&16 != 0 {
			ack := binary.BigEndian.Uint32(h[8:12])
			v.AppACKs++
			v.AppACKAt = now
			if !f.ackSeen || int32(ack-v.AppACK) >= 0 {
				v.AppACK = ack
			}
			f.ackSeen = true
		}
	}
	v.Pending = -1 // Unknown until both data sequence and ACK have been observed.
	if f.dataSeen && f.ackSeen {
		v.Pending = int64(int32(v.TunDataEnd - v.AppACK))
		if v.Pending < 0 {
			v.Pending = 0
		}
	}
}

package transportdiag

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

func TestStagesRejectStaleSYNACK(t *testing.T) {
	d := New()
	k := Key{netip.MustParseAddrPort("10.0.0.2:45000"), netip.MustParseAddrPort("192.0.2.1:443")}
	f := d.Begin(k)
	p := make([]byte, 40)
	p[0] = 0x45
	p[9] = 6
	copy(p[12:16], k.Local.Addr().AsSlice())
	copy(p[16:20], k.Remote.Addr().AsSlice())
	binary.BigEndian.PutUint16(p[20:22], 45000)
	binary.BigEndian.PutUint16(p[22:24], 443)
	binary.BigEndian.PutUint32(p[24:28], 100)
	p[33] = 2
	d.Packet("SYN_TX", p, false)
	d.Packet("PACKET_TO_WG", p, false)
	copy(p[12:16], k.Remote.Addr().AsSlice())
	copy(p[16:20], k.Local.Addr().AsSlice())
	binary.BigEndian.PutUint16(p[20:22], 443)
	binary.BigEndian.PutUint16(p[22:24], 45000)
	p[33] = 0x12
	binary.BigEndian.PutUint32(p[28:32], 99)
	d.Packet("SYNACK_RX", p, true)
	if d.SynAckRx.Load() != 0 {
		t.Fatal("stale response matched new session")
	}
	binary.BigEndian.PutUint32(p[28:32], 101)
	d.Packet("SYNACK_RX", p, true)
	d.Packet("GVISOR_DELIVER", p, true)
	out := d.End(f, false, true)
	for _, s := range []string{"SYN_TX@", "PACKET_TO_WG@", "SYNACK_RX@", "GVISOR_DELIVER@", "outer_scope=session_not_flow"} {
		if !strings.Contains(out, s) {
			t.Fatal(out)
		}
	}
	if len(d.flows) != 0 || d.ConnectTimeout.Load() != 1 {
		t.Fatal(d.Stats())
	}
}

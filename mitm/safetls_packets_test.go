package mitm

import (
	"bytes"
	"encoding/binary"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"testing"
)

func TestSafeTLSPacketDelivery(t *testing.T) {
	resetSafeTLS()
	f := newSafeTLSFlow(999, "example.test", "192.0.2.1:443", nil)
	safeTLSAttachPackets(f, stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), RemotePort: 12345, LocalAddress: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), LocalPort: 443})
	defer f.finish("test")
	packet := func(toApp bool, payload int, ack uint32) []byte {
		p := make([]byte, 40+payload)
		p[0] = 0x45
		p[9] = 6
		binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
		copy(p[12:16], []byte{10, 0, 0, 2})
		copy(p[16:20], []byte{192, 0, 2, 1})
		binary.BigEndian.PutUint16(p[20:22], 12345)
		binary.BigEndian.PutUint16(p[22:24], 443)
		if toApp {
			copy(p[12:16], []byte{192, 0, 2, 1})
			copy(p[16:20], []byte{10, 0, 0, 2})
			binary.BigEndian.PutUint16(p[20:22], 443)
			binary.BigEndian.PutUint16(p[22:24], 12345)
		}
		p[32] = 0x50
		p[33] = 16
		binary.BigEndian.PutUint32(p[28:32], ack)
		binary.BigEndian.PutUint16(p[34:36], 4096)
		return p
	}
	p := packet(true, 100, 0)
	binary.BigEndian.PutUint32(p[24:28], 0xfffffff0)
	original := append([]byte(nil), p...)
	raw443ObserveTunPacket(p, true)
	if f.v.Pending != -1 {
		t.Fatal("ACK unknown", f.v)
	}
	a := packet(false, 0, 0x54)
	raw443ObserveTunPacket(a, false)
	if f.v.Pending != 0 || f.v.TunDataEnd != 0x54 || f.v.AppACKs != 1 || !bytes.Equal(p, original) {
		t.Fatal(f.v)
	}
	// Retransmission increases observed payload, not the highest data sequence.
	raw443ObserveTunPacket(p, true)
	if f.v.Pending != 0 || f.v.TunPayload != 200 {
		t.Fatal(f.v)
	}
	// Stale ACK must not regress cumulative ACK across sequence wrap.
	binary.BigEndian.PutUint32(a[28:32], 0xfffffff5)
	raw443ObserveTunPacket(a, false)
	if f.v.Pending != 0 || f.v.AppACK != 0x54 {
		t.Fatal(f.v)
	}
	binary.BigEndian.PutUint32(p[24:28], 0x54)
	raw443ObserveTunPacket(p, true)
	if f.v.Pending != 100 {
		t.Fatal(f.v)
	}
	a[33] = 17
	binary.BigEndian.PutUint16(a[34:36], 0)
	raw443ObserveTunPacket(a, false)
	if !f.v.AppFIN || f.v.AppWindow != 0 {
		t.Fatal(f.v)
	}
	a[33] = 20
	raw443ObserveTunPacket(a, false)
	if !f.v.AppRST {
		t.Fatal(f.v)
	}
	n := f.v.TunPackets
	raw443ObserveTunPacket(p[:25], true)
	if f.v.TunPackets != n {
		t.Fatal("truncated counted")
	}
	safeTLSDetachPackets(f)
	raw443ObserveTunPacket(p, true)
	if f.v.TunPackets != n {
		t.Fatal("detached counted")
	}
}

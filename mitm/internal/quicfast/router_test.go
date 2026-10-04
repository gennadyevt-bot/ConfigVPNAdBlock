package quicfast

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name + ".bin")
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func udpPacket(v6 bool, src, dst uint16, payload []byte) []byte {
	off := 20
	if v6 {
		off = 40
	}
	b := make([]byte, off+8+len(payload))
	if v6 {
		b[0] = 0x60
		b[6] = 17
		b[7] = 64
		binary.BigEndian.PutUint16(b[4:], uint16(len(b)-40))
		b[8] = 0xfd
		b[23] = 2
		b[24] = 0xfd
		b[39] = 1
	} else {
		b[0] = 0x45
		b[8] = 64
		b[9] = 17
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		copy(b[12:], []byte{10, 99, 0, 2})
		copy(b[16:], []byte{10, 99, 0, 1})
		binary.BigEndian.PutUint16(b[10:], checksum(b[:20]))
	}
	binary.BigEndian.PutUint16(b[off:], src)
	binary.BigEndian.PutUint16(b[off+2:], dst)
	binary.BigEndian.PutUint16(b[off+4:], uint16(len(b)-off))
	copy(b[off+8:], payload)
	p := packet{data: b, off: off, v6: v6}
	binary.BigEndian.PutUint16(b[off+6:], udpChecksum(p))
	return b
}
func reply(b []byte) []byte {
	p, _ := parse(b)
	r := append([]byte(nil), b...)
	if p.v6 {
		copy(r[8:24], b[24:40])
		copy(r[24:40], b[8:24])
	} else {
		copy(r[12:16], b[16:20])
		copy(r[16:20], b[12:16])
	}
	copy(r[p.off:p.off+2], b[p.off+2:p.off+4])
	copy(r[p.off+2:p.off+4], b[p.off:p.off+2])
	return r
}
func read(t *testing.T, c chan []byte) []byte {
	t.Helper()
	select {
	case b := <-c:
		return b
	case <-time.After(time.Second):
		t.Fatal("packet not forwarded")
		return nil
	}
}
func TestInitialRFC9001AndVersions(t *testing.T) {
	for _, tc := range []struct{ name, host string }{{"rfc9001-client", "example.com"}, {"youtube-v1", "youtubei.googleapis.com"}, {"youtube-v2", "youtubei.googleapis.com"}} {
		t.Run(tc.name, func(t *testing.T) {
			var h hello
			b := fixture(t, tc.name)
			before := append([]byte(nil), b...)
			host, pending := h.inspect(b)
			if host != tc.host || pending || !bytes.Equal(b, before) {
				t.Fatalf("SNI=%q pending=%v input changed=%v", host, pending, !bytes.Equal(b, before))
			}
			b[len(b)-1] ^= 1
			var invalid hello
			if host, _ := invalid.inspect(b); host != "" {
				t.Fatal("unauthenticated Initial accepted")
			}
		})
	}
}
func TestFastPathRoundTripAndOwnership(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) {
			tx, rx := make(chan []byte, 4), make(chan []byte, 4)
			var closed atomic.Int32
			r := New(Config{Reserve: func(bool) (Reservation, error) { return Reservation{Port: 49001, Close: func() { closed.Add(1) }}, nil }, Send: func(b []byte) error { tx <- b; return nil }, Deliver: func(b []byte) error { rx <- b; return nil }})
			defer func() { r.Stop(); r.Wait() }()
			original := udpPacket(v6, 42000, 443, fixture(t, "youtube-v1"))
			scratch := append([]byte(nil), original...)
			if !r.Outbound(scratch) {
				t.Fatal("not consumed")
			}
			clear(scratch)
			sent := read(t, tx)
			p, ok := parse(sent)
			if !ok || p.src.Port() != 49001 || !bytes.Equal(sent[p.off+8:], original[p.off+8:]) {
				t.Fatal("forwarding corrupted packet/checksum")
			}
			server := reply(sent)
			if !r.Inbound(server) {
				t.Fatal("reply not demultiplexed")
			}
			clear(server)
			got := read(t, rx)
			gp, ok := parse(got)
			if !ok || gp.dst.Port() != 42000 || !bytes.Equal(got[gp.off+8:], original[p.off+8:]) {
				t.Fatal("return path corrupted")
			}
			if r.Inbound(reply(udpPacket(v6, 49999, 443, []byte("unrelated")))) {
				t.Fatal("unmatched WG response stolen")
			}
			r.expire(time.Now().Add(3 * time.Minute))
			if closed.Load() != 1 || r.Inbound(reply(sent)) {
				t.Fatal("endpoint or reverse mapping survived expiry")
			}
		})
	}
}
func TestFragmentedInitialAndPolicy(t *testing.T) {
	tx := make(chan []byte, 10)
	r := New(Config{Reserve: func(bool) (Reservation, error) { return Reservation{Port: 49002, Close: func() {}}, nil }, Send: func(b []byte) error { tx <- b; return nil }, Deliver: func([]byte) error { return nil }, Blocked: func(host, ip string) bool { return host == "ads.googlevideo.com" }})
	defer func() { r.Stop(); r.Wait() }()
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "fragment-0")))
	if len(tx) != 0 {
		t.Fatal("incomplete SNI bypassed policy")
	}
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "fragment-1")))
	read(t, tx)
	read(t, tx)
	for i, name := range []string{"google-v1", "google-v2", "blocked-v1"} {
		r.Outbound(udpPacket(false, uint16(42001+i), 443, fixture(t, name)))
	}
	r.mu.Lock()
	for key, f := range r.flows {
		if key.client.Port() != 42000 && !f.denied {
			t.Fatal("browser/ad flow allowed")
		}
	}
	r.mu.Unlock()
	if VideoHost("googlevideo.com.evil.example") || VideoHost("www.google.com") || !VideoHost("rr1.googlevideo.com") {
		t.Fatal("hostname boundary")
	}
	if r.Outbound(udpPacket(false, 1234, 53, []byte("DNS"))) {
		t.Fatal("DNS bypassed AdBlock")
	}
	bad := udpPacket(false, 1234, 443, fixture(t, "youtube-v1"))
	bad[len(bad)-1] ^= 1
	if r.Outbound(bad) {
		t.Fatal("bad checksum accepted")
	}
	r.Stop()
	if !strings.Contains(r.Stats(), "quicFastActive=0") {
		t.Fatal("stop retained session")
	}
}
func TestBackpressureDoesNotBlockPacketLoops(t *testing.T) {
	blocked := make(chan struct{})
	started := make(chan struct{}, 1)
	r := New(Config{Reserve: func(bool) (Reservation, error) { return Reservation{Port: 49003, Close: func() {}}, nil }, Send: func([]byte) error {
		select {
		case started <- struct{}{}:
		default:
		}
		<-blocked
		return nil
	}, Deliver: func([]byte) error { return nil }})
	p := udpPacket(false, 42000, 443, fixture(t, "youtube-v1"))
	r.Outbound(p)
	<-started
	done := make(chan struct{})
	go func() {
		for i := 0; i < 600; i++ {
			r.Outbound(p)
		}
		r.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("backpressure blocked TUN or shutdown")
	}
	close(blocked)
	r.Wait()
	if r.queueDropN.Load() == 0 {
		t.Fatal("missing queue-drop diagnostics")
	}
}
func FuzzInitialParser(f *testing.F) {
	b, _ := os.ReadFile("testdata/youtube-v1.bin")
	f.Add(b)
	f.Add([]byte{0xc0, 0, 0, 0, 1, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) { var h hello; h.inspect(b) })
}

func TestHandshakeCIDAndReusedTuple(t *testing.T) {
	tx := make(chan []byte, 4)
	r := New(Config{Reserve: func(bool) (Reservation, error) { return Reservation{Port: 49004, Close: func() {}}, nil }, Send: func(b []byte) error { tx <- b; return nil }, Deliver: func([]byte) error { return nil }})
	defer func() { r.Stop(); r.Wait() }()
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "youtube-v1")))
	read(t, tx)
	// QUIC switches to a server-chosen destination CID in Handshake packets.
	handshake := []byte{0xe0, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8, 0}
	r.Outbound(udpPacket(false, 42000, 443, handshake))
	sent := read(t, tx)
	p, ok := parse(sent)
	if !ok || p.src.Port() != 49004 || !bytes.Equal(sent[p.off+8:], handshake) {
		t.Fatal("server CID changed mapping or discarded handshake")
	}
	// Even identical CID/UDP tuple must not authorize a different ClientHello.
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "google-v1")))
	r.mu.Lock()
	f := r.flows[flowKey{p.src, p.dst}]
	for _, v := range r.flows {
		f = v
	}
	denied := f.denied
	r.mu.Unlock()
	if !denied || len(tx) != 0 {
		t.Fatal("new browser Initial inherited video bypass")
	}
}

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
	first := read(t, tx)
	if r.unknownN.Load() != 1 {
		t.Fatal("incomplete Initial did not pass as unknown")
	}
	firstPacket, _ := parse(first)
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "fragment-1")))
	second := read(t, tx)
	secondPacket, _ := parse(second)
	if firstPacket.src.Port() != secondPacket.src.Port() {
		t.Fatal("fragment classification changed reply mapping")
	}
	for i, name := range []string{"google-v1", "google-v2", "blocked-v1"} {
		r.Outbound(udpPacket(false, uint16(42001+i), 443, fixture(t, name)))
	}
	read(t, tx)
	read(t, tx) // Chrome/Google v1 and v2 both use fast path.
	r.mu.Lock()
	for key, f := range r.flows {
		wantDenied := key.client.Port() == 42003
		if f.denied != wantDenied {
			t.Errorf("client=%d blocked=%v want=%v", key.client.Port(), f.denied, wantDenied)
		}
	}
	r.mu.Unlock()
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
	// Reused tuple/CID with a different permitted SNI keeps the packet mapping.
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "google-v1")))
	google := read(t, tx)
	gp, _ := parse(google)
	if gp.src.Port() != 49004 {
		t.Fatal("known hostname transition remapped flow")
	}
	// A subsequently authenticated advertising domain is blocked on that tuple.
	r.cfg.Blocked = func(host, ip string) bool { return host == "ads.googlevideo.com" }
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "blocked-v1")))
	if r.blockN.Load() != 1 || r.Inbound(reply(google)) {
		t.Fatal("blocked reused tuple kept reverse mapping")
	}
	// A later nonblocked Initial can reopen a previously blocked tuple.
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "google-v2")))
	read(t, tx)
	if r.knownN.Load() != 3 {
		t.Fatal("blocked flow remained stuck after permitted Initial")
	}
}

func TestUnknownQUICPassAndReverseMapping(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[v6], func(t *testing.T) {
			cases := [][]byte{{0x40, 1, 2, 3}, {0xc0, 0x12, 0x34, 0x56, 0x78, 0xff}, fixture(t, "youtube-v1")}
			cases[2][len(cases[2])-1] ^= 1 // Valid IP checksum, unauthenticatable QUIC Initial.
			tx, rx := make(chan []byte, 8), make(chan []byte, 8)
			var ports atomic.Uint32
			r := New(Config{Reserve: func(bool) (Reservation, error) {
				return Reservation{Port: uint16(49010 + ports.Add(1)), Close: func() {}}, nil
			}, Send: func(b []byte) error { tx <- b; return nil }, Deliver: func(b []byte) error { rx <- b; return nil }})
			defer func() { r.Stop(); r.Wait() }()
			for i, payload := range cases {
				client := uint16(42100 + i)
				r.Outbound(udpPacket(v6, client, 443, payload))
				sent := read(t, tx)
				sp, ok := parse(sent)
				if !ok || !bytes.Equal(sent[sp.off+8:], payload) || !r.Inbound(reply(sent)) {
					t.Fatal("unknown QUIC did not use raw path")
				}
				received := read(t, rx)
				rp, ok := parse(received)
				if !ok || rp.dst.Port() != client || !bytes.Equal(received[rp.off+8:], payload) {
					t.Fatal("unknown QUIC reply misrouted")
				}
			}
			if r.unknownN.Load() != 3 || r.parseFailN.Load() != 3 || r.blockN.Load() != 0 {
				t.Fatal(r.Stats())
			}
			// Session stop still releases unknown-flow reservations and reply mappings.
			r.Stop()
			if !strings.Contains(r.Stats(), "quicFastActive=0") {
				t.Fatal("unknown endpoints leaked")
			}
		})
	}
}
func TestDNSFallbackAndLateBlockedSNI(t *testing.T) {
	tx := make(chan []byte, 8)
	var dnsName atomic.Value
	dnsName.Store("ads.example.test")
	r := New(Config{Reserve: func(bool) (Reservation, error) { return Reservation{Port: 49020, Close: func() {}}, nil }, Send: func(b []byte) error { tx <- b; return nil }, Deliver: func([]byte) error { return nil }, KnownHost: func(string) string { return dnsName.Load().(string) }, Blocked: func(host, ip string) bool { return host == "ads.example.test" || host == "youtubei.googleapis.com" }})
	defer func() { r.Stop(); r.Wait() }()
	r.Outbound(udpPacket(false, 42000, 443, []byte{0x40, 1, 2, 3}))
	if r.blockN.Load() != 1 || r.txN.Load() != 0 {
		t.Fatal("DNS-known advertising flow passed")
	}
	// Authenticated SNI overrides DNS association on shared CDN addresses.
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "google-v1")))
	read(t, tx)
	dnsName.Store("") // Expired/ambiguous DNS must not persist a block decision.
	r.Outbound(udpPacket(false, 42001, 443, []byte{0x40, 4, 5}))
	read(t, tx)
	r.Outbound(udpPacket(false, 42002, 443, fixture(t, "fragment-0")))
	first := read(t, tx)
	r.Outbound(udpPacket(false, 42002, 443, fixture(t, "fragment-1")))
	if r.blockN.Load() != 2 || r.Inbound(reply(first)) {
		t.Fatal("late blocklist SNI did not revoke mapping")
	}
	// Fragmented ClientHello with reused CID must replace the old Google SNI.
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "fragment-0")))
	read(t, tx)
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "fragment-1")))
	if r.blockN.Load() != 3 {
		t.Fatal("fragmented reused CID kept a stale permitted SNI")
	}

}

func TestBlockedTupleReusedByUnparsedConnection(t *testing.T) {
	tx := make(chan []byte, 4)
	r := New(Config{Reserve: func(bool) (Reservation, error) { return Reservation{Port: 49030, Close: func() {}}, nil }, Send: func(b []byte) error { tx <- b; return nil }, Deliver: func([]byte) error { return nil }, Blocked: func(host, ip string) bool { return host == "ads.googlevideo.com" }})
	defer func() { r.Stop(); r.Wait() }()
	r.Outbound(udpPacket(false, 42000, 443, fixture(t, "blocked-v1")))
	if r.blockN.Load() != 1 {
		t.Fatal("advertising Initial not blocked")
	}
	initial := fixture(t, "youtube-v1")
	initial[6] ^= 1 // New CID, hence unauthenticatable with the previous key.
	r.Outbound(udpPacket(false, 42000, 443, initial))
	read(t, tx)
	if r.unknownN.Load() != 1 || r.parseFailN.Load() != 1 {
		t.Fatal("parser failure inherited the previous block verdict")
	}
}

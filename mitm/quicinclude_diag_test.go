package mitm

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"configadblock/mitm/internal/quicfast"
	"golang.org/x/sys/unix"
)

func includeUDP(v6 bool, port uint16, payload []byte) []byte {
	off := 20
	if v6 {
		off = 40
	}
	b := make([]byte, off+8+len(payload))
	if v6 {
		b[0] = 0x60
		b[6] = 17
		binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
		b[8] = 0x20
		b[9] = 1
		b[23] = 2
		b[24] = 0x20
		b[25] = 1
		b[39] = 1
	} else {
		b[0] = 0x45
		b[9] = 17
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		copy(b[12:16], []byte{10, 0, 0, 2})
		copy(b[16:20], []byte{192, 0, 2, 1})
	}
	binary.BigEndian.PutUint16(b[off:off+2], 42000)
	binary.BigEndian.PutUint16(b[off+2:off+4], port)
	binary.BigEndian.PutUint16(b[off+4:off+6], uint16(8+len(payload)))
	copy(b[off+8:], payload)
	checksum := func(p []byte) uint16 {
		var n uint32
		for len(p) > 1 {
			n += uint32(binary.BigEndian.Uint16(p))
			p = p[2:]
		}
		if len(p) > 0 {
			n += uint32(p[0]) << 8
		}
		for n>>16 > 0 {
			n = (n & 65535) + (n >> 16)
		}
		return ^uint16(n)
	}
	if v6 {
		pseudo := append([]byte(nil), b[8:40]...)
		pseudo = append(pseudo, 0, 0, byte((len(b)-40)>>8), byte(len(b)-40), 0, 0, 0, 17)
		pseudo = append(pseudo, b[40:]...)
		binary.BigEndian.PutUint16(b[off+6:off+8], checksum(pseudo))
	} else {
		binary.BigEndian.PutUint16(b[10:12], checksum(b[:20]))
	}
	return b
}
func TestQuicIncludeIsolationAndStopRetention(t *testing.T) {
	for _, tc := range []struct {
		mode, apps string
		drop       bool
	}{
		{"INCLUDE", "com.android.chrome,com.google.android.googlequicksearchbox", true},
		{"INCLUDE", "com.android.chrome", true},
		{"INCLUDE", "com.google.android.googlequicksearchbox", true},
		{"GLOBAL", "com.android.chrome", false},
		{"EXCLUDE", "com.android.chrome", false},
		{"INCLUDE", "", false},
		{"INCLUDE", "com.google.android.youtube", false},
		{"INCLUDE", "com.android.chrome,com.google.android.youtube", false},
		{"INCLUDE", "com.android.chrome,other.app", false},
	} {
		t.Run(tc.mode+tc.apps, func(t *testing.T) {
			SetQuicIncludeDiagnostic(tc.mode, tc.apps)
			defer StopQuicIncludeDiagnostic()
			s := quicIncludeCurrent.Load()
			for _, v6 := range []bool{false, true} {
				b := includeUDP(v6, 443, []byte{0x40, 1, 2, 3})
				original := append([]byte(nil), b...)
				if s.outbound(b) != tc.drop || !bytes.Equal(b, original) {
					t.Fatal("scope mismatch or packet mutation")
				}
			}
			if s.outbound(includeUDP(false, 53, []byte("DNS"))) {
				t.Fatal("DNS intercepted")
			}
			if tc.drop {
				if s.packets.Load() != 2 || s.flows.Load() != 2 || LastQuicDropAt() == "0" || QuicMode() != "DROP_INCLUDE_DIAG" {
					t.Fatal(QuicIncludeDropStats())
				}
				StopQuicIncludeDiagnostic()
				if s.packets.Load() != 2 || QuicMode() != "NORMAL" || LastQuicDropAt() == "0" {
					t.Fatal("STOP reset counters")
				}
			} else if QuicMode() != "NORMAL" || s.packets.Load() != 0 {
				t.Fatal("non-browser session changed")
			}
		})
	}
}
func TestQuicIncludeDropBeforeRawWG(t *testing.T) {
	SetQuicIncludeDiagnostic("INCLUDE", "com.android.chrome")
	defer StopQuicIncludeDiagnostic()
	s := quicIncludeCurrent.Load()
	// Real TUN fd: read consumes UDP/443 and returns the following DNS packet.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[0]), "include-tun")
	peer := os.NewFile(uintptr(fds[1]), "include-app")
	defer f.Close()
	defer peer.Close()
	raw := make(chan []byte, 1)
	r := quicfast.New(quicfast.Config{Reserve: func(bool) (quicfast.Reservation, error) {
		return quicfast.Reservation{Port: 49000, Close: func() {}}, nil
	}, Send: func(b []byte) error { raw <- b; return nil }, Deliver: func([]byte) error { return nil }})
	defer r.Stop()
	c := &tunCounter{f: f, fast: r, quicDiag: s}
	q := includeUDP(false, 443, []byte{0x40, 1, 2, 3})
	dns := includeUDP(false, 53, []byte("DNS"))
	peer.Write(q)
	peer.Write(q)
	peer.Write(dns)
	f.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	n, err := c.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], dns) {
		t.Fatalf("DNS read err=%v", err)
	}
	if s.packets.Load() != 2 || s.flows.Load() != 1 || s.bytes.Load() != int64(2*len(q)) {
		t.Fatal(QuicIncludeDropStats())
	}
	select {
	case <-raw:
		t.Fatal("dropped QUIC reached WG")
	case <-time.After(20 * time.Millisecond):
	}
	// DROP emitted no ICMP/response to app.
	peer.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if n, err := peer.Read(buf); n > 0 || err == nil {
		t.Fatal("DROP wrote response to app")
	}
	// New GLOBAL TUN captures a different session; the old session cannot leak.
	SetQuicIncludeDiagnostic("GLOBAL", "")
	if quicIncludeCurrent.Load() == s || s.active.Load() {
		t.Fatal("diagnostic leaked across TUN sessions")
	}

	// The identical read/fast path passes YouTube UDP/443 in a fresh GLOBAL TUN.
	c.quicDiag = quicIncludeCurrent.Load()
	hello, err := os.ReadFile("internal/quicfast/testdata/youtube-v1.bin")
	if err != nil {
		t.Fatal(err)
	}
	peer.Write(includeUDP(false, 443, hello))
	peer.Write(dns)
	n, err = c.Read(buf)
	if err != nil || !bytes.Equal(buf[:n], dns) {
		t.Fatal("normal TUN read failed", err)
	}
	select {
	case <-raw:
	case <-time.After(time.Second):
		t.Fatal("normal YouTube QUIC did not reach WG fast path")
	}
}
func TestQuicIncludeSNILogAndTCPLink(t *testing.T) {
	SetQuicIncludeDiagnostic("INCLUDE", "com.android.chrome")
	defer StopQuicIncludeDiagnostic()
	s := quicIncludeCurrent.Load()
	hello, err := os.ReadFile("internal/quicfast/testdata/google-v1.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !s.outbound(includeUDP(false, 443, hello)) {
		t.Fatal("known QUIC was not dropped")
	}
	f := &raw443Flow{counts: new(raw443Counters), host: "www.google.com", dst: "192.0.2.1:443", fid: 76}
	f.begin()
	defer f.finish("test_end")
	tcp443AfterQuicDrop(f)
	if LastTcp443AfterQuicDropAt() == "0" {
		t.Fatal("TCP after DROP not recorded")
	}
	flowMu.Lock()
	logs := strings.Join(flowRing, "\n")
	flowMu.Unlock()
	if !strings.Contains(logs, "TCP443_AFTER_QUIC_DROP") || !strings.Contains(logs, "mapped_port=0 reason=force_tcp_fallback") {
		t.Fatal(logs)
	}
	// RAW relay still carries sustained bytes in this mode; DROP has no TCP effect.
	app, up, flow, done := rawTestRelay(t)
	app.Write([]byte("tcp-request"))
	app.CloseWrite()
	got, err := io.ReadAll(up)
	if err != nil || string(got) != "tcp-request" {
		t.Fatal("TCP request blocked", err)
	}
	up.Write(bytes.Repeat([]byte("response"), 2048))
	up.CloseWrite()
	got, err = io.ReadAll(app)
	if err != nil || len(got) != 16384 {
		t.Fatal("TCP response blocked", err)
	}
	rawTestDone(t, done)
	if flow.counts.upOK.Load() != 1 || flow.counts.downOK.Load() != 1 || flow.counts.fail.Load() != 0 {
		t.Fatal("RAW TCP regressed")
	}
}

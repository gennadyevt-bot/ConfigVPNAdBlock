package mitm

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func packetTCP(v6 bool, seq uint32, flags byte, data []byte) []byte {
	b := includeUDP(v6, 443, nil)
	off := 20
	if v6 {
		off = 40
	}
	b = b[:off]
	b = append(b, make([]byte, 20+len(data))...)
	if v6 {
		b[6] = 6
		binary.BigEndian.PutUint16(b[4:], uint16(len(b)-40))
	} else {
		b[9] = 6
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
		b[10] = 0
		b[11] = 0
		binary.BigEndian.PutUint16(b[10:], browserChecksum(b[:20]))
	}
	binary.BigEndian.PutUint16(b[off:], 42000)
	binary.BigEndian.PutUint16(b[off+2:], 443)
	binary.BigEndian.PutUint32(b[off+4:], seq)
	binary.BigEndian.PutUint32(b[off+8:], 1234)
	b[off+12] = 80
	b[off+13] = flags
	binary.BigEndian.PutUint16(b[off+14:], 65535)
	copy(b[off+20:], data)
	p, _ := parseBrowserPacket(b)
	binary.BigEndian.PutUint16(b[off+16:], browserTransportChecksum(p))
	return b
}
func capturedBrowserHello(t *testing.T, host string) []byte {
	t.Helper()
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); tls.Client(a, &tls.Config{ServerName: host}).Handshake(); a.Close() }()
	b.SetReadDeadline(time.Now().Add(time.Second))
	h := make([]byte, 5)
	if _, e := io.ReadFull(b, h); e != nil {
		t.Fatal(e)
	}
	body := make([]byte, int(binary.BigEndian.Uint16(h[3:])))
	if _, e := io.ReadFull(b, body); e != nil {
		t.Fatal(e)
	}
	b.Close()
	<-done
	return append(h, body...)
}
func testBrowserFilter() *browserPacketFilter {
	return &browserPacketFilter{blocked: func(h string) bool {
		return h == "ads.example.com" || h == "ads.googlevideo.com" || strings.Contains(h, "doubleclick") || strings.Contains(h, "googleadservices")
	}, log: func(string) {}, deliver: func([]byte) error { return nil }}
}
func TestBrowserPacketTLSReorderingAndRetransmission(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, host := range []string{"ads.example.com", "dzen.ru"} {
			f := testBrowserFilter()
			var reply []byte
			f.deliver = func(b []byte) error { reply = append([]byte(nil), b...); return nil }
			hello := capturedBrowserHello(t, host)
			cut := len(hello) / 2
			f.outbound(packetTCP(v6, 100, 2, nil))
			for _, b := range [][]byte{packetTCP(v6, 101+uint32(cut), 24, hello[cut:]), packetTCP(v6, 101+uint32(cut), 24, hello[cut:])} {
				orig := append([]byte(nil), b...)
				if f.outbound(b) || !bytes.Equal(orig, b) {
					t.Fatal("partial hello changed")
				}
			}
			b := packetTCP(v6, 101, 24, hello[:cut])
			orig := append([]byte(nil), b...)
			if got := f.outbound(b); got != (host == "ads.example.com") || !bytes.Equal(orig, b) {
				t.Fatalf("host=%s blocked=%t", host, got)
			}
			if host == "ads.example.com" {
				p, ok := parseBrowserPacket(reply)
				if !ok || reply[p.off+13] != 4 || browserTransportChecksum(p) != 0 {
					t.Fatal("invalid reset")
				}
				if !f.outbound(b) {
					t.Fatal("blocked retransmission passed")
				}
			} else {
				if reply != nil {
					t.Fatal("allowed reset")
				}
				for _, flags := range []byte{16, 17, 4} {
					if f.outbound(packetTCP(v6, 101+uint32(len(hello)), flags, nil)) {
						t.Fatal("allowed ACK/FIN/RST blocked")
					}
				}
			}
		}
	}
}
func TestBrowserPacketDNSAndQUIC(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		f := testBrowserFilter()
		var reply []byte
		f.deliver = func(b []byte) error { reply = b; return nil }
		name, _ := dnsmessage.NewName("ads.example.com.")
		q, e := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 45, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
		if e != nil {
			t.Fatal(e)
		}
		if !f.outbound(includeUDP(v6, 53, q)) {
			t.Fatal("DNS not blocked")
		}
		p, ok := parseBrowserPacket(reply)
		if !ok || p.src.Port() != 53 || p.dst.Port() != 42000 || browserTransportChecksum(p) != 0 {
			t.Fatal("invalid DNS reply")
		}
		var m dnsmessage.Message
		if e := m.Unpack(reply[p.off+8:]); e != nil || m.ID != 45 || m.RCode != dnsmessage.RCodeNameError {
			t.Fatal("invalid NXDOMAIN", e)
		}
		for _, fixture := range []string{"blocked-v1", "google-v1", "blocked-v2", "google-v2"} {
			f = testBrowserFilter()
			raw, e := os.ReadFile("internal/quicfast/testdata/" + fixture + ".bin")
			if e != nil {
				t.Fatal(e)
			}
			b := includeUDP(v6, 443, raw)
			orig := append([]byte(nil), b...)
			want := strings.HasPrefix(fixture, "blocked")
			if f.outbound(b) != want || !bytes.Equal(orig, b) {
				t.Fatal("QUIC decision", fixture)
			}
			if want {
				if !f.outbound(includeUDP(v6, 443, []byte{0x40, 1, 2, 3})) {
					t.Fatal("blocked short header passed")
				}
				raw[6] ^= 1
				if f.outbound(includeUDP(v6, 443, raw)) {
					t.Fatal("new unauthenticatable CID inherited block")
				}
			}
		}
	}
}
func TestBrowserPacketNativeIdentityAndStop(t *testing.T) {
	a, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
	if e != nil {
		t.Fatal(e)
	}
	u, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
	if e != nil {
		t.Fatal(e)
	}
	app := os.NewFile(uintptr(a[1]), "app")
	up := os.NewFile(uintptr(u[1]), "up")
	defer app.Close()
	defer up.Close()
	defer StopBrowserPacketTunnel()
	if e = StartBrowserPacketTunnel(int64(a[0]), int64(u[0]), 1280); e != nil {
		t.Fatal(e)
	}
	for _, v6 := range []bool{false, true} {
		for _, b := range [][]byte{packetTCP(v6, 100, 2, nil), packetTCP(v6, 101, 24, capturedBrowserHello(t, "dzen.ru")), includeUDP(v6, 53, []byte("unchanged DNS")), includeUDP(v6, 443, []byte{0x40, 2, 3, 4})} {
			for _, direction := range []bool{true, false} {
				src, dst := app, up
				if !direction {
					src, dst = up, app
				}
				dst.SetReadDeadline(time.Now().Add(time.Second))
				if _, e = src.Write(b); e != nil {
					t.Fatal(e)
				}
				got := make([]byte, 65535)
				n, e := dst.Read(got)
				if e != nil || !bytes.Equal(got[:n], b) {
					t.Fatal("packet altered or missing", e)
				}
			}
		}
	}
	done := make(chan struct{})
	go func() { StopTunnel(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop leaked packet loop")
	}
	if browserPackets.Load().active.Load() {
		t.Fatal("active after stop")
	}
}

package mitm

import (
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type rejectSystemSocket struct{ calls atomic.Int64 }

func (p *rejectSystemSocket) Protect(int64) bool {
	p.calls.Add(1)
	return false
}

func TestEncryptedDNSUsesWireGuardUpstream(t *testing.T) {
	for _, port := range []string{"853", "443"} {
		t.Run(port, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
			if err != nil {
				t.Fatal(err)
			}
			peer := os.NewFile(uintptr(fds[1]), "vpn-peer")
			defer peer.Close()
			if err := startWgUpstream(int64(fds[0]), 1280, "10.99.0.2", ""); err != nil {
				t.Fatal(err)
			}
			defer stopWgUpstream()
			p := &rejectSystemSocket{}
			protectorMu.Lock()
			old := protector
			protector = p
			protectorMu.Unlock()
			defer SetProtector(old)
			started := time.Now()
			conn, err := tlsDialTimeout(net.JoinHostPort("192.0.2.1", port), "dns.example", 100*time.Millisecond)
			if p.calls.Load() != 0 {
				t.Fatal("encrypted DNS attempted a system socket outside WireGuard")
			}
			if conn != nil {
				conn.Close()
				t.Fatal("silent peer unexpectedly connected")
			}
			if err == nil || time.Since(started) > time.Second {
				t.Fatalf("deadline not honored: %v", err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			packet := make([]byte, 1500)
			n, err := peer.Read(packet)
			if err != nil {
				t.Fatal(err)
			}
			if n < 40 || packet[0]>>4 != 4 || packet[9] != 6 || !net.IP(packet[16:20]).Equal(net.ParseIP("192.0.2.1")) {
				t.Fatal("no DNS upstream TCP SYN reached the VPN packet socket")
			}
			if wgUpstream.trace.ActiveEndpoints.Load() != 0 {
				t.Fatal("timed-out DNS dial leaked an endpoint")
			}
		})
	}
}

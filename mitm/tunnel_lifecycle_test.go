package mitm

import (
	"bytes"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// net.ParseIP returns a 16-byte value even for IPv4. The upstream stack
// requires a four-byte address when dialing the IPv4 protocol.
func TestWgUpstreamIPv4Packet(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	peer := os.NewFile(uintptr(fds[1]), "upstream-peer")
	defer peer.Close()
	if err := startWgUpstream(int64(fds[0]), 1280, "10.0.0.2", ""); err != nil {
		t.Fatal(err)
	}
	defer stopWgUpstream()
	c, err := wgDialUDP("192.0.2.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := []byte("upstream-ipv4-regression")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	peer.SetReadDeadline(time.Now().Add(time.Second))
	packet := make([]byte, 1280)
	n, err := peer.Read(packet)
	if err != nil {
		t.Fatal(err)
	}
	if n < 28 || packet[0]>>4 != 4 || !bytes.Equal(packet[16:20], []byte{192, 0, 2, 1}) || !bytes.Equal(packet[n-len(payload):n], payload) {
		t.Fatalf("unexpected upstream packet: %x", packet[:n])
	}
}

func TestTunnelClosesOwnedDescriptor(t *testing.T) {
	for _, mtu := range []int64{0, 1280} {
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
		if err != nil {
			t.Fatal(err)
		}
		err = StartTunnel(int64(fds[0]), mtu)
		if mtu == 0 && err == nil || mtu != 0 && err != nil {
			t.Fatalf("StartTunnel(%d): %v", mtu, err)
		}
		StopTunnel()
		var st unix.Stat_t
		if err := unix.Fstat(fds[0], &st); err != unix.EBADF {
			t.Fatalf("owned TUN fd leaked: %v", err)
		}
		unix.Close(fds[1])
	}
}

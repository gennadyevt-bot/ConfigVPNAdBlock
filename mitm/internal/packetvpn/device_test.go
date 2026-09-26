package packetvpn

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"golang.org/x/sys/unix"
)

func socketPair(t *testing.T) (int, *os.File) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fds[1]), "test-packets")
	t.Cleanup(func() { f.Close() })
	return fds[0], f
}

// Regression: sockets must work without the TUNGETIFF ioctl used by the
// Android backend. Exercise real encrypted traffic in both directions.
func TestPacketTunnelEncryptedRoundTrip(t *testing.T) {
	for _, mode := range []string{"WG", "AWG"} {
		t.Run(mode, func(t *testing.T) {
			k1, _ := ecdh.X25519().GenerateKey(rand.Reader)
			k2, _ := ecdh.X25519().GenerateKey(rand.Reader)
			extra := ""
			if mode == "AWG" {
				extra = "jc=3\njmin=40\njmax=80\ns1=15\ns2=20\nh1=1111\nh2=2222\nh3=3333\nh4=4444\n"
			}
			start := func(key *ecdh.PrivateKey) (*device.Device, *os.File, int) {
				fd, f := socketPair(t)
				tun, err := newPacketTun(fd, 1280)
				if err != nil {
					t.Fatal(err)
				}
				// Like protectedBind in production, wrap the UDP bind. No Linux
				// route-netlink listener is needed for this loopback exchange.
				d := device.NewDevice(tun, struct{ conn.Bind }{conn.NewStdNetBind()}, &device.Logger{Verbosef: func(string, ...any) {}, Errorf: t.Logf}, false, func(device.StatusCode) {})
				t.Cleanup(d.Close)
				if err := d.IpcSet(fmt.Sprintf("private_key=%x\n%s", key.Bytes(), extra)); err != nil {
					t.Fatal(err)
				}
				if err := d.Up(); err != nil {
					t.Fatal(err)
				}
				cfg, err := d.IpcGet()
				if err != nil {
					t.Fatal(err)
				}
				var port int
				for _, line := range strings.Split(cfg, "\n") {
					if strings.HasPrefix(line, "listen_port=") {
						fmt.Sscanf(line, "listen_port=%d", &port)
					}
				}
				if port == 0 {
					t.Fatal("missing UDP listener")
				}
				return d, f, port
			}
			d1, f1, p1 := start(k1)
			d2, f2, p2 := start(k2)
			for _, peer := range []struct {
				d    *device.Device
				key  *ecdh.PrivateKey
				port int
			}{{d1, k2, p2}, {d2, k1, p1}} {
				if err := peer.d.IpcSet(fmt.Sprintf("public_key=%x\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n", peer.key.PublicKey().Bytes(), peer.port)); err != nil {
					t.Fatal(err)
				}
			}
			for i, pair := range [][2]*os.File{{f1, f2}, {f2, f1}} {
				payload := []byte("filtered-packet-through-vpn")
				packet := make([]byte, 20+len(payload))
				packet[0] = 0x45
				packet[8] = 64
				packet[9] = 253
				binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
				copy(packet[12:16], []byte{10, 0, 0, byte(i + 1)})
				copy(packet[16:20], []byte{10, 0, 0, byte(2 - i)})
				copy(packet[20:], payload)
				pair[1].SetReadDeadline(time.Now().Add(10 * time.Second))
				if _, err := pair[0].Write(packet); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, 1500)
				n, err := pair[1].Read(got)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(packet, got[:n]) {
					t.Fatalf("packet changed: %x", got[:n])
				}
			}
		})
	}
}

func TestPacketCloseUnblocksRead(t *testing.T) {
	fd, _ := socketPair(t)
	tun, err := newPacketTun(fd, 1280)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, e := tun.Read([][]byte{make([]byte, 1500)}, make([]int, 1), 0); done <- e }()
	tun.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("expected close error")
		}
	case <-time.After(time.Second):
		t.Fatal("read blocked after close")
	}
}

// Android must never send its encrypted UDP packets back into its own VPN.
type testBind struct {
	conn.Bind
	closed bool
}

func (b *testBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, 1234, nil }
func (b *testBind) Close() error                                    { b.closed = true; return nil }
func (b *testBind) PeekLookAtSocketFd4() (int, error)               { return 4, nil }
func (b *testBind) PeekLookAtSocketFd6() (int, error)               { return 6, nil }
func TestProtectionBeforeUse(t *testing.T) {
	for _, allow := range []bool{true, false} {
		raw := &testBind{}
		calls := 0
		b := &protectedBind{Bind: raw, protect: func(int) bool { calls++; return allow }}
		_, _, err := b.Open(0)
		if allow && (err != nil || calls != 2 || raw.closed) {
			t.Fatalf("protect both sockets: calls=%d err=%v", calls, err)
		}
		if !allow && (err == nil || !raw.closed) {
			t.Fatal("unprotected sockets left open")
		}
	}
}

// Регрессия: packetTun БЕЗ немедленного пакета не должен убивать WG device,
// а пакет после простоя должен проходить end-to-end.
func TestPacketTunIdleKeepsDeviceAlive(t *testing.T) {
	k1, _ := ecdh.X25519().GenerateKey(rand.Reader)
	k2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	startDev := func(key *ecdh.PrivateKey) (*device.Device, *os.File, int) {
		fd, f := socketPair(t)
		tun, err := newPacketTun(fd, 1280)
		if err != nil {
			t.Fatal(err)
		}
		d := device.NewDevice(tun, struct{ conn.Bind }{conn.NewStdNetBind()}, &device.Logger{Verbosef: func(string, ...any) {}, Errorf: t.Logf}, false, func(device.StatusCode) {})
		t.Cleanup(d.Close)
		if err := d.IpcSet(fmt.Sprintf("private_key=%x\n", key.Bytes())); err != nil {
			t.Fatal(err)
		}
		if err := d.Up(); err != nil {
			t.Fatal(err)
		}
		cfg, err := d.IpcGet()
		if err != nil {
			t.Fatal(err)
		}
		var port int
		for _, line := range strings.Split(cfg, "\n") {
			if strings.HasPrefix(line, "listen_port=") {
				fmt.Sscanf(line, "listen_port=%d", &port)
			}
		}
		if port == 0 {
			t.Fatal("missing UDP listener")
		}
		return d, f, port
	}
	d1, f1, p1 := startDev(k1)
	d2, f2, p2 := startDev(k2)
	for _, peer := range []struct {
		d    *device.Device
		key  *ecdh.PrivateKey
		port int
	}{{d1, k2, p2}, {d2, k1, p1}} {
		if err := peer.d.IpcSet(fmt.Sprintf("public_key=%x\nendpoint=127.0.0.1:%d\nallowed_ip=0.0.0.0/0\n", peer.key.PublicKey().Bytes(), peer.port)); err != nil {
			t.Fatal(err)
		}
	}
	// 1) IDLE: без пакетов 500 мс устройства НЕ должны самозакрыться
	time.Sleep(500 * time.Millisecond)
	if _, err := d1.IpcGet(); err != nil {
		t.Fatal("device closed while idle: ", err)
	}
	if _, err := d2.IpcGet(); err != nil {
		t.Fatal("device closed while idle: ", err)
	}
	// 2) пакет после простоя должен пройти (первая отправка может уйти на handshake)
	payload := []byte("after-idle-packet")
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	packet[8] = 64
	packet[9] = 253
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 0, 0, 1})
	copy(packet[16:20], []byte{10, 0, 0, 2})
	copy(packet[20:], payload)
	got := make([]byte, 1500)
	awaitPacket(t, f2, packet, got)
}

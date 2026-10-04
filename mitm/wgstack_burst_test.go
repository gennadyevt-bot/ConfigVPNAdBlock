package mitm

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

func TestUpstreamConcurrentTCP(t *testing.T) {
	for _, mode := range []string{"socketpair", "WG", "AWG"} {
		t.Run(mode, func(t *testing.T) { testUpstreamConcurrentTCP(t, mode) })
	}
}
func testUpstreamConcurrentTCP(t *testing.T, mode string) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	if mode != "socketpair" {
		right, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
		if e != nil {
			t.Fatal(e)
		}
		k1, _ := ecdh.X25519().GenerateKey(rand.Reader)
		k2, _ := ecdh.X25519().GenerateKey(rand.Reader)
		extra := ""
		if mode == "AWG" {
			extra = "jc=3\njmin=40\njmax=80\ns1=15\ns2=20\nh1=1111\nh2=2222\nh3=3333\nh4=4444\n"
		}
		server, e := testPacketDevice(right[0], 1280, fmt.Sprintf("private_key=%x\n%spublic_key=%x\nallowed_ip=0.0.0.0/0\n", k2.Bytes(), extra, k1.PublicKey().Bytes()), func(int) bool { return true }, t.Logf)
		if e != nil {
			t.Fatal(e)
		}
		defer server.Close()
		config, _ := server.IpcGet()
		var port int
		for _, line := range strings.Split(config, "\n") {
			if strings.HasPrefix(line, "listen_port=") {
				fmt.Sscanf(line, "listen_port=%d", &port)
			}
		}
		client, e := testPacketDevice(fds[1], 1280, fmt.Sprintf("private_key=%x\n%spublic_key=%x\nallowed_ip=0.0.0.0/0\nendpoint=127.0.0.1:%d\n", k1.Bytes(), extra, k2.PublicKey().Bytes(), port), func(int) bool { return true }, t.Logf)
		if e != nil {
			t.Fatal(e)
		}
		defer client.Close()
		fds[1] = right[1]
	}
	f := os.NewFile(uintptr(fds[1]), "server")
	ep, _ := iobased.New(f, 1280, 0)
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol}})
	s.CreateNIC(1, ep)
	s.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 99, 0, 1}).WithPrefix()}, stack.AddressProperties{})
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	l, e := gonet.ListenTCP(s, tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 99, 0, 1}), Port: 443}, ipv4.ProtocolNumber)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { l.Close(); f.Close(); s.Close(); ep.Close(); ep.Wait() }()
	go func() {
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 1)
				if _, e := c.Read(b); e == nil {
					c.Write(b)
				}
			}()
		}
	}()
	if e := startWgUpstream(int64(fds[0]), 1280, "10.99.0.2", ""); e != nil {
		t.Fatal(e)
	}
	defer stopWgUpstream()
	// Run raw UDP/443 through exactly the same encrypted engines alongside TCP.
	serverUDP, ue := gonet.DialUDP(s, &tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{10, 99, 0, 1}), Port: 443}, nil, ipv4.ProtocolNumber)
	if ue != nil {
		t.Fatal(ue)
	}
	defer serverUDP.Close()
	go func() {
		b := make([]byte, 1500)
		for {
			n, addr, e := serverUDP.ReadFrom(b)
			if e != nil {
				return
			}
			serverUDP.WriteTo(b[:n], addr)
		}
	}()
	appFDs, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
	if e != nil {
		t.Fatal(e)
	}
	app := os.NewFile(uintptr(appFDs[1]), "test-app-tun")
	defer app.Close()
	if e := StartTunnel(int64(appFDs[0]), 1280); e != nil {
		t.Fatal(e)
	}
	defer StopTunnel()
	initial, e := os.ReadFile("internal/quicfast/testdata/youtube-v1.bin")
	if e != nil {
		t.Fatal(e)
	}
	googleInitial, e := os.ReadFile("internal/quicfast/testdata/google-v1.bin")
	if e != nil {
		t.Fatal(e)
	}
	// Establish the encrypted peer session before the burst. UDP itself has no
	// retransmission during a cold WG/AWG handshake; this test checks packet
	// mapping and concurrent traffic on an established VPN, not UDP reliability.
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	warm, warmErr := wgDialTCPContext(ctx, "10.99.0.1:443")
	cancel()
	if warmErr != nil {
		t.Fatal(warmErr)
	}
	warm.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			payload := []byte{0x40, byte(i), 0x55, 0x66}
			if i == 0 {
				payload = initial
			}
			if i == 1 {
				payload = googleInitial
			}
			// Three separate mappings: YouTube, Chrome/Google and unknown cached QUIC.
			clientPort := uint16(42000 + i%3)
			packet := rawTestUDP(payload, clientPort)
			app.SetDeadline(time.Now().Add(2500 * time.Millisecond))
			if _, e := app.Write(packet); e != nil {
				t.Error(e)
				return
			}
			reply := make([]byte, 1500)
			n, e := app.Read(reply)
			if e != nil || n < 28 || binary.BigEndian.Uint16(reply[22:24]) != clientPort || !bytes.Equal(payload, reply[28:n]) {
				t.Errorf("raw QUIC roundtrip %d: len=%d err=%v stats=%s flow=%s", i, n, e, WgUpstreamStats(), FlowLog())
				return
			}
		}
	}()

	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
			defer cancel()
			c, e := wgDialTCPContext(ctx, "10.99.0.1:443")
			if e != nil {
				t.Error(e)
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			c.Write([]byte{42})
			b := make([]byte, 1)
			if _, e = c.Read(b); e != nil || b[0] != 42 {
				t.Error(fmt.Sprintf("echo %v %v", b, e))
			}
		}()
	}
	wg.Wait()
}

// Linux has no Android PeekLookAtSocketFd; use the same packet I/O and engine
// with a loopback bind. Production protection is tested in packetvpn separately.
type testPacketTun struct {
	f      *os.File
	events chan tun.Event
}

func (p *testPacketTun) File() *os.File           { return p.f }
func (p *testPacketTun) Name() (string, error)    { return "test", nil }
func (p *testPacketTun) MTU() (int, error)        { return 1280, nil }
func (p *testPacketTun) Events() <-chan tun.Event { return p.events }
func (p *testPacketTun) BatchSize() int           { return 1 }
func (p *testPacketTun) Close() error             { close(p.events); return p.f.Close() }
func (p *testPacketTun) Read(b [][]byte, s []int, o int) (int, error) {
	n, e := p.f.Read(b[0][o:])
	if e != nil {
		return 0, e
	}
	s[0] = n
	return 1, nil
}
func (p *testPacketTun) Write(b [][]byte, o int) (int, error) {
	for i, v := range b {
		if _, e := p.f.Write(v[o:]); e != nil {
			return i, e
		}
	}
	return len(b), nil
}
func testPacketDevice(fd, mtu int, settings string, protect func(int) bool, logf func(string, ...any)) (*device.Device, error) {
	t := &testPacketTun{os.NewFile(uintptr(fd), "test-wg"), make(chan tun.Event)}
	d := device.NewDevice(t, struct{ conn.Bind }{conn.NewStdNetBind()}, &device.Logger{Verbosef: func(string, ...any) {}, Errorf: logf}, false, func(device.StatusCode) {})
	if e := d.IpcSet(settings); e != nil {
		d.Close()
		return nil, e
	}
	if e := d.Up(); e != nil {
		d.Close()
		return nil, e
	}
	return d, nil
}

// Complete IPv4 datagram from the Android side, including its UDP checksum.
func rawTestUDP(payload []byte, clientPort uint16) []byte {
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	b[8] = 64
	b[9] = 17
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	copy(b[12:], []byte{10, 99, 0, 2})
	copy(b[16:], []byte{10, 99, 0, 1})
	sum := func(b []byte) uint16 {
		var s uint32
		for len(b) > 1 {
			s += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) > 0 {
			s += uint32(b[0]) << 8
		}
		for s>>16 != 0 {
			s = (s & 65535) + (s >> 16)
		}
		return ^uint16(s)
	}
	binary.BigEndian.PutUint16(b[10:], sum(b[:20]))
	binary.BigEndian.PutUint16(b[20:], clientPort)
	binary.BigEndian.PutUint16(b[22:], 443)
	binary.BigEndian.PutUint16(b[24:], uint16(len(b)-20))
	copy(b[28:], payload)
	pseudo := append([]byte(nil), b[12:20]...)
	pseudo = append(pseudo, 0, 17, byte((len(b)-20)>>8), byte(len(b)-20))
	pseudo = append(pseudo, b[20:]...)
	binary.BigEndian.PutUint16(b[26:], sum(pseudo))
	return b
}

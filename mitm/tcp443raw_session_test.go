package mitm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device/iobased"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

func TestRaw443StopPreservesAndStartRotatesSession(t *testing.T) {
	SetTcp443RawInclude(true)
	defer SetTcp443RawInclude(false)
	c := raw443Current.Load()
	f := &raw443Flow{counts: c, host: "example.com", dst: "192.0.2.1:443", fid: 71}
	f.begin()
	f.sent(true, 2048)
	f.sent(false, 102401)
	SetTcp443RawInclude(false)
	if raw443Current.Load() != c || raw443Last.Load() != c {
		t.Fatal("STOP discarded session")
	}
	// Actual shutdown EOF can happen AFTER STOP. Last session must see it.
	f.read(true, 0, io.EOF)
	f.finish("vpn_stop")
	if !strings.Contains(Tcp443LastSessionStats(), "TCP443_RAW_APP_BYTES_TOTAL=2048") {
		t.Fatal(Tcp443LastSessionStats())
	}
	var summaries []raw443Summary
	if err := json.Unmarshal([]byte(Tcp443LastSessionFlows()), &summaries); err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].EndTime == 0 || !summaries[0].ClientEOF || summaries[0].UpstreamBytes != 102401 {
		t.Fatal(summaries)
	}
	SetTcp443RawInclude(true)
	if raw443Current.Load() == c || raw443Current.Load().started.Load() != 0 || raw443Last.Load() != c {
		t.Fatal("START did not rotate session")
	}
	if c.finished.Load() != 1 {
		t.Fatal("final summary not exactly once")
	}
	f.finish("duplicate")
	if c.finished.Load() != 1 {
		t.Fatal("duplicate finish")
	}
}
func TestRaw443WatchdogReportsWithoutClosing(t *testing.T) {
	f := &raw443Flow{counts: new(raw443Counters), host: "example.com", fid: 72}
	f.begin()
	defer f.finish("test_end")
	f.mu.Lock()
	last := f.lastActivity
	f.mu.Unlock()
	f.watchdog(last.Add(11*time.Second), 10*time.Second)
	f.watchdog(last.Add(12*time.Second), 10*time.Second)
	if f.counts.stuck.Load() != 1 || f.counts.finished.Load() != 0 {
		t.Fatal("watchdog closed or repeated flow")
	}
	select {
	case <-f.done:
		t.Fatal("watchdog closed flow")
	default:
	}
	f.sent(false, 7)
	if f.snapshot().UpstreamBytes != 7 {
		t.Fatal("flow did not continue after watchdog")
	}
}
func TestRaw443PacketDeliveryAndACKObservation(t *testing.T) {
	f := &raw443Flow{counts: new(raw443Counters), host: "example.com", fid: 73}
	f.begin()
	defer f.finish("test_end")
	raw443AttachPackets(f, stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}), RemotePort: 12345, LocalAddress: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), LocalPort: 443})
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
	p := packet(true, 2048, 0)
	original := append([]byte(nil), p...)
	raw443ObserveTunPacket(p, true)
	raw443ObserveTunPacket(packet(false, 0, 2049), false)
	s := f.snapshot()
	if s.TunPayloadBytesToApp != 2048 || s.AppACKCount != 1 || s.AppLastACK != 2049 || s.AppWindow != 4096 || !bytes.Equal(p, original) {
		t.Fatal(s)
	}
	// Truncated TCP/IP is ignored, never interpreted as delivery.
	raw443ObserveTunPacket(p[:25], true)
	if f.snapshot().TunPacketsToApp != 1 {
		t.Fatal("truncated packet counted")
	}
}

type rawAdapterTestHandler struct {
	upstream net.Conn
	flow     *raw443Flow
	done     chan struct{}
}

func (h *rawAdapterTestHandler) HandleTCP(c adapter.TCPConn) {
	defer c.Close() // mirrors tunHandler/handle443's outer defer
	raw443AttachPackets(h.flow, c.ID())
	relay443Raw(c, h.upstream, h.flow) // synchronous, no early return
	close(h.done)
}
func (h *rawAdapterTestHandler) HandleUDP(c adapter.UDPConn) { c.Close() }

// Real tun2socks adapter + gVisor + packet fd, not a net.Pipe mock. App FIN
// must preserve a 256 KiB pending response through the reverse TUN packet path.
func TestRaw443AdapterSustainedResponseAfterFIN(t *testing.T) {
	SetTcp443RawInclude(true)
	defer SetTcp443RawInclude(false)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	appFile := os.NewFile(uintptr(fds[0]), "raw-app-packets")
	tunFile := os.NewFile(uintptr(fds[1]), "raw-tun-packets")
	appEP, err := iobased.New(appFile, 1280, 0)
	if err != nil {
		t.Fatal(err)
	}
	tunEP, err := iobased.New(&tunCounter{f: tunFile}, 1280, 0)
	if err != nil {
		t.Fatal(err)
	}
	appStack := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}, TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol}})
	if e := appStack.CreateNIC(1, appEP); e != nil {
		t.Fatal(e)
	}
	if e := appStack.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{10, 0, 0, 2}).WithPrefix()}, stack.AddressProperties{}); e != nil {
		t.Fatal(e)
	}
	appStack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}})
	relayUp, up := rawTestTCPPair(t)
	f := &raw443Flow{counts: raw443Current.Load(), host: "example.com", dst: "192.0.2.1:443", fid: 74}
	f.begin()
	h := &rawAdapterTestHandler{upstream: relayUp, flow: f, done: make(chan struct{})}
	tunStack, err := core.CreateStack(&core.Config{LinkEndpoint: tunEP, TransportHandler: h})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		appFile.Close()
		tunFile.Close()
		appStack.Close()
		tunStack.Close()
		appEP.Close()
		tunEP.Close()
		appEP.Wait()
		tunEP.Wait()
	}()
	app, err := gonet.DialTCP(appStack, tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}), Port: 443}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.SetDeadline(time.Now().Add(5 * time.Second))
	request := bytes.Repeat([]byte("request"), 600)
	if _, err = app.Write(request); err != nil {
		t.Fatal(err)
	}
	app.CloseWrite()
	got, err := io.ReadAll(up)
	if err != nil || !bytes.Equal(got, request) {
		t.Fatalf("request bytes=%d err=%v", len(got), err)
	}
	select {
	case <-h.done:
		t.Fatal("adapter returned before response")
	default:
	}
	response := bytes.Repeat([]byte("response"), 32768)
	upDone := make(chan error, 1)
	go func() { _, e := up.Write(response); up.CloseWrite(); upDone <- e }()
	got, err = io.ReadAll(app)
	if err != nil || !bytes.Equal(got, response) {
		t.Fatalf("response bytes=%d err=%v", len(got), err)
	}
	if err = <-upDone; err != nil {
		t.Fatal(err)
	}
	rawTestDone(t, h.done)
	// gVisor Write acceptance/relay EOF can precede actual packet drain.
	deadline := time.Now().Add(time.Second)
	for f.snapshot().TunPayloadBytesToApp < int64(len(response)) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s := f.snapshot()
	if s.UpstreamBytes != int64(len(response)) || s.TunPayloadBytesToApp < int64(len(response)) || s.AppACKCount < 2 || s.HalfCloseClient != "ok" || s.HalfCloseUpstream != "ok" || f.counts.fail.Load() != 0 {
		t.Fatalf("adapter summary=%+v", s)
	}
}

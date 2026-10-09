package mitm

import (
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestAppScopeTCPTracePreservesTunPackets(t *testing.T) {
	SetAppScopeContentAllowlist("INCLUDE", "com.android.chrome", true)
	defer SetAppScopeContentAllowlist("OFF", "", false)
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	app, tun := os.NewFile(uintptr(fds[0]), "app"), os.NewFile(uintptr(fds[1]), "tun")
	defer app.Close()
	defer tun.Close()
	counter := &tunCounter{f: tun}
	for _, v6 := range []bool{false, true} {
		packet := packetTCP(v6, 1234, 2, nil)
		p, _ := parseBrowserPacket(packet)
		dnsIPMapMu.Lock()
		saved := dnsIPMap[p.dst.Addr().String()]
		delete(dnsIPMap, p.dst.Addr().String())
		dnsIPMapMu.Unlock()
		t.Cleanup(func() { dnsIPMapMu.Lock(); dnsIPMap[p.dst.Addr().String()] = saved; dnsIPMapMu.Unlock() })
		dnsIPMapPut(p.dst.Addr().String(), "lenta.ru", 60)
		app.Write(packet)
		buf := make([]byte, 2048)
		n, err := counter.Read(buf)
		if err != nil || !bytes.Equal(packet, buf[:n]) {
			t.Fatal("trace changed incoming SYN", err)
		}
		if !strings.Contains(FlowLog(), "stage=tun_read") || !strings.Contains(FlowLog(), "host=\"lenta.ru\" hostSource=dns") {
			t.Fatal("missing pre-stack trace")
		}
		replyTCP := append([]byte(nil), packet[p.off:]...)
		replyTCP[13] = 18
		reply := browserReply(p, replyTCP)
		counter.Write(reply)
		n, err = app.Read(buf)
		if err != nil || !bytes.Equal(reply, buf[:n]) {
			t.Fatal("trace changed outgoing packet", err)
		}
	}
	SetAppScopeContentAllowlist("GLOBAL", "", true)
	before := strings.Count(FlowLog(), "APP_SCOPE_TCP")
	appScopeTraceTCPPacket(packetTCP(false, 1, 2, nil), false)
	if strings.Count(FlowLog(), "APP_SCOPE_TCP") != before {
		t.Fatal("verbose trace leaked into global mode")
	}
}

func TestAppScopeRUHostReachesUpstreamDial(t *testing.T) {
	SetAppScopeContentAllowlist("INCLUDE", "com.android.chrome", true)
	SetBrowserCompatibility("INCLUDE", "com.android.chrome")
	defer func() { SetAppScopeContentAllowlist("OFF", "", false); SetBrowserCompatibility("OFF", "") }()
	for _, host := range []string{"lenta.ru", "icdn.lenta.ru", "dzen.ru", "google.com"} {
		// An ephemeral closed destination produces a real connect error. It
		// proves the request reaches the dial instead of a hostname drop.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		dst := listener.Addr().String()
		listener.Close()
		app, tun := net.Pipe()
		done := make(chan struct{})
		go func() { handle443(diagnosticTestConn{tun, stack.TransportEndpointID{}}, dst); close(done) }()
		app.SetDeadline(time.Now().Add(3 * time.Second))
		_, err = app.Write(capturedBrowserHello(t, host))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, app)
		app.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("flow did not finish")
		}
		log := FlowLog()
		if !strings.Contains(log, "stage=upstream_dial") || !strings.Contains(log, "host=\""+host+"\" hostSource=sni decision=allow reason=\"BROWSER_TLS_PASSTHROUGH\"") {
			t.Fatalf("%s did not reach upstream: %s", host, log)
		}
	}
}

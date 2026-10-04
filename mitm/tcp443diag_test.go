package mitm

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type diagnosticTestConn struct {
	net.Conn
	id stack.TransportEndpointID
}

func (c diagnosticTestConn) ID() stack.TransportEndpointID { return c.id }

type diagnosticTestScope struct{ t *testing.T }

func (s diagnosticTestScope) DirectForFlow(src string, port int64, dst string, dport int64) bool {
	if src != "10.0.0.3" || dst != "127.0.0.1" || dport != 443 {
		s.t.Errorf("incorrect Android UID tuple: %s:%d -> %s:%d", src, port, dst, dport)
	}
	return port == 42000
}
func TestScopedDirect443PreservesRemoteTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "upstream-response") }))
	defer server.Close()
	root := x509.NewCertPool()
	root.AddCert(server.Certificate())
	SetDirect443(true)
	SetDirect443Scope(diagnosticTestScope{t})
	ResetTCP443Diagnostics()
	old := contentFilterEnabled()
	SetContentFilter(true)
	defer func() { SetDirect443(false); SetDirect443Scope(nil); SetContentFilter(old) }()
	app, tun := net.Pipe()
	defer app.Close()
	id := stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4([4]byte{10, 0, 0, 3}), RemotePort: 42000, LocalAddress: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), LocalPort: 443}
	wrapped := diagnosticTestConn{tun, id}
	id.RemotePort = 42001
	if diagnostic443For(diagnosticTestConn{tun, id}) {
		t.Fatal("another app received diagnostic bypass")
	}
	SetDirect443Scope(nil)
	if diagnostic443For(wrapped) {
		t.Fatal("missing UID scope enabled a global bypass")
	}
	SetDirect443Scope(diagnosticTestScope{t})
	done := make(chan struct{})
	go func() { handle443(wrapped, server.Listener.Addr().String()); close(done) }()
	client := tls.Client(app, &tls.Config{RootCAs: root, ServerName: "example.com"})
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if !client.ConnectionState().PeerCertificates[0].Equal(server.Certificate()) {
		t.Fatal("diagnostic replaced upstream certificate")
	}
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "upstream-response" {
		t.Fatalf("response %q err=%v", body, err)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("direct relay leaked after client close")
	}
	if counts443["TCP443_DIRECT_ATTEMPT"].Load() != 1 || counts443["TCP443_DIRECT_OK"].Load() != 1 || counts443["TCP443_DIRECT_FAIL"].Load() != 0 || counts443["MITM443_ATTEMPT"].Load() != 0 {
		t.Fatal(Tcp443Diagnostics())
	}
}
func TestDirect443NoReplyIsFailure(t *testing.T) {
	ResetTCP443Diagnostics()
	app, client := net.Pipe()
	remote, up := net.Pipe()
	defer app.Close()
	done := make(chan struct{})
	go func() { relay443Diagnostic(client, up, "example.com", "192.0.2.1:443"); close(done) }()
	remote.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay leaked without upstream data")
	}
	if counts443["TCP443_DIRECT_OK"].Load() != 0 || counts443["TCP443_DIRECT_FAIL"].Load() != 1 {
		t.Fatal(Tcp443Diagnostics())
	}
}

func TestScopedDirect443StillBlocksSNI(t *testing.T) {
	blockedMu.Lock()
	saved := blockedDomains
	blockedDomains = map[string]bool{"blocked.example.com": true}
	blockedMu.Unlock()
	defer func() { blockedMu.Lock(); blockedDomains = saved; blockedMu.Unlock() }()
	SetDirect443(true)
	SetDirect443Scope(diagnosticTestScope{t})
	ResetTCP443Diagnostics()
	defer func() { SetDirect443(false); SetDirect443Scope(nil) }()
	app, tun := net.Pipe()
	defer app.Close()
	id := stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4([4]byte{10, 0, 0, 3}), RemotePort: 42000, LocalAddress: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), LocalPort: 443}
	done := make(chan struct{})
	go func() { handle443(diagnosticTestConn{tun, id}, "127.0.0.1:1"); close(done) }()
	client := tls.Client(app, &tls.Config{ServerName: "blocked.example.com"})
	client.SetDeadline(time.Now().Add(time.Second))
	if err := client.Handshake(); err == nil {
		t.Fatal("blocked SNI accepted TLS")
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked SNI leaked connection")
	}
	if counts443["TCP443_DIRECT_ATTEMPT"].Load() != 0 || counts443["MITM443_ATTEMPT"].Load() != 0 {
		t.Fatal("blocklist did not run before diagnostic dial: " + Tcp443Diagnostics())
	}
}

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

func TestBrowserCompatibilityScope(t *testing.T) {
	defer SetBrowserCompatibility("OFF", "")
	for _, tc := range []struct {
		mode, apps string
		want       bool
	}{
		{"INCLUDE", "com.android.chrome", true},
		{"INCLUDE", "com.android.chrome,com.google.android.googlequicksearchbox", true},
		{"GLOBAL", "com.android.chrome", false},
		{"EXCLUDE", "com.android.chrome", false},
		{"INCLUDE", "", false},
		{"INCLUDE", "com.android.chrome,com.google.android.youtube", false},
		{"INCLUDE", "other.app", false},
	} {
		SetBrowserCompatibility(tc.mode, tc.apps)
		if browserCompatibility.Load() != tc.want {
			t.Fatalf("scope %s %s", tc.mode, tc.apps)
		}
	}
}
func TestBrowserCompatibilityPreservesRemoteTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "upstream-response") }))
	defer server.Close()
	root := x509.NewCertPool()
	root.AddCert(server.Certificate())
	SetBrowserCompatibility("INCLUDE", "com.android.chrome")
	ResetTCP443Diagnostics()
	old := contentFilterEnabled()
	SetContentFilter(true)
	defer func() { SetBrowserCompatibility("OFF", ""); SetContentFilter(old) }()
	app, tun := net.Pipe()
	defer app.Close()
	id := stack.TransportEndpointID{RemoteAddress: tcpip.AddrFrom4([4]byte{10, 0, 0, 3}), RemotePort: 42000, LocalAddress: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), LocalPort: 443}
	wrapped := diagnosticTestConn{tun, id}
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
	if counts443["MITM443_ATTEMPT"].Load() != 0 {
		t.Fatal(Tcp443Diagnostics())
	}
}
func TestBrowserCompatibilityStillBlocksSNI(t *testing.T) {
	blockedMu.Lock()
	saved := blockedDomains
	blockedDomains = map[string]bool{"blocked.example.com": true}
	blockedMu.Unlock()
	defer func() { blockedMu.Lock(); blockedDomains = saved; blockedMu.Unlock() }()
	SetBrowserCompatibility("INCLUDE", "com.android.chrome")
	ResetTCP443Diagnostics()
	defer func() { SetBrowserCompatibility("OFF", "") }()
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

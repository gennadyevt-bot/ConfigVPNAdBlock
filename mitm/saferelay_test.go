package mitm

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func safeRelayTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, e := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	c, e := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	s, e := l.AcceptTCP()
	if e != nil {
		c.Close()
		t.Fatal(e)
	}
	for _, v := range []*net.TCPConn{c, s} {
		v.SetDeadline(time.Now().Add(4 * time.Second))
		t.Cleanup(func() { v.Close() })
	}
	return c, s
}
func TestSafeRelayHalfCloseDrainsResponse(t *testing.T) {
	app, client := safeRelayTCPPair(t)
	up, server := safeRelayTCPPair(t)
	resetSafeTLS()
	f := newSafeTLSFlow(123, "example.test", "192.0.2.1:443", nil)
	request := []byte("request requiring EOF")
	response := bytes.Repeat([]byte{71}, 256*1024)
	done := make(chan string, 1)
	go func() { done <- relaySafeTLS(client, up, f) }()
	serverDone := make(chan error, 1)
	go func() {
		b, e := io.ReadAll(server)
		if e == nil && !bytes.Equal(b, request) {
			e = errors.New("changed request")
		}
		if e == nil {
			_, e = server.Write(response)
		}
		server.CloseWrite()
		serverDone <- e
	}()
	if _, e := app.Write(request); e != nil {
		t.Fatal(e)
	}
	if e := app.CloseWrite(); e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(app)
	if e != nil || !bytes.Equal(b, response) {
		t.Fatalf("response length=%d err=%v", len(b), e)
	}
	if e := <-serverDone; e != nil {
		t.Fatal(e)
	}
	if r := <-done; r != "client_eof+upstream_eof" {
		t.Fatal(r)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.v.HalfCloseClient != "ok" || f.v.HalfCloseUpstream != "ok" || f.v.AppBytes != int64(len(request)) || f.v.UpstreamBytes != int64(len(response)) {
		t.Fatal(f.v)
	}
}

type safeRelayBrokenRead struct{ net.Conn }

func (c safeRelayBrokenRead) Read([]byte) (int, error) { return 0, errors.New("injected read failure") }
func TestSafeRelayErrorCancelsOppositeReader(t *testing.T) {
	app, client := net.Pipe()
	up, server := net.Pipe()
	defer app.Close()
	defer server.Close()
	resetSafeTLS()
	f := newSafeTLSFlow(124, "example.test", "192.0.2.1:443", nil)
	done := make(chan string, 1)
	go func() { done <- relaySafeTLS(client, safeRelayBrokenRead{up}, f) }()
	select {
	case r := <-done:
		if !strings.Contains(r, "injected read failure") {
			t.Fatal(r)
		}
	case <-time.After(time.Second):
		t.Fatal("opposite reader was left blocked")
	}
}

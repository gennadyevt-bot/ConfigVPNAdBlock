package mitm

import (
	"io"
	"net"
	"testing"
	"time"
)

// Real TCP pairs exercise FIN/CloseWrite; net.Pipe cannot model half-close.
func rawTestTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() { c, _ := l.AcceptTCP(); accepted <- c }()
	a, err := net.DialTCP("tcp", nil, l.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	b := <-accepted
	if b == nil {
		a.Close()
		t.Fatal("accept failed")
	}
	deadline := time.Now().Add(3 * time.Second)
	a.SetDeadline(deadline)
	b.SetDeadline(deadline)
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
func rawTestRelay(t *testing.T) (*net.TCPConn, *net.TCPConn, *raw443Flow, <-chan struct{}) {
	t.Helper()
	app, relayApp := rawTestTCPPair(t)
	relayUp, upstream := rawTestTCPPair(t)
	f := &raw443Flow{counts: new(raw443Counters), host: "example.com", dst: "192.0.2.1:443", fid: 1}
	done := make(chan struct{})
	go func() { relay443Raw(relayApp, relayUp, f); close(done) }()
	return app, upstream, f, done
}
func rawTestDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("raw relay did not finish")
	}
}
func TestRaw443ClientEOFKeepsPendingResponse(t *testing.T) {
	app, up, f, done := rawTestRelay(t)
	if _, err := app.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	app.CloseWrite()
	request, err := io.ReadAll(up)
	if err != nil || string(request) != "request" {
		t.Fatalf("upstream request=%q err=%v", request, err)
	}
	select {
	case <-done:
		t.Fatal("client FIN killed pending response")
	default:
	}
	if _, err := up.Write([]byte("pending-response")); err != nil {
		t.Fatal(err)
	}
	up.CloseWrite()
	response, err := io.ReadAll(app)
	if err != nil || string(response) != "pending-response" {
		t.Fatalf("app response=%q err=%v", response, err)
	}
	rawTestDone(t, done)
	if f.counts.upOK.Load() != 1 || f.counts.downOK.Load() != 1 || f.counts.fail.Load() != 0 || f.counts.appBytes.Load() != 7 || f.counts.upstreamBytes.Load() != 16 {
		t.Fatal("incorrect raw success/byte counts")
	}
}
func TestRaw443UpstreamEOFKeepsPendingRequest(t *testing.T) {
	app, up, f, done := rawTestRelay(t)
	up.Write([]byte("early-response"))
	up.CloseWrite()
	response, err := io.ReadAll(app)
	if err != nil || string(response) != "early-response" {
		t.Fatalf("response=%q err=%v", response, err)
	}
	select {
	case <-done:
		t.Fatal("upstream FIN killed pending request")
	default:
	}
	if _, err := app.Write([]byte("late-request")); err != nil {
		t.Fatal(err)
	}
	app.CloseWrite()
	request, err := io.ReadAll(up)
	if err != nil || string(request) != "late-request" {
		t.Fatalf("request=%q err=%v", request, err)
	}
	rawTestDone(t, done)
	if f.counts.upOK.Load() != 1 || f.counts.downOK.Load() != 1 || f.counts.fail.Load() != 0 {
		t.Fatal("half-close not counted correctly")
	}
}
func TestRaw443ZeroResponseFails(t *testing.T) {
	app, up, f, done := rawTestRelay(t)
	app.Write([]byte("request"))
	app.CloseWrite()
	if _, err := io.ReadAll(up); err != nil {
		t.Fatal(err)
	}
	up.CloseWrite()
	response, err := io.ReadAll(app)
	if err != nil || len(response) != 0 {
		t.Fatalf("response=%q err=%v", response, err)
	}
	rawTestDone(t, done)
	if f.counts.upOK.Load() != 1 || f.counts.downOK.Load() != 0 || f.counts.fail.Load() != 1 {
		t.Fatal("zero response must be RAW_FAIL, never DOWN_OK")
	}
}
func TestRaw443BidirectionalExchange(t *testing.T) {
	app, up, f, done := rawTestRelay(t)
	for _, request := range []string{"client-hello", "encrypted-request", "more-request"} {
		if _, err := app.Write([]byte(request)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(request))
		if _, err := io.ReadFull(up, got); err != nil || string(got) != request {
			t.Fatalf("request=%q err=%v", got, err)
		}
		reply := "server:" + request
		up.Write([]byte(reply))
		got = make([]byte, len(reply))
		if _, err := io.ReadFull(app, got); err != nil || string(got) != reply {
			t.Fatalf("reply=%q err=%v", got, err)
		}
	}
	app.CloseWrite()
	up.CloseWrite()
	rawTestDone(t, done)
	if f.counts.upOK.Load() != 1 || f.counts.downOK.Load() != 1 || f.counts.fail.Load() != 0 {
		t.Fatal("bidirectional raw exchange failed")
	}
}
func TestRaw443NeverFallsBackToSystemSocket(t *testing.T) {
	if wgUpstreamActive() {
		t.Fatal("unexpected active WG from another test")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	SetTcp443RawInclude(true)
	defer SetTcp443RawInclude(false)
	app, client := net.Pipe()
	defer app.Close()
	defer client.Close()
	reason := raw443ThroughWG(client, listener.Addr().String(), "example.com", []byte("client-hello"), 2, raw443Current.Load())
	if reason != "rawWgDialFail" {
		t.Fatal("inactive WG did not fail closed")
	}
	c := raw443Current.Load()
	if c.attempt.Load() != 1 || c.fail.Load() != 1 || c.upOK.Load() != 0 || c.downOK.Load() != 0 {
		t.Fatal(Tcp443RawStats())
	}
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
	if conn, err := listener.Accept(); err == nil {
		conn.Close()
		t.Fatal("RAW dial escaped into system network")
	}
}

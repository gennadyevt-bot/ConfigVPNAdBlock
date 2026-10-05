package mitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func tlsTestRecord(kind byte, body []byte) []byte {
	p := []byte{kind, 3, 3, 0, 0}
	binary.BigEndian.PutUint16(p[3:5], uint16(len(body)))
	return append(p, body...)
}
func TestPassiveTLSFragmentedServerHello(t *testing.T) {
	// TLS 1.3 supported_versions extension; ALPN is encrypted afterwards.
	body := make([]byte, 38)
	body[0] = 3
	body[1] = 3
	body = append(body, 0, 6, 0, 43, 0, 2, 3, 4)
	hs := append([]byte{2, 0, 0, byte(len(body))}, body...)
	packet := append(tlsTestRecord(22, hs), tlsTestRecord(23, []byte{1, 2, 3})...)
	var logs []string
	o := tlsRecordObserver{emit: func(e, d string) { logs = append(logs, e+" "+d) }}
	for _, b := range packet {
		o.feed([]byte{b})
	}
	joined := strings.Join(logs, ";")
	if !strings.Contains(joined, "selectedVersion=0x0304") || !strings.Contains(joined, "selectedALPN=encrypted") || !strings.Contains(joined, "ENCRYPTED") {
		t.Fatal(joined)
	}
	if strings.Contains(joined, "handshake_complete=true") {
		t.Fatal("claimed an invisible TLS 1.3 handshake")
	}
}
func TestPassiveTLSAlertAndLimits(t *testing.T) {
	var events []string
	o := tlsRecordObserver{emit: func(e, d string) { events = append(events, e+" "+d) }}
	o.feed(tlsTestRecord(21, []byte{2, 46}))
	if len(events) != 1 || !strings.Contains(events[0], "description=46") {
		t.Fatal(events)
	}
	o.feed([]byte{22, 3, 3, 255, 255, 0})
	if !o.disabled || len(o.buf) != 0 {
		t.Fatal("unbounded invalid record")
	}
	// TLS 1.2 alert after ChangeCipherSpec is ciphertext, not a visible alert.
	events = nil
	o = tlsRecordObserver{emit: func(e, d string) { events = append(events, e+" "+d) }}
	o.feed(tlsTestRecord(20, []byte{1}))
	o.feed(tlsTestRecord(21, []byte{2, 46}))
	if len(events) != 1 || !strings.HasPrefix(events[0], "ENCRYPTED") {
		t.Fatal(events)
	}
}
func TestPassiveTLSWrappersPreserveExchange(t *testing.T) {
	resetSafeTLS()
	f := newSafeTLSFlow(1, "example.test", "192.0.2.1:443", nil)
	app, client := net.Pipe()
	server, up := net.Pipe()
	defer app.Close()
	defer server.Close()
	for _, c := range []net.Conn{app, client, server, up} {
		c.SetDeadline(time.Now().Add(3 * time.Second))
	}
	request := tlsTestRecord(23, bytes.Repeat([]byte{7}, 12000))
	response := tlsTestRecord(23, bytes.Repeat([]byte{9}, 15000))
	done := make(chan struct{})
	go func() {
		relay(&safeTLSConn{Conn: client, f: f, client: true}, &safeTLSConn{Conn: up, f: f})
		f.finish("test")
		close(done)
	}()
	serverDone := make(chan error, 1)
	go func() {
		b := make([]byte, len(request))
		_, e := io.ReadFull(server, b)
		if e == nil && !bytes.Equal(b, request) {
			e = fmt.Errorf("request changed")
		}
		if e == nil {
			_, e = server.Write(response)
		}
		server.Close()
		serverDone <- e
	}()
	if _, e := app.Write(request); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, len(response))
	if _, e := io.ReadFull(app, b); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b, response) {
		t.Fatal("response changed")
	}
	app.Close()
	<-done
	if e := <-serverDone; e != nil {
		t.Fatal(e)
	}
	f.mu.Lock()
	v := f.v
	f.mu.Unlock()
	if v.AppBytes != int64(len(request)) || v.UpstreamBytes != int64(len(response)) || v.EndAt == 0 {
		t.Fatalf("%+v", v)
	}
	if !strings.Contains(SafeTLSFlows(), "example.test") {
		t.Fatal("summary missing after close")
	}
}
func TestMITMServedChainUsesLoadedCA(t *testing.T) {
	dir := t.TempDir()
	ca, _, e := loadOrCreateCA(dir)
	if e != nil {
		t.Fatal(e)
	}
	root, e := x509.ParseCertificate(ca.Certificate[0])
	if e != nil {
		t.Fatal(e)
	}
	setMITMCA(ca, root)
	reload, _, e := loadOrCreateCA(dir)
	if e != nil || !bytes.Equal(reload.Certificate[0], root.Raw) {
		t.Fatal("CA changed on reload", e)
	}
	for _, host := range []string{"cdn.ampproject.org", "encrypted-tbn0.gstatic.com", "dzen.ru"} {
		leaf, e := certForName(host)
		if e != nil {
			t.Fatal(e)
		}
		if len(leaf.Certificate) != 2 || !bytes.Equal(leaf.Certificate[1], root.Raw) {
			t.Fatal("wrong signer chain")
		}
		a, b := net.Pipe()
		a.SetDeadline(time.Now().Add(3 * time.Second))
		b.SetDeadline(time.Now().Add(3 * time.Second))
		pool := x509.NewCertPool()
		pool.AddCert(root)
		server := tls.Server(a, &tls.Config{Certificates: []tls.Certificate{*leaf}, NextProtos: []string{"h2", "http/1.1"}})
		client := tls.Client(b, &tls.Config{ServerName: host, RootCAs: pool, NextProtos: []string{"h2"}})
		done := make(chan error, 1)
		go func() { done <- server.Handshake() }()
		e = client.Handshake()
		se := <-done
		a.Close()
		b.Close()
		if e != nil || se != nil {
			t.Fatalf("%s client=%v server=%v", host, e, se)
		}
	}
}

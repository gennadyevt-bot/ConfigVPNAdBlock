package mitm

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
)

// TCP443Scope identifies the original app socket, never the foreground app.
// Android implements this using ConnectivityManager.getConnectionOwnerUid.
type TCP443Scope interface {
	DirectForFlow(sourceIP string, sourcePort int64, destinationIP string, destinationPort int64) bool
}

var tcp443ScopeMu sync.RWMutex
var tcp443Scope TCP443Scope

func SetDirect443Scope(scope TCP443Scope) {
	tcp443ScopeMu.Lock()
	tcp443Scope = scope
	tcp443ScopeMu.Unlock()
}
func diagnostic443For(conn adapter.TCPConn) (match bool) {
	if !direct443On() {
		return false
	}
	tcp443ScopeMu.RLock()
	scope := tcp443Scope
	tcp443ScopeMu.RUnlock()
	// No scope must never expand this experiment to a global MITM bypass.
	if scope == nil {
		return false
	}
	defer func() {
		if v := recover(); v != nil {
			flowLog(fmt.Sprintf("TCP443_DIAG_SCOPE_FAIL err=%v", v))
			match = false
		}
	}()
	id := conn.ID()
	return scope.DirectForFlow(id.RemoteAddress.String(), int64(id.RemotePort), id.LocalAddress.String(), int64(id.LocalPort))
}

var stages443 = []string{"TCP443_DIRECT_ATTEMPT", "TCP443_DIRECT_OK", "TCP443_DIRECT_FAIL", "MITM443_ATTEMPT", "MITM443_TLS_CLIENT_OK", "MITM443_TLS_CLIENT_FAIL", "MITM443_UPSTREAM_OK", "MITM443_UPSTREAM_FAIL", "MITM443_HTTP_OK"}
var counts443 = func() map[string]*atomic.Int64 {
	m := map[string]*atomic.Int64{}
	for _, s := range stages443 {
		m[s] = new(atomic.Int64)
	}
	return m
}()

func stage443(stage, host, detail string) {
	if n := counts443[stage]; n != nil {
		n.Add(1)
	}
	flowLog(fmt.Sprintf("%s sni=%q %s", stage, host, detail))
}
func ResetTCP443Diagnostics() {
	for _, n := range counts443 {
		n.Store(0)
	}
}
func Tcp443Diagnostics() string {
	var s strings.Builder
	fmt.Fprintf(&s, "direct443=%t", direct443On())
	for _, name := range stages443 {
		fmt.Fprintf(&s, " %s=%d", name, counts443[name].Load())
	}
	return s.String()
}

// DIRECT_OK requires upstream bytes successfully delivered back to the app;
// a successful TCP SYN/ACK alone is deliberately not counted as OK.
type diagReplyWriter struct {
	net.Conn
	host      string
	delivered atomic.Int64
	once      sync.Once
}

func (w *diagReplyWriter) Write(b []byte) (int, error) {
	n, e := w.Conn.Write(b)
	if n > 0 {
		w.delivered.Add(int64(n))
		w.once.Do(func() { stage443("TCP443_DIRECT_OK", w.host, "stage=first_upstream_bytes_delivered") })
	}
	return n, e
}
func relay443Diagnostic(client, up net.Conn, host, dst string) {
	defer client.Close()
	defer up.Close()
	writer := &diagReplyWriter{Conn: client, host: host}
	type result struct {
		direction string
		n         int64
		err       error
	}
	done := make(chan result, 2)
	go func() { n, e := io.Copy(writer, up); done <- result{"upstream_to_app", n, e} }()
	go func() { n, e := io.Copy(up, client); done <- result{"app_to_upstream", n, e} }()
	first := <-done
	// Release both goroutines when either peer closes; no timeout/retry policy change.
	client.Close()
	up.Close()
	second := <-done
	if writer.delivered.Load() == 0 {
		stage443("TCP443_DIRECT_FAIL", host, fmt.Sprintf("dst=%s stage=relay_no_reply first=%s err=%v", dst, first.direction, first.err))
	}
	flowLog(fmt.Sprintf("TCP443_DIRECT_END sni=%q dst=%s %s_bytes=%d %s_bytes=%d", host, dst, first.direction, first.n, second.direction, second.n))
}

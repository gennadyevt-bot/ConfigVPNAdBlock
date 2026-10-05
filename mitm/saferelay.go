package mitm

import (
	"fmt"
	"io"
	"net"
	"sync/atomic"
)

// Propagate each clean EOF independently. A request can end before its response;
// only a real copy/half-close error cancels the opposite direction.
func relaySafeTLS(client, upstream net.Conn, f *safeTLSFlow) string {
	defer client.Close()
	defer upstream.Close()
	type result struct {
		direction string
		err       error
	}
	done := make(chan result, 2)
	copySide := func(dst, src net.Conn, up bool) {
		direction := "upstream_to_app"
		if up {
			direction = "app_to_upstream"
		}
		n, err := io.Copy(&safeTLSConn{Conn: dst, f: f, client: !up}, &safeTLSConn{Conn: src, f: f, client: up})
		if up {
			atomic.AddInt64(&dirRx, n)
		} else {
			atomic.AddInt64(&dirTx, n)
		}
		if err == nil {
			status := "unsupported"
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				err = cw.CloseWrite()
				status = "ok"
				if err != nil {
					status = "error:" + err.Error()
				}
			}
			f.mu.Lock()
			if up {
				f.v.HalfCloseUpstream = status
			} else {
				f.v.HalfCloseClient = status
			}
			f.mu.Unlock()
			f.event(up, "HALF_CLOSE", fmt.Sprintf("direction=%s status=%q", direction, status))
		}
		done <- result{direction, err}
	}
	go copySide(upstream, client, true)
	go copySide(client, upstream, false)
	reason := "client_eof+upstream_eof"
	for i := 0; i < 2; i++ {
		r := <-done
		if r.err != nil && reason == "client_eof+upstream_eof" {
			reason = r.direction + ":" + r.err.Error()
			client.Close()
			upstream.Close()
		}
	}
	return reason
}

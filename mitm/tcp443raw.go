package mitm

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// alpha74: selected applications are already scoped by the established Android
// INCLUDE TUN. No UID lookup, TLS termination or system-network fallback here.
var raw443Include atomic.Bool

type raw443Counters struct{ attempt, upOK, downOK, fail, appBytes, upstreamBytes atomic.Int64 }

var raw443Current = func() *atomic.Pointer[raw443Counters] {
	p := new(atomic.Pointer[raw443Counters])
	p.Store(new(raw443Counters))
	return p
}()

func SetTcp443RawInclude(enabled bool) {
	raw443Current.Store(new(raw443Counters))
	raw443Include.Store(enabled)
}
func Tcp443Mode() string {
	if raw443Include.Load() {
		return "RAW_INCLUDE_DIAG"
	}
	return "NORMAL"
}
func Tcp443RawStats() string {
	c := raw443Current.Load()
	return fmt.Sprintf("TCP443_RAW_ATTEMPT=%d TCP443_RAW_UP_OK=%d TCP443_RAW_DOWN_OK=%d TCP443_RAW_FAIL=%d TCP443_RAW_APP_BYTES=%d TCP443_RAW_UPSTREAM_BYTES=%d", c.attempt.Load(), c.upOK.Load(), c.downOK.Load(), c.fail.Load(), c.appBytes.Load(), c.upstreamBytes.Load())
}

type raw443Flow struct {
	counts                     *raw443Counters
	host, dst                  string
	fid                        int64
	upOnce, downOnce, failOnce sync.Once
	delivered                  atomic.Int64
}

func (f *raw443Flow) log(reason, detail string) {
	flowLog(fmt.Sprintf("TCP443_RAW_FLOW id=%d sni=%q dst=%s reason=%s %s", f.fid, f.host, f.dst, reason, detail))
}
func (f *raw443Flow) fail(reason, detail string) {
	f.failOnce.Do(func() { f.counts.fail.Add(1); f.log(reason, detail) })
}
func (f *raw443Flow) sent(up bool, n int) {
	if n <= 0 {
		return
	}
	if up {
		f.counts.appBytes.Add(int64(n))
		f.upOnce.Do(func() { f.counts.upOK.Add(1); f.log("up_ok", "stage=app_bytes_sent") })
	} else {
		f.delivered.Add(int64(n))
		f.counts.upstreamBytes.Add(int64(n))
		f.downOnce.Do(func() { f.counts.downOK.Add(1); f.log("down_ok", "stage=upstream_bytes_delivered_to_app") })
	}
}

// WG-only dial: never call dialTCP(), whose non-unified fallback is a system socket.
func raw443ThroughWG(client net.Conn, dst, host string, prefix []byte, fid int64, counts *raw443Counters) string {
	f := &raw443Flow{counts: counts, host: host, dst: dst, fid: fid}
	f.counts.attempt.Add(1)
	f.log("attempt", "stage=wg_dial")
	if !raw443Include.Load() || raw443Current.Load() != counts {
		f.fail("session_replaced", "stage=before_wg_dial")
		return "rawSessionReplaced"
	}
	upstream, err := wgDialTCP(dst)
	if err != nil {
		f.fail("dial_error", "stage=wg_dial err="+err.Error())
		return "rawWgDialFail"
	}
	defer upstream.Close()
	if !raw443Include.Load() || raw443Current.Load() != counts {
		f.fail("session_replaced", "stage=after_wg_dial")
		return "rawSessionReplaced"
	}
	if err := raw443Write(upstream, prefix, true, f); err != nil {
		f.fail("write_error", "stage=client_hello err="+err.Error())
		return "rawClientHelloFail"
	}
	relay443Raw(client, upstream, f)
	return "rawRelayDone"
}
func raw443Write(dst net.Conn, b []byte, up bool, f *raw443Flow) error {
	for len(b) > 0 {
		n, err := dst.Write(b)
		if n > 0 {
			f.sent(up, n)
			b = b[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

type raw443Result struct {
	direction, reason string
	err               error
}

func raw443Copy(dst, src net.Conn, up bool, f *raw443Flow) raw443Result {
	direction := "upstream_to_app"
	eof := "upstream_eof"
	if up {
		direction = "app_to_upstream"
		eof = "client_eof"
	}
	b := make([]byte, 32*1024)
	for {
		n, err := src.Read(b)
		if n > 0 {
			if we := raw443Write(dst, b[:n], up, f); we != nil {
				return raw443Result{direction, "write_error", we}
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return raw443Result{direction, "read_error", err}
			}
			// Forward FIN only in this direction. The opposite reader stays alive to
			// drain a pending response/request, including after application CloseWrite.
			if cw, ok := dst.(interface{ CloseWrite() error }); ok {
				if e := cw.CloseWrite(); e != nil {
					return raw443Result{direction, "write_error", e}
				}
			} else {
				f.log(eof, "direction="+direction+" half_close=unsupported reverse_kept_open")
			}
			return raw443Result{direction, eof, nil}
		}
	}
}
func relay443Raw(client, upstream net.Conn, f *raw443Flow) {
	defer client.Close()
	defer upstream.Close()
	done := make(chan raw443Result, 2)
	go func() { done <- raw443Copy(upstream, client, true, f) }()
	go func() { done <- raw443Copy(client, upstream, false, f) }()
	for i := 0; i < 2; i++ {
		result := <-done
		f.log(result.reason, fmt.Sprintf("direction=%s err=%v", result.direction, result.err))
		if result.err != nil {
			f.fail(result.reason, "direction="+result.direction+" err="+result.err.Error())
			// Real read/write errors cancel both readers. A clean EOF never does.
			client.Close()
			upstream.Close()
		} else if result.reason == "upstream_eof" && f.delivered.Load() == 0 {
			f.fail("no_upstream_reply", "stage=upstream_eof")
		}
	}
	if f.delivered.Load() == 0 {
		f.fail("no_upstream_reply", "stage=relay_end")
	}
	f.log("relay_end", "both_directions_finished")
}

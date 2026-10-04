package mitm

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// alpha74: selected applications are already scoped by the established Android
// INCLUDE TUN. No UID lookup, TLS termination or system-network fallback here.
var raw443Include atomic.Bool

type raw443Counters struct {
	attempt, upOK, downOK, fail, appBytes, upstreamBytes                             atomic.Int64
	started, finished, stuck, clientEOF, upstreamEOF, readError, writeError, noReply atomic.Int64
	mu                                                                               sync.Mutex
	active                                                                           map[int64]*raw443Flow
	ended                                                                            []*raw443Flow
}

var raw443SessionsMu sync.Mutex
var raw443Last atomic.Pointer[raw443Counters]

var raw443Current = func() *atomic.Pointer[raw443Counters] {
	p := new(atomic.Pointer[raw443Counters])
	p.Store(new(raw443Counters))
	return p
}()

func SetTcp443RawInclude(enabled bool) {
	raw443SessionsMu.Lock()
	defer raw443SessionsMu.Unlock()
	if enabled {
		old := raw443Current.Load()
		if old.started.Load() > 0 {
			raw443PreserveSession(old)
		}
		raw443Current.Store(new(raw443Counters))
	} else {
		// Preserve the same object: late EOF/cleanup updates the stopped session.
		if old := raw443Current.Load(); old.started.Load() > 0 {
			raw443PreserveSession(old)
		}
	}
	raw443Include.Store(enabled)
}

// Caller serializes rotations. Drop packet observers from the older retained
// session so diagnosis cannot accumulate port/flow references over reconnects.
func raw443PreserveSession(c *raw443Counters) {
	previous := raw443Last.Swap(c)
	if previous != nil && previous != c {
		previous.mu.Lock()
		for _, f := range previous.ended {
			raw443DetachPackets(f)
		}
		previous.mu.Unlock()
	}
}
func Tcp443Mode() string {
	if raw443Include.Load() {
		return "RAW_INCLUDE_DIAG"
	}
	return "NORMAL"
}
func Tcp443RawStats() string            { return raw443Stats(raw443Current.Load()) }
func Tcp443CurrentSessionStats() string { return raw443Stats(raw443Current.Load()) }
func Tcp443LastSessionStats() string    { return raw443Stats(raw443Last.Load()) }
func raw443Stats(c *raw443Counters) string {
	if c == nil {
		return "none"
	}
	return fmt.Sprintf("TCP443_RAW_ATTEMPT=%d TCP443_RAW_UP_OK=%d TCP443_RAW_DOWN_OK=%d TCP443_RAW_FAIL=%d TCP443_RAW_APP_BYTES=%d TCP443_RAW_UPSTREAM_BYTES=%d TCP443_RAW_FLOW_STARTED=%d TCP443_RAW_FLOW_FINISHED=%d TCP443_RAW_FLOW_STUCK=%d TCP443_RAW_FLOW_CLIENT_EOF=%d TCP443_RAW_FLOW_UPSTREAM_EOF=%d TCP443_RAW_FLOW_READ_ERROR=%d TCP443_RAW_FLOW_WRITE_ERROR=%d TCP443_RAW_FLOW_NO_REPLY=%d TCP443_RAW_APP_BYTES_TOTAL=%d TCP443_RAW_UPSTREAM_BYTES_TOTAL=%d", c.attempt.Load(), c.upOK.Load(), c.downOK.Load(), c.fail.Load(), c.appBytes.Load(), c.upstreamBytes.Load(), c.started.Load(), c.finished.Load(), c.stuck.Load(), c.clientEOF.Load(), c.upstreamEOF.Load(), c.readError.Load(), c.writeError.Load(), c.noReply.Load(), c.appBytes.Load(), c.upstreamBytes.Load())
}
func Tcp443CurrentSessionFlows() string { return raw443Summaries(raw443Current.Load()) }
func Tcp443LastSessionFlows() string    { return raw443Summaries(raw443Last.Load()) }
func raw443Summaries(c *raw443Counters) string {
	if c == nil {
		return "[]"
	}
	c.mu.Lock()
	flows := append([]*raw443Flow{}, c.ended...)
	for _, f := range c.active {
		flows = append(flows, f)
	}
	c.mu.Unlock()
	ended := make([]raw443Summary, 0, len(flows))
	for _, f := range flows {
		ended = append(ended, f.snapshot())
	}
	b, _ := json.Marshal(ended)
	return string(b)
}

// Unix milliseconds; zero means that event has not happened. Reads include
// ClientHello capture; bytes count only successful destination writes.
type raw443Summary struct {
	AppReadBytes         int64  `json:"appReadBytes"`
	UpstreamReadBytes    int64  `json:"upstreamReadBytes"`
	FlowID               int64  `json:"flowId"`
	Dst                  string `json:"dst"`
	SNI                  string `json:"sni"`
	StartTime            int64  `json:"startTime"`
	EndTime              int64  `json:"endTime"`
	DurationMs           int64  `json:"durationMs"`
	AppBytes             int64  `json:"appToUpstreamBytes"`
	UpstreamBytes        int64  `json:"upstreamToAppBytes"`
	AppReadCount         int64  `json:"appReadCount"`
	UpstreamReadCount    int64  `json:"upstreamReadCount"`
	AppLastReadAt        int64  `json:"appLastReadAt"`
	UpstreamLastReadAt   int64  `json:"upstreamLastReadAt"`
	AppLastWriteAt       int64  `json:"appLastWriteAt"`
	UpstreamLastWriteAt  int64  `json:"upstreamLastWriteAt"`
	ClientEOF            bool   `json:"clientEOF"`
	UpstreamEOF          bool   `json:"upstreamEOF"`
	ClientReadError      string `json:"clientReadError"`
	UpstreamReadError    string `json:"upstreamReadError"`
	ClientWriteError     string `json:"clientWriteError"`
	UpstreamWriteError   string `json:"upstreamWriteError"`
	CloseReason          string `json:"closeReason"`
	HalfCloseClient      string `json:"halfCloseClient"`
	HalfCloseUpstream    string `json:"halfCloseUpstream"`
	Stage                string `json:"stage"`
	AppStage             string `json:"appStage"`
	UpstreamStage        string `json:"upstreamStage"`
	TunPacketsToApp      int64  `json:"tunPacketsToApp"`
	TunPayloadBytesToApp int64  `json:"tunPayloadBytesToApp"`
	TunLastWriteAt       int64  `json:"tunLastWriteAt"`
	AppACKCount          int64  `json:"appACKCount"`
	AppLastACKAt         int64  `json:"appLastACKAt"`
	AppLastACK           uint32 `json:"appLastACK"`
	AppWindow            uint16 `json:"appWindowRaw"`
	AppRST               bool   `json:"appRST"`
	TunRST               bool   `json:"tunRST"`
}
type raw443Flow struct {
	counts                                                                     *raw443Counters
	host, dst                                                                  string
	fid                                                                        int64
	upOnce, downOnce, failOnce                                                 sync.Once
	readErrorOnce, writeErrorOnce, clientEOFOnce, upstreamEOFOnce, noReplyOnce sync.Once
	delivered                                                                  atomic.Int64
	mu                                                                         sync.Mutex
	summary                                                                    raw443Summary
	lastActivity                                                               time.Time
	upMilestone, downMilestone                                                 int
	initOnce, finishOnce                                                       sync.Once
	done                                                                       chan struct{}
	stuckEpisode                                                               bool
	stuckOnce                                                                  sync.Once
	packetKey                                                                  string
	closeReason                                                                string
}

func (f *raw443Flow) begin() {
	f.initOnce.Do(func() {
		now := time.Now()
		f.mu.Lock()
		f.summary = raw443Summary{FlowID: f.fid, Dst: f.dst, SNI: f.host, StartTime: now.UnixMilli(), Stage: "client_hello"}
		f.lastActivity = now
		f.done = make(chan struct{})
		f.mu.Unlock()
		f.counts.started.Add(1)
		f.counts.mu.Lock()
		if f.counts.active == nil {
			f.counts.active = make(map[int64]*raw443Flow)
		}
		f.counts.active[f.fid] = f
		f.counts.mu.Unlock()
		go func() {
			tick := time.NewTicker(time.Second)
			defer tick.Stop()
			for {
				select {
				case <-f.done:
					return
				case now := <-tick.C:
					f.watchdog(now, 10*time.Second)
				}
			}
		}()
	})
}
func (f *raw443Flow) snapshot() raw443Summary {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.summary
	end := s.EndTime
	if end == 0 {
		end = time.Now().UnixMilli()
	}
	s.DurationMs = end - s.StartTime
	return s
}
func (f *raw443Flow) stage(stage string) { f.mu.Lock(); f.summary.Stage = stage; f.mu.Unlock() }
func (f *raw443Flow) directionStage(up bool, stage string) {
	f.mu.Lock()
	if up {
		f.summary.AppStage = stage
	} else {
		f.summary.UpstreamStage = stage
	}
	f.mu.Unlock()
}
func (f *raw443Flow) setHost(host string) {
	f.mu.Lock()
	f.host = host
	f.summary.SNI = host
	f.mu.Unlock()
}
func (f *raw443Flow) progress(event string) {
	s := f.snapshot()
	flowLog(fmt.Sprintf("TCP443_RAW_PROGRESS id=%d sni=%q dst=%s appBytes=%d upstreamBytes=%d appReads=%d upstreamReads=%d stage=%s event=%s", s.FlowID, s.SNI, s.Dst, s.AppBytes, s.UpstreamBytes, s.AppReadCount, s.UpstreamReadCount, s.Stage, event))
}
func (f *raw443Flow) watchdog(now time.Time, idle time.Duration) {
	f.mu.Lock()
	elapsed := now.Sub(f.lastActivity)
	report := f.summary.EndTime == 0 && elapsed >= idle && !f.stuckEpisode
	if report {
		f.stuckEpisode = true
	}
	s := f.summary
	f.mu.Unlock()
	if report {
		f.stuckOnce.Do(func() { f.counts.stuck.Add(1) })
		flowLog(fmt.Sprintf("TCP443_RAW_STUCK flowId=%d dst=%s sni=%q appBytes=%d upstreamBytes=%d lastActivityMs=%d stage=%s appStage=%s upstreamStage=%s tunPackets=%d tunPayloadBytes=%d appACKs=%d lastACK=%d appWindowRaw=%d", s.FlowID, s.Dst, s.SNI, s.AppBytes, s.UpstreamBytes, elapsed.Milliseconds(), s.Stage, s.AppStage, s.UpstreamStage, s.TunPacketsToApp, s.TunPayloadBytesToApp, s.AppACKCount, s.AppLastACK, s.AppWindow))
	}
}
func (f *raw443Flow) read(up bool, n int, err error) {
	now := time.Now()
	f.mu.Lock()
	if up {
		f.summary.AppReadCount++
		f.summary.AppReadBytes += int64(n)
		f.summary.AppLastReadAt = now.UnixMilli()
	} else {
		f.summary.UpstreamReadCount++
		f.summary.UpstreamReadBytes += int64(n)
		f.summary.UpstreamLastReadAt = now.UnixMilli()
	}
	if n > 0 {
		f.lastActivity = now
		f.stuckEpisode = false
	}
	if errors.Is(err, io.EOF) {
		if up {
			f.summary.ClientEOF = true
		} else {
			f.summary.UpstreamEOF = true
		}
	} else if err != nil {
		if up {
			f.summary.ClientReadError = err.Error()
		} else {
			f.summary.UpstreamReadError = err.Error()
		}
	}
	f.mu.Unlock()
	if errors.Is(err, io.EOF) {
		if up {
			f.clientEOFOnce.Do(func() { f.counts.clientEOF.Add(1) })
		} else {
			f.upstreamEOFOnce.Do(func() { f.counts.upstreamEOF.Add(1) })
		}
	} else if err != nil {
		f.readErrorOnce.Do(func() { f.counts.readError.Add(1) })
	}
}
func (f *raw443Flow) writeError(up bool, err error) {
	f.mu.Lock()
	if up {
		f.summary.UpstreamWriteError = err.Error()
	} else {
		f.summary.ClientWriteError = err.Error()
	}
	f.mu.Unlock()
	f.writeErrorOnce.Do(func() { f.counts.writeError.Add(1) })
}
func (f *raw443Flow) halfClose(up bool, status string) {
	f.mu.Lock()
	if up {
		f.summary.HalfCloseUpstream = status
	} else {
		f.summary.HalfCloseClient = status
	}
	f.mu.Unlock()
}
func (f *raw443Flow) finish(reason string) {
	f.begin()
	f.finishOnce.Do(func() {
		f.mu.Lock()
		if f.closeReason != "" {
			reason = f.closeReason
		}
		f.summary.EndTime = time.Now().UnixMilli()
		f.summary.CloseReason = reason
		f.summary.Stage = "finished"
		f.mu.Unlock()
		close(f.done)
		s := f.snapshot()
		f.counts.finished.Add(1)
		f.counts.mu.Lock()
		delete(f.counts.active, f.fid)
		// Bounded STATUS retention; every flow still gets its own END log.
		if len(f.counts.ended) >= 128 {
			raw443DetachPackets(f.counts.ended[0])
			f.counts.ended = f.counts.ended[1:]
		}
		// Retain observation for delayed gVisor packet output/ACKs after relay EOF.
		f.counts.ended = append(f.counts.ended, f)
		f.counts.mu.Unlock()
		if f.counts != raw443Current.Load() && f.counts != raw443Last.Load() {
			raw443DetachPackets(f)
		}
		f.progress("close")
		b, _ := json.Marshal(s)
		flowLog(fmt.Sprintf("TCP443_RAW_END id=%d sni=%q dst=%s durationMs=%d appBytes=%d upstreamBytes=%d reason=%s summary=%s", s.FlowID, s.SNI, s.Dst, s.DurationMs, s.AppBytes, s.UpstreamBytes, s.CloseReason, b))
	})
}

// Instrument actual ClientHello Read calls without changing adapter ownership.
type raw443PeekConn struct {
	net.Conn
	flow *raw443Flow
}

func (c raw443PeekConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.flow.read(true, n, err)
	return n, err
}
func (f *raw443Flow) log(reason, detail string) {
	flowLog(fmt.Sprintf("TCP443_RAW_FLOW id=%d sni=%q dst=%s reason=%s %s", f.fid, f.snapshot().SNI, f.dst, reason, detail))
}
func (f *raw443Flow) fail(reason, detail string) {
	if reason == "no_upstream_reply" {
		f.noReplyOnce.Do(func() { f.counts.noReply.Add(1) })
	}
	f.failOnce.Do(func() {
		f.counts.fail.Add(1)
		f.mu.Lock()
		f.closeReason = reason
		f.mu.Unlock()
		f.log(reason, detail)
	})
}
func (f *raw443Flow) sent(up bool, n int) {
	if n <= 0 {
		return
	}
	f.begin()
	f.mu.Lock()
	now := time.Now()
	f.lastActivity = now
	f.stuckEpisode = false
	var total int64
	var milestone *int
	if up {
		f.summary.AppBytes += int64(n)
		f.summary.UpstreamLastWriteAt = now.UnixMilli()
		total = f.summary.AppBytes
		milestone = &f.upMilestone
	} else {
		f.summary.UpstreamBytes += int64(n)
		f.summary.AppLastWriteAt = now.UnixMilli()
		total = f.summary.UpstreamBytes
		milestone = &f.downMilestone
	}
	report := false
	for *milestone < 4 && total >= []int64{1, 1024, 10240, 102400}[*milestone] {
		(*milestone)++
		report = true
	}
	f.mu.Unlock()
	if report {
		f.progress(fmt.Sprintf("bytes_direction_up_%t", up))
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
	f.begin()
	defer f.finish("raw_return")
	return raw443Run(client, prefix, f)
}
func raw443Run(client net.Conn, prefix []byte, f *raw443Flow) string {
	counts, dst := f.counts, f.dst
	f.stage("wg_dial")
	f.counts.attempt.Add(1)
	f.log("attempt", "stage=wg_dial")
	if !raw443Include.Load() || raw443Current.Load() != counts {
		f.fail("session_replaced", "stage=before_wg_dial")
		return "rawSessionReplaced"
	}
	tcp443AfterQuicDrop(f)
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
	f.stage("client_hello_write")
	if err := raw443Write(upstream, prefix, true, f); err != nil {
		f.fail("write_error", "stage=client_hello err="+err.Error())
		return "rawClientHelloFail"
	}
	relay443Raw(client, upstream, f)
	return "rawRelayDone"
}
func raw443Write(dst net.Conn, b []byte, up bool, f *raw443Flow) error {
	for len(b) > 0 {
		f.directionStage(up, "write_pending")
		n, err := dst.Write(b)
		if n > 0 {
			f.sent(up, n)
			b = b[n:]
		}
		if err != nil {
			f.writeError(up, err)
			return err
		}
		if n == 0 {
			f.writeError(up, io.ErrShortWrite)
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
		f.directionStage(up, "read_pending")
		n, err := src.Read(b)
		f.read(up, n, err)
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
					f.halfClose(up, "error:"+e.Error())
					f.writeError(up, e)
					return raw443Result{direction, "write_error", e}
				}
				f.halfClose(up, "ok")
			} else {
				f.halfClose(up, "unsupported")
				f.log(eof, "direction="+direction+" half_close=unsupported reverse_kept_open")
			}
			f.directionStage(up, eof)
			return raw443Result{direction, eof, nil}
		}
	}
}
func relay443Raw(client, upstream net.Conn, f *raw443Flow) {
	f.begin()
	f.stage("relay_read_or_write")
	defer f.finish("client_eof+upstream_eof")
	defer client.Close()
	defer upstream.Close()
	done := make(chan raw443Result, 2)
	go func() { done <- raw443Copy(upstream, client, true, f) }()
	go func() { done <- raw443Copy(client, upstream, false, f) }()
	for i := 0; i < 2; i++ {
		result := <-done
		f.progress(result.reason)
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

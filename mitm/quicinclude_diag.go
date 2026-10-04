package mitm

import (
	"configadblock/mitm/internal/quicfast"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// A captured session belongs to exactly one established TUN. No UID/foreground
// detection. Restrict this experiment to browser-only INCLUDE lists: a session
// containing YouTube (or another package) keeps its normal QUIC fast path.
type quicIncludeDropFlow struct {
	inspector quicfast.DiagnosticHello
	host      string
	last      time.Time
}
type quicIncludeDropSession struct {
	active                         atomic.Bool
	attempt, packets, bytes, flows atomic.Int64
	lastDrop, lastTCP              atomic.Int64
	mu                             sync.Mutex
	dropped                        map[string]*quicIncludeDropFlow
	lastByIP                       map[netip.Addr]time.Time
}

var quicIncludeCurrent atomic.Pointer[quicIncludeDropSession]

func SetQuicIncludeDiagnostic(mode, packages string) {
	s := &quicIncludeDropSession{dropped: make(map[string]*quicIncludeDropFlow), lastByIP: make(map[netip.Addr]time.Time)}
	apps := strings.Split(packages, ",")
	enabled := mode == "INCLUDE" && strings.TrimSpace(packages) != ""
	for _, app := range apps {
		app = strings.TrimSpace(app)
		if app != "com.android.chrome" && app != "com.google.android.googlequicksearchbox" {
			enabled = false
		}
	}
	s.active.Store(enabled)
	old := quicIncludeCurrent.Swap(s)
	if old != nil {
		old.active.Store(false)
	}
	flowLog(fmt.Sprintf("QUIC_INCLUDE_MODE mode=%s tunAppScope=%s apps=%s", QuicMode(), mode, packages))
}
func StopQuicIncludeDiagnostic() {
	if s := quicIncludeCurrent.Load(); s != nil {
		s.active.Store(false)
	} // preserve stats at STOP
}
func QuicMode() string {
	if s := quicIncludeCurrent.Load(); s != nil && s.active.Load() {
		return "DROP_INCLUDE_DIAG"
	}
	return "NORMAL"
}
func QuicIncludeDropStats() string {
	s := quicIncludeCurrent.Load()
	if s == nil {
		s = new(quicIncludeDropSession)
	}
	return fmt.Sprintf("QUIC_INCLUDE_DROP_ATTEMPT=%d QUIC_INCLUDE_DROP_PACKETS=%d QUIC_INCLUDE_DROP_BYTES=%d QUIC_INCLUDE_DROP_FLOWS=%d", s.attempt.Load(), s.packets.Load(), s.bytes.Load(), s.flows.Load())
}
func LastQuicDropAt() string {
	s := quicIncludeCurrent.Load()
	if s == nil {
		return "0"
	}
	return fmt.Sprint(s.lastDrop.Load())
}
func LastTcp443AfterQuicDropAt() string {
	s := quicIncludeCurrent.Load()
	if s == nil {
		return "0"
	}
	return fmt.Sprint(s.lastTCP.Load())
}

func (s *quicIncludeDropSession) outbound(b []byte) bool {
	if s == nil || !s.active.Load() {
		return false
	}
	client, dst, payload, ok := quicfast.DiagnosticUDP443(b)
	if !ok {
		return false
	}
	// Every UDP/443 attempt is silently consumed BEFORE raw WG or gVisor. No
	// ICMP response, socket, reservation or mapping; mapped_port=0 is literal.
	s.attempt.Add(1)
	s.packets.Add(1)
	s.bytes.Add(int64(len(b)))
	now := time.Now()
	s.lastDrop.Store(now.UnixMilli())
	key := client.String() + ">" + dst.String()
	s.mu.Lock()
	f := s.dropped[key]
	first := f == nil || now.Sub(f.last) > 2*time.Minute
	if first {
		s.flows.Add(1)
		if len(s.dropped) >= 512 {
			// Bounded diagnostic state; eviction never changes the DROP decision.
			var oldest string
			var at time.Time
			for k, v := range s.dropped {
				if at.IsZero() || v.last.Before(at) {
					oldest = k
					at = v.last
				}
			}
			delete(s.dropped, oldest)
		}
		f = &quicIncludeDropFlow{}
		s.dropped[key] = f
	}
	f.last = now
	host := f.inspector.Inspect(payload)
	if host == "" {
		host, _ = dnsIPMapGet(dst.Addr().String())
	}
	changed := host != "" && host != f.host
	if host != "" {
		f.host = host
	}
	if len(s.lastByIP) >= 512 {
		for ip, at := range s.lastByIP {
			if now.Sub(at) > 2*time.Minute {
				delete(s.lastByIP, ip)
			}
		}
		if len(s.lastByIP) >= 512 {
			for ip := range s.lastByIP {
				delete(s.lastByIP, ip)
				break
			}
		}
	}
	s.lastByIP[dst.Addr()] = now
	name := f.host
	if name == "" {
		name = "unknown"
	}
	s.mu.Unlock()
	if first || changed {
		flowLog(fmt.Sprintf("QUIC_INCLUDE_DROP dst=%s host=%q client=%s mapped_port=0 reason=force_tcp_fallback", dst, name, client))
	}
	return true
}
func tcp443AfterQuicDrop(f *raw443Flow) {
	s := quicIncludeCurrent.Load()
	if s == nil || !s.active.Load() {
		return
	}
	host, _, err := net.SplitHostPort(f.dst)
	if err != nil {
		return
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	now := time.Now()
	s.mu.Lock()
	last := s.lastByIP[ip]
	s.mu.Unlock()
	// A TCP fallback can choose a different IP from the QUIC attempt.
	// Distinguish destination matches from mere ordering in the same session.
	correlation := "destination_ip"
	if last.IsZero() {
		last = time.UnixMilli(s.lastDrop.Load())
		correlation = "include_session"
	}
	if s.lastDrop.Load() == 0 || now.Sub(last) > 2*time.Minute {
		return
	}
	s.lastTCP.Store(now.UnixMilli())
	flowLog(fmt.Sprintf("TCP443_AFTER_QUIC_DROP sni=%q dst=%s timeSinceLastQuicDropMs=%d correlation=%s", f.snapshot().SNI, f.dst, now.Sub(last).Milliseconds(), correlation))
}

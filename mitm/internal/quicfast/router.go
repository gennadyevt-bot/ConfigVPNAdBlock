package quicfast

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Reservation struct {
	Port  uint16
	Close func()
}
type Config struct {
	Reserve       func(bool) (Reservation, error)
	Send, Deliver func([]byte) error
	Blocked       func(string, string) bool
	Log           func(string)
}
type flowKey struct{ client, server netip.AddrPort }
type flow struct {
	key             flowKey
	hello           hello
	held            [][]byte
	binding         Reservation
	last            time.Time
	allowed, denied bool
}
type Router struct {
	cfg                                   Config
	mu                                    sync.Mutex
	flows, reverse                        map[flowKey]*flow
	ctx                                   context.Context
	cancel                                context.CancelFunc
	stop                                  sync.Once
	wg                                    sync.WaitGroup
	tx, rx                                chan []byte
	txN, rxN, dropN, queueDropN, ioErrors atomic.Uint64
}

func VideoHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, base := range []string{"youtube.com", "youtube-nocookie.com", "googlevideo.com", "ytimg.com", "ggpht.com", "youtubei.googleapis.com", "youtube.googleapis.com"} {
		if host == base || strings.HasSuffix(host, "."+base) {
			return true
		}
	}
	return false
}
func New(c Config) *Router {
	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{cfg: c, flows: make(map[flowKey]*flow), reverse: make(map[flowKey]*flow), ctx: ctx, cancel: cancel, tx: make(chan []byte, 256), rx: make(chan []byte, 256)}
	r.wg.Add(3)
	go r.pump(r.tx, c.Send, &r.txN, "TX")
	go r.pump(r.rx, c.Deliver, &r.rxN, "RX")
	go r.reap()
	return r
}
func (r *Router) log(s string) {
	if r.cfg.Log != nil {
		r.cfg.Log(s)
	}
}
func (r *Router) enqueue(q chan []byte, b []byte) {
	if r.ctx.Err() != nil {
		r.queueDropN.Add(1)
		return
	}
	select {
	case q <- b:
	default:
		r.queueDropN.Add(1)
	}
}
func (r *Router) pump(q chan []byte, write func([]byte) error, n *atomic.Uint64, direction string) {
	defer r.wg.Done()
	for {
		select {
		case <-r.ctx.Done():
			return
		case b := <-q:
			if r.ctx.Err() != nil {
				return
			}
			if err := write(b); err != nil {
				v := r.ioErrors.Add(1)
				if v == 1 || v%64 == 0 {
					r.log(fmt.Sprintf("QUIC_FAST_IO_ERROR direction=%s total=%d err=%v", direction, v, err))
				}
			} else {
				if n.Add(1) == 1 {
					r.log("QUIC_FAST_FIRST_PACKET direction=" + direction)
				}
			}
		}
	}
}

// Outbound consumes packets before application gVisor; queued bytes are owned.
func (r *Router) Outbound(b []byte) bool {
	p, ok := parse(b)
	if !ok || p.dst.Port() != 443 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		r.dropN.Add(1)
		return true
	}
	key := flowKey{p.src, p.dst}
	f := r.flows[key]
	if f == nil {
		if len(r.flows) >= 512 {
			r.dropN.Add(1)
			return true
		}
		f = &flow{key: key, last: time.Now()}
		r.flows[key] = f
	}
	f.last = time.Now()
	payload := p.data[p.off+8:]
	if f.denied {
		r.dropN.Add(1)
		return true
	}
	if f.allowed {
		// Handshake long headers use the server's CID: they must keep the same
		// mapping. Only a new/retransmitted client Initial is reclassified.
		if isInitial(payload) {
			host, pending := f.hello.inspect(payload)
			if pending {
				r.removeBinding(f)
				f.allowed = false
				f.held = append(f.held, append([]byte(nil), b...))
				return true
			}
			if host == "" || !VideoHost(host) || (r.cfg.Blocked != nil && r.cfg.Blocked(host, p.dst.Addr().String())) {
				r.removeBinding(f)
				f.allowed = false
				f.denied = true
				r.dropN.Add(1)
				r.log(fmt.Sprintf("QUIC_FAST_DENY_REUSED_FLOW dst=%s host=%q", p.dst, host))
				return true
			}
		}
		if f.allowed {
			r.enqueue(r.tx, rewrite(p, f.binding.Port, true))
			return true
		}
	}
	host, pending := f.hello.inspect(payload)
	if pending && len(f.held) < 8 {
		f.held = append(f.held, append([]byte(nil), b...))
		return true
	}
	if host == "" || !VideoHost(host) || (r.cfg.Blocked != nil && r.cfg.Blocked(host, p.dst.Addr().String())) {
		f.denied = true
		f.held = nil
		r.dropN.Add(1)
		r.log(fmt.Sprintf("QUIC_FAST_DENY dst=%s host=%q", p.dst, host))
		return true
	}
	binding, err := r.cfg.Reserve(p.v6)
	if err != nil {
		f.denied = true
		f.held = nil
		r.dropN.Add(1)
		r.log(fmt.Sprintf("QUIC_FAST_RESERVE_FAIL dst=%s err=%v", p.dst, err))
		return true
	}
	f.binding = binding
	f.allowed = true
	r.reverse[flowKey{netip.AddrPortFrom(p.src.Addr(), binding.Port), p.dst}] = f
	r.log(fmt.Sprintf("QUIC_FAST_OPEN dst=%s host=%s client=%s mapped_port=%d", p.dst, host, p.src, binding.Port))
	for _, saved := range f.held {
		sp, _ := parse(saved)
		r.enqueue(r.tx, rewrite(sp, binding.Port, true))
	}
	f.held = nil
	r.enqueue(r.tx, rewrite(p, binding.Port, true))
	return true
}

// The sole WG RX loop calls Inbound; bounded queues keep TUN backpressure
// from blocking TCP/DNS delivery. Matched packets never enter upstream gVisor.
func (r *Router) Inbound(b []byte) bool {
	p, ok := parse(b)
	if !ok || p.src.Port() != 443 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	f := r.reverse[flowKey{p.dst, p.src}]
	if f == nil {
		return false
	}
	f.last = time.Now()
	r.enqueue(r.rx, rewrite(p, f.key.client.Port(), false))
	return true
}
func (r *Router) removeBinding(f *flow) {
	if f.binding.Close != nil {
		delete(r.reverse, flowKey{netip.AddrPortFrom(f.key.client.Addr(), f.binding.Port), f.key.server})
		f.binding.Close()
		f.binding = Reservation{}
	}
}
func (r *Router) expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, f := range r.flows {
		ttl := 10 * time.Second
		if f.allowed {
			ttl = 2 * time.Minute
		}
		if now.Sub(f.last) > ttl {
			r.removeBinding(f)
			delete(r.flows, k)
		}
	}
}
func (r *Router) reap() {
	defer r.wg.Done()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case now := <-t.C:
			r.expire(now)
		}
	}
}

// Stop doesn't wait: owning TUN/WG FDs must close before joining blocked IO.
func (r *Router) Stop() {
	r.stop.Do(func() {
		r.cancel()
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, f := range r.flows {
			r.removeBinding(f)
		}
		clear(r.flows)
		clear(r.reverse)
	})
}
func (r *Router) Wait() { r.wg.Wait() }
func (r *Router) Stats() string {
	r.mu.Lock()
	n := len(r.reverse)
	r.mu.Unlock()
	return fmt.Sprintf("quicFastTx=%d quicFastRx=%d quicFastDenied=%d quicFastQueueDropped=%d quicFastIOErrors=%d quicFastActive=%d", r.txN.Load(), r.rxN.Load(), r.dropN.Load(), r.queueDropN.Load(), r.ioErrors.Load(), n)
}

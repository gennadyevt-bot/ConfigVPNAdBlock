package quicfast

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
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
	KnownHost     func(string) string
	Log           func(string)
}
type flowKey struct{ client, server netip.AddrPort }
type flow struct {
	key             flowKey
	hello           hello
	connectionID    []byte
	host            string
	source          string
	verdict         string
	verdictHost     string
	parseLogged     bool
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
	blockN, knownN, unknownN, parseFailN  atomic.Uint64
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
	freshConnection := false
	if cid := initialConnectionID(payload); len(cid) > 0 && !bytes.Equal(cid, f.connectionID) {
		// Port tuples can be reused after a blocked connection. Carry no stale SNI
		// verdict into a new Initial, including an unsupported QUIC version.
		f.connectionID = append([]byte(nil), cid...)
		f.hello = hello{}
		f.host = ""
		f.source = ""
		f.parseLogged = false
		f.denied = false
		freshConnection = true
	}
	// Classification answers only whether a hostname is blocked. Unknown,
	// unsupported and incomplete QUIC must use the same raw packet path.
	if freshConnection || (!f.allowed && !f.denied) || isInitial(payload) {
		previousCID := append([]byte(nil), f.hello.cid...)
		// Independently decode complete new ClientHellos even on reused tuples/CIDs;
		// otherwise merge authenticated fragments into this connection's assembler.
		candidate := hello{}
		host, pending := candidate.inspect(payload)
		if pending && len(candidate.cid) > 0 && bytes.Equal(candidate.cid, previousCID) {
			merged := f.hello
			mergedHost, mergedPending := merged.inspect(payload)
			if mergedHost != "" || mergedPending {
				f.hello = merged
				host, pending = mergedHost, mergedPending
			} else {
				// Authenticated CRYPTO bytes changed on a reused CID. Start a new
				// assembler instead of retaining an old SNI or rejecting the flow.
				f.hello = candidate
				f.host = ""
				f.source = ""
			}
		} else {
			f.hello = candidate
		}
		if len(f.hello.cid) > 0 && !bytes.Equal(f.hello.cid, previousCID) {
			f.host = ""
			f.source = ""
			f.parseLogged = false
		}
		if host != "" {
			f.host = host
			f.source = "sni"
		}
		if host == "" && !pending && !f.parseLogged {
			f.parseLogged = true
			r.parseFailN.Add(1)
			r.log(fmt.Sprintf("QUIC_FAST_PARSE_FAIL dst=%s client=%s fallback=raw_wg", p.dst, p.src))
		}
	}
	if f.source == "dns" {
		f.host = ""
		f.source = ""
	}
	if f.host == "" && r.cfg.KnownHost != nil {
		// Only fresh, unambiguous DNS associations may identify an unknown flow.
		// Authenticated SNI always takes precedence over shared CDN IP history.
		if host := r.cfg.KnownHost(p.dst.Addr().String()); host != "" {
			f.host = host
			f.source = "dns"
		}
	}
	if r.cfg.Blocked != nil && r.cfg.Blocked(f.host, p.dst.Addr().String()) {
		r.removeBinding(f)
		f.allowed = false
		f.denied = true
		r.dropN.Add(1)
		r.verdict(f, "QUIC_FAST_BLOCK")
		return true
	}
	f.denied = false
	if !f.allowed {
		binding, err := r.cfg.Reserve(p.v6)
		if err != nil {
			// Resource/I/O failures are not a blocklist decision or a permanent denial.
			r.dropN.Add(1)
			r.log(fmt.Sprintf("QUIC_FAST_RESERVE_FAIL dst=%s err=%v", p.dst, err))
			return true
		}
		f.binding = binding
		f.allowed = true
		r.reverse[flowKey{netip.AddrPortFrom(p.src.Addr(), binding.Port), p.dst}] = f
	}
	verdict := "QUIC_FAST_PASS_UNKNOWN"
	if f.host != "" {
		verdict = "QUIC_FAST_PASS_KNOWN"
	}
	r.verdict(f, verdict)
	r.enqueue(r.tx, rewrite(p, f.binding.Port, true))

	return true
}

// Log once per decision/hostname transition, not for every video packet.
func (r *Router) verdict(f *flow, verdict string) {
	if f.verdict == verdict && f.verdictHost == f.host {
		return
	}
	f.verdict = verdict
	f.verdictHost = f.host
	switch verdict {
	case "QUIC_FAST_BLOCK":
		r.blockN.Add(1)
	case "QUIC_FAST_PASS_KNOWN":
		r.knownN.Add(1)
	case "QUIC_FAST_PASS_UNKNOWN":
		r.unknownN.Add(1)
	}
	r.log(fmt.Sprintf("%s dst=%s host=%q source=%s client=%s mapped_port=%d", verdict, f.key.server, f.host, f.source, f.key.client, f.binding.Port))
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
	return fmt.Sprintf("QUIC_FAST_BLOCK=%d QUIC_FAST_PASS_KNOWN=%d QUIC_FAST_PASS_UNKNOWN=%d QUIC_FAST_PARSE_FAIL=%d quicFastTx=%d quicFastRx=%d quicFastDropped=%d quicFastQueueDropped=%d quicFastIOErrors=%d quicFastActive=%d", r.blockN.Load(), r.knownN.Load(), r.unknownN.Load(), r.parseFailN.Load(), r.txN.Load(), r.rxN.Load(), r.dropN.Load(), r.queueDropN.Load(), r.ioErrors.Load(), n)
}

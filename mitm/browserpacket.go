package mitm

// Browser traffic retains Android's TCP/DNS implementation. The filter observes
// IP packets; it never terminates TLS, dials another TCP connection or rewrites
// allowed packets. This avoids the two TCP stacks used by the content pipeline.
import (
	"configadblock/mitm/internal/quicfast"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type browserPacket struct {
	b        []byte
	off      int
	proto    byte
	src, dst netip.AddrPort
}

func parseBrowserPacket(b []byte) (p browserPacket, ok bool) {
	p.b = b
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		p.off = int(b[0]&15) * 4
		if p.off < 20 || p.off > len(b) || int(binary.BigEndian.Uint16(b[2:4])) != len(b) || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 {
			return p, false
		}
		p.proto = b[9]
		p.src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[12:16])), 0)
		p.dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[16:20])), 0)
	case len(b) >= 40 && b[0]>>4 == 6:
		if int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) {
			return p, false
		}
		p.off = 40
		p.proto = b[6]
		p.src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])), 0)
		p.dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[24:40])), 0)
	default:
		return p, false
	}
	minimum := 0
	if p.proto == 6 {
		minimum = 20
	} else if p.proto == 17 {
		minimum = 8
	} else {
		return p, false
	}
	if len(b) < p.off+minimum {
		return p, false
	}
	if p.proto == 6 {
		h := int(b[p.off+12]>>4) * 4
		if h < 20 || p.off+h > len(b) {
			return p, false
		}
	}
	if p.proto == 17 && int(binary.BigEndian.Uint16(b[p.off+4:])) != len(b)-p.off {
		return p, false
	}
	p.src = netip.AddrPortFrom(p.src.Addr(), binary.BigEndian.Uint16(b[p.off:]))
	p.dst = netip.AddrPortFrom(p.dst.Addr(), binary.BigEndian.Uint16(b[p.off+2:]))
	return p, true
}
func browserChecksum(b []byte) uint16 {
	var n uint32
	for len(b) > 1 {
		n += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		n += uint32(b[0]) << 8
	}
	for n>>16 != 0 {
		n = (n & 65535) + (n >> 16)
	}
	return ^uint16(n)
}
func browserTransportChecksum(p browserPacket) uint16 {
	t := p.b[p.off:]
	var h []byte
	if p.b[0]>>4 == 4 {
		h = append(h, p.b[12:20]...)
		h = append(h, 0, p.proto, byte(len(t)>>8), byte(len(t)))
	} else {
		h = append(h, p.b[8:40]...)
		h = append(h, 0, 0, byte(len(t)>>8), byte(len(t)), 0, 0, 0, p.proto)
	}
	return browserChecksum(append(h, t...))
}
func browserReply(p browserPacket, payload []byte) []byte {
	b := append([]byte(nil), p.b[:p.off]...)
	if b[0]>>4 == 4 {
		copy(b[12:16], p.b[16:20])
		copy(b[16:20], p.b[12:16])
	} else {
		copy(b[8:24], p.b[24:40])
		copy(b[24:40], p.b[8:24])
	}
	b = append(b, payload...)
	if b[0]>>4 == 4 {
		binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
		b[10] = 0
		b[11] = 0
		binary.BigEndian.PutUint16(b[10:12], browserChecksum(b[:p.off]))
	} else {
		binary.BigEndian.PutUint16(b[4:6], uint16(len(b)-40))
	}
	p.b = b
	checkoff := 16
	if p.proto == 17 {
		checkoff = 6
	}
	binary.BigEndian.PutUint16(b[p.off+checkoff:], 0)
	c := browserTransportChecksum(p)
	if c == 0 && p.proto == 17 {
		c = 65535
	}
	binary.BigEndian.PutUint16(b[p.off+checkoff:], c)
	return b
}
func browserDNSReply(p browserPacket, q []byte) []byte {
	answer := transportDNSError(q, 3)
	if answer == nil {
		return nil
	}
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u, p.dst.Port())
	binary.BigEndian.PutUint16(u[2:], p.src.Port())
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(answer)))
	return browserReply(p, append(u, answer...))
}
func browserReset(p browserPacket) []byte {
	t := p.b[p.off:]
	r := make([]byte, 20)
	binary.BigEndian.PutUint16(r, p.dst.Port())
	binary.BigEndian.PutUint16(r[2:], p.src.Port())
	r[12] = 5 << 4
	if t[13]&16 != 0 {
		copy(r[4:8], t[8:12])
		r[13] = 4
	} else {
		n := uint32(len(t) - int(t[12]>>4)*4)
		if t[13]&2 != 0 {
			n++
		}
		if t[13]&1 != 0 {
			n++
		}
		binary.BigEndian.PutUint32(r[8:], binary.BigEndian.Uint32(t[4:])+n)
		r[13] = 20
	}
	return browserReply(p, r)
}

type browserFlowKey struct {
	src, dst netip.AddrPort
	proto    byte
}
type browserPacketFlow struct {
	base          uint32
	syn           bool
	data, seen    []byte
	contiguous    int
	done, blocked bool
	last          time.Time
	quic          quicfast.DiagnosticHello
	host          string
}
type browserPacketFilter struct {
	flows    map[browserFlowKey]*browserPacketFlow
	blocked  func(string) bool
	log      func(string)
	deliver  func([]byte) error
	lastReap time.Time
}

func (f *browserPacketFilter) outbound(b []byte) bool {
	p, ok := parseBrowserPacket(b)
	if !ok {
		return false
	}
	if p.proto == 17 && p.dst.Port() == 53 {
		q := b[p.off+8:]
		host := dnsQueryDomain(q)
		if host != "" && f.blocked(host) {
			f.log("BROWSER_PACKET_DNS_BLOCK host=" + host)
			if r := browserDNSReply(p, q); r != nil {
				_ = f.deliver(r)
			}
			return true
		}
		return false
	}
	if p.dst.Port() != 443 {
		return false
	}
	now := time.Now()
	if f.flows == nil {
		f.flows = make(map[browserFlowKey]*browserPacketFlow)
	}
	if now.Sub(f.lastReap) > time.Minute {
		for k, s := range f.flows {
			if now.Sub(s.last) > 5*time.Minute {
				delete(f.flows, k)
			}
		}
		f.lastReap = now
	}
	key := browserFlowKey{p.src, p.dst, p.proto}
	s := f.flows[key]
	if s == nil {
		if len(f.flows) >= 512 {
			return false
		}
		s = &browserPacketFlow{}
		f.flows[key] = s
	}
	s.last = now
	if p.proto == 17 {
		_, _, payload, valid := quicfast.DiagnosticUDP443(b)
		if valid {
			host := s.quic.CurrentHost(payload)
			if host != s.host {
				s.host = host
				s.blocked = host != "" && f.blocked(host)
				f.log(fmt.Sprintf("BROWSER_PACKET_QUIC host=%q blocked=%t dst=%s", host, s.blocked, p.dst))
			}
		}
		return s.blocked
	}
	t := b[p.off:]
	seq := binary.BigEndian.Uint32(t[4:8])
	syn := t[13]&2 != 0
	if syn && (!s.syn || s.base != seq+1) {
		*s = browserPacketFlow{base: seq + 1, syn: true, last: now}
	}
	if s.blocked {
		if t[13]&4 == 0 {
			_ = f.deliver(browserReset(p))
		}
		return true
	}
	if s.done {
		return false
	}
	payload := t[int(t[12]>>4)*4:]
	if len(payload) == 0 {
		return false
	}
	if syn {
		seq++
	}
	// If attaching mid-connection, pass it unchanged instead of guessing a stream.
	if !s.syn {
		s.done = true
		return false
	}
	off := int(int32(seq - s.base))
	if off < 0 || off+len(payload) > 32768 {
		s.done = true
		s.data = nil
		s.seen = nil
		return false
	}
	if len(s.data) < off+len(payload) {
		s.data = append(s.data, make([]byte, off+len(payload)-len(s.data))...)
		s.seen = append(s.seen, make([]byte, off+len(payload)-len(s.seen))...)
	}
	for i, v := range payload {
		j := off + i
		if s.seen[j] != 0 && s.data[j] != v {
			s.done = true
			s.data = nil
			s.seen = nil
			return false
		}
		s.data[j] = v
		s.seen[j] = 1
	}
	for s.contiguous < len(s.seen) && s.seen[s.contiguous] != 0 {
		s.contiguous++
	}
	host, complete := browserClientHello(s.data[:s.contiguous])
	if complete {
		s.done = true
		s.host = host
		s.blocked = host != "" && f.blocked(host)
		s.data = nil
		s.seen = nil
		f.log(fmt.Sprintf("BROWSER_PACKET_TLS host=%q blocked=%t dst=%s", host, s.blocked, p.dst))
		if s.blocked {
			_ = f.deliver(browserReset(p))
			return true
		}
	}
	return false
}

// The payload-bearing segment that completes a blocked ClientHello is never
// forwarded. Earlier fragments cannot complete a server TLS handshake.
func browserClientHello(stream []byte) (string, bool) {
	var handshake []byte
	for len(stream) >= 5 {
		if stream[0] != 22 {
			return "", true
		}
		n := int(binary.BigEndian.Uint16(stream[3:5]))
		if n > 18432 {
			return "", true
		}
		if len(stream) < 5+n {
			return "", false
		}
		handshake = append(handshake, stream[5:5+n]...)
		stream = stream[5+n:]
		if len(handshake) < 4 {
			continue
		}
		h := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
		if handshake[0] != 1 || h > 65532 {
			return "", true
		}
		if len(handshake) < 4+h {
			continue
		}
		b := handshake[4 : 4+h]
		if len(b) < 35 {
			return "", true
		}
		off := 35 + int(b[34])
		if off+2 > len(b) {
			return "", true
		}
		off += 2 + int(binary.BigEndian.Uint16(b[off:]))
		if off >= len(b) {
			return "", true
		}
		off += 1 + int(b[off])
		if off+2 > len(b) {
			return "", true
		}
		end := off + 2 + int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		if end > len(b) {
			return "", true
		}
		for off+4 <= end {
			kind := binary.BigEndian.Uint16(b[off:])
			n := int(binary.BigEndian.Uint16(b[off+2:]))
			off += 4
			if off+n > end {
				return "", true
			}
			if kind == 0 && n >= 5 {
				e := b[off : off+n]
				l := int(binary.BigEndian.Uint16(e[3:]))
				if e[2] == 0 && 5+l <= len(e) {
					return string(e[5 : 5+l]), true
				}
			}
			off += n
		}
		return "", true
	}
	return "", false
}

type browserPacketSession struct {
	tun, up      *os.File
	wg           sync.WaitGroup
	once         sync.Once
	tx, rx, drop atomic.Uint64
	active       atomic.Bool
	filter       browserPacketFilter
	diagnostic   browserDiagnostic
}

var browserPackets atomic.Pointer[browserPacketSession]

func StartBrowserPacketTunnel(tunFD, upFD, mtu int64) error {
	StopBrowserPacketTunnel()
	for _, fd := range []int64{tunFD, upFD} {
		if err := unix.SetNonblock(int(fd), true); err != nil {
			unix.Close(int(tunFD))
			unix.Close(int(upFD))
			return err
		}
	}
	s := &browserPacketSession{tun: os.NewFile(uintptr(tunFD), "browser-tun"), up: os.NewFile(uintptr(upFD), "browser-wg")}
	s.active.Store(true)
	s.filter = browserPacketFilter{blocked: isBlocked, log: flowLog, deliver: func(b []byte) error {
		n, e := s.tun.Write(b)
		if e == nil && n != len(b) {
			e = io.ErrShortWrite
		}
		return e
	}}
	browserPackets.Store(s)
	s.wg.Add(2)
	go s.copyPackets(true)
	go s.copyPackets(false)
	flowLog(fmt.Sprintf("BROWSER_PACKET_NATIVE_READY mtu=%d TCP_DNS_ORIGINAL SNI_DNS_BLOCK_ON", mtu))
	return nil
}
func (s *browserPacketSession) close() {
	s.once.Do(func() { s.active.Store(false); s.tun.Close(); s.up.Close() })
}
func (s *browserPacketSession) copyPackets(outbound bool) {
	defer s.wg.Done()
	defer s.close()
	src, dst := s.up, s.tun
	if outbound {
		src, dst = s.tun, s.up
	}
	b := make([]byte, 65535)
	for {
		n, e := src.Read(b)
		if e != nil {
			if s.active.Load() {
				flowLog(fmt.Sprintf("BROWSER_PACKET_IO_END outbound=%t err=%v", outbound, e))
			}
			return
		}
		if n == 0 {
			return
		}
		if outbound {
			atomic.AddInt64(&tunRxPkts, 1)
			atomic.AddInt64(&tunRxBytes, int64(n))
			analyzeTunPkt(b[:n])
			blocked := s.filter.outbound(b[:n])
			s.diagnostic.observe(b[:n], true, blocked)
			if blocked {
				s.drop.Add(1)
				continue
			}
		}
		if !outbound {
			s.diagnostic.observe(b[:n], false, false)
		}
		w, e := dst.Write(b[:n])
		if e != nil || w != n {
			flowLog(fmt.Sprintf("BROWSER_PACKET_WRITE_END outbound=%t err=%v", outbound, e))
			return
		}
		if outbound {
			s.tx.Add(1)
		} else {
			s.rx.Add(1)
			atomic.AddInt64(&tunTxPkts, 1)
			atomic.AddInt64(&tunTxBytes, int64(n))
		}
	}
}
func StopBrowserPacketTunnel() {
	if s := browserPackets.Load(); s != nil {
		s.close()
		s.wg.Wait()
	}
}
func BrowserPacketStats() string {
	s := browserPackets.Load()
	if s == nil {
		return "browserPackets: none"
	}
	return fmt.Sprintf("browserPackets active=%t tx=%d rx=%d blockedPackets=%d", s.active.Load(), s.tx.Load(), s.rx.Load(), s.drop.Load()) + " flows=" + s.diagnostic.snapshot()
}

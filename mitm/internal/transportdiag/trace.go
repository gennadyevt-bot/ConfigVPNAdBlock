// Package transportdiag traces TCP handshakes without retaining packet payloads.
package transportdiag

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Key struct{ Local, Remote netip.AddrPort }
type Flow struct {
	ID               uint64
	Key              Key
	Started          time.Time
	stages           map[string]int64
	seq              uint32
	hasSeq           bool
	outerTX, outerRX uint64
}
type Trace struct {
	RXRunning, TXRunning                                                                        atomic.Int64
	ioError                                                                                     string
	failures                                                                                    []string
	mu                                                                                          sync.Mutex
	next                                                                                        uint64
	flows                                                                                       map[Key]*Flow
	TCPDialStarted, SynTx, SynAckRx, ConnectOK, ConnectTimeout, EndpointClosed, ActiveEndpoints atomic.Int64
	PacketRxDropped, PacketTxDropped                                                            atomic.Int64
	OuterTX, OuterRX, OuterTXErrors, OuterRXErrors                                              atomic.Uint64
	// alpha51: счётчики SYN на границе engine-TUN. SynTx (gVisor) vs
	// TunSynRx (движок прочитал из TUN) показывают потери между стеком и
	// движком; TunSynRtx — ретрансмиты SYN (gVisor не получил SYN-ACK);
	// TunSynAck — SYN-ACK реально дошёл до TUN от движка.
	TunSynRx, TunSynRtx, TunSynAck                                                              atomic.Int64
	synMu                                                                                       sync.Mutex
	synCount                                                                                    map[string]int
}

// SynIn: SYN (без ACK) уходит в движок. Возвращает номер попытки (1=первый).
func (t *Trace) SynIn(key string) int {
	t.TunSynRx.Add(1)
	t.synMu.Lock()
	defer t.synMu.Unlock()
	if t.synCount == nil {
		t.synCount = make(map[string]int, 512)
	}
	if len(t.synCount) > 4096 {
		t.synCount = make(map[string]int, 512)
	}
	t.synCount[key]++
	return t.synCount[key]
}

// SynAckTun: входящий SYN-ACK дошёл до TUN от движка (расшифрован).
func (t *Trace) SynAckTun(key string) {
	t.TunSynAck.Add(1)
	t.synMu.Lock()
	delete(t.synCount, key)
	t.synMu.Unlock()
}

// FlowLogf пишет строку в журнал приложения. Логгер задаётся хост-пакетом
// через SetFlowLogger (из mitm подключается flowLog -> adblock_journal).
var flowLogger atomic.Value // func(string)

func SetFlowLogger(f func(string)) { flowLogger.Store(f) }

func FlowLogf(format string, args ...any) {
	if v := flowLogger.Load(); v != nil {
		v.(func(string))(fmt.Sprintf(format, args...))
	}
}

func New() *Trace { return &Trace{flows: make(map[Key]*Flow)} }
func (t *Trace) Begin(k Key) *Flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	f := &Flow{ID: t.next, Key: k, Started: time.Now(), stages: map[string]int64{"DIAL_START": 0}, outerTX: t.OuterTX.Load(), outerRX: t.OuterRX.Load()}
	t.flows[k] = f
	return f
}
func (t *Trace) End(f *Flow, ok, timeout bool) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.flows, f.Key)
	if ok {
		t.ConnectOK.Add(1)
		return ""
	}
	if timeout {
		t.ConnectTimeout.Add(1)
	}
	var stages []string
	for _, s := range []string{"DIAL_START", "SYN_TX", "PACKET_SOCKET_TX", "PACKET_TO_WG", "PACKET_FROM_WG", "SYNACK_RX", "GVISOR_DELIVER"} {
		if ms, ok := f.stages[s]; ok {
			stages = append(stages, fmt.Sprintf("%s@%dms", s, ms))
		}
	}
	result := "CONNECT_ERROR"
	if timeout {
		result = "TIMEOUT"
	}
	line := fmt.Sprintf("result=%s dial=%d local=%s dst=%s stages=%s WG_OUTER_TX_delta=%d WG_OUTER_RX_delta=%d outer_scope=session_not_flow", result, f.ID, f.Key.Local, f.Key.Remote, strings.Join(stages, ","), t.OuterTX.Load()-f.outerTX, t.OuterRX.Load()-f.outerRX)
	t.failures = append(t.failures, line)
	if len(t.failures) > 8 {
		t.failures = t.failures[len(t.failures)-8:]
	}
	return line
}
func (t *Trace) Packet(stage string, p []byte, inbound bool) {
	k, seq, ack, flags, ok := parse(p, inbound)
	if !ok || flags&2 == 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	f := t.flows[k]
	if f == nil {
		return
	}
	if !inbound {
		if flags&0x12 != 2 {
			return
		}
		if !f.hasSeq {
			f.seq = seq
			f.hasSeq = true
		}
	} else {
		if flags&0x12 != 0x12 || !f.hasSeq || ack != f.seq+1 {
			return
		}
	}
	if _, seen := f.stages[stage]; !seen {
		f.stages[stage] = time.Since(f.Started).Milliseconds()
		if stage == "SYN_TX" {
			t.SynTx.Add(1)
		}
		if stage == "SYNACK_RX" {
			t.SynAckRx.Add(1)
		}
	}
}
func parse(p []byte, in bool) (Key, uint32, uint32, byte, bool) {
	var src, dst netip.Addr
	var o int
	if len(p) < 20 {
		return Key{}, 0, 0, 0, false
	}
	switch p[0] >> 4 {
	case 4:
		o = int(p[0]&15) * 4
		if o < 20 || p[9] != 6 || binary.BigEndian.Uint16(p[6:8])&0x3fff != 0 {
			return Key{}, 0, 0, 0, false
		}
		src = netip.AddrFrom4([4]byte(p[12:16]))
		dst = netip.AddrFrom4([4]byte(p[16:20]))
	case 6:
		if len(p) < 40 {
			return Key{}, 0, 0, 0, false
		}
		o = 40
		src = netip.AddrFrom16([16]byte(p[8:24]))
		dst = netip.AddrFrom16([16]byte(p[24:40]))
		next := p[6]
		for hops := 0; next != 6; hops++ {
			if hops >= 8 || len(p) < o+2 {
				return Key{}, 0, 0, 0, false
			}
			n := 0
			switch next {
			case 0, 43, 60:
				n = (int(p[o+1]) + 1) * 8
			case 44:
				if len(p) < o+8 || binary.BigEndian.Uint16(p[o+2:o+4])&0xfff9 != 0 {
					return Key{}, 0, 0, 0, false
				}
				n = 8
			case 51:
				n = (int(p[o+1]) + 2) * 4
			default:
				return Key{}, 0, 0, 0, false
			}
			if len(p) < o+n {
				return Key{}, 0, 0, 0, false
			}
			next = p[o]
			o += n
		}
	default:
		return Key{}, 0, 0, 0, false
	}
	if len(p) < o+20 {
		return Key{}, 0, 0, 0, false
	}
	k := Key{netip.AddrPortFrom(src, binary.BigEndian.Uint16(p[o:o+2])), netip.AddrPortFrom(dst, binary.BigEndian.Uint16(p[o+2:o+4]))}
	if in {
		k.Local, k.Remote = k.Remote, k.Local
	}
	return k, binary.BigEndian.Uint32(p[o+4 : o+8]), binary.BigEndian.Uint32(p[o+8 : o+12]), p[o+13], true
}
func (t *Trace) Stats() string {
	return fmt.Sprintf("tcpDialStarted=%d synTx=%d synAckRx=%d connectOk=%d connectTimeout=%d endpointClosed=%d activeEndpoints=%d packetRxDropped=%d packetTxDropped=%d WG_OUTER_TX=%d WG_OUTER_RX=%d outerTxErrors=%d outerRxErrors=%d tunSynRx=%d tunSynRtx=%d tunSynAck=%d", t.TCPDialStarted.Load(), t.SynTx.Load(), t.SynAckRx.Load(), t.ConnectOK.Load(), t.ConnectTimeout.Load(), t.EndpointClosed.Load(), t.ActiveEndpoints.Load(), t.PacketRxDropped.Load(), t.PacketTxDropped.Load(), t.OuterTX.Load(), t.OuterRX.Load(), t.OuterTXErrors.Load(), t.OuterRXErrors.Load(), t.TunSynRx.Load(), t.TunSynRtx.Load(), t.TunSynAck.Load())
}

func (t *Trace) Failures() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.failures, "\nWG_DIAL_FAIL ")
}

func (t *Trace) IOFailure(stage string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ioError = stage + ": " + err.Error()
}
func (t *Trace) IOStatus() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return fmt.Sprintf("rxLoop=%d txLoop=%d lastIOError=%q", t.RXRunning.Load(), t.TXRunning.Load(), t.ioError)
}

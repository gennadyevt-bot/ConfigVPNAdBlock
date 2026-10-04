package mitm

import (
	"configadblock/mitm/internal/quicfast"
	"configadblock/mitm/internal/transportdiag"
	"context"
	"errors"
	"os"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Owns the socket and both loops. Close must interrupt blocked I/O and Wait
// must finish before a replacement session is installed.
type wgLink struct {
	*channel.Endpoint
	f               *os.File
	counts          *wgPacketCounter
	trace           *transportdiag.Trace
	once, closeOnce sync.Once
	wg              sync.WaitGroup
	cancel          context.CancelFunc
	rawMu           sync.RWMutex
	raw             *quicfast.Router
}

func newWgLink(f *os.File, mtu uint32, c *wgPacketCounter, d *transportdiag.Trace) *wgLink {
	return &wgLink{Endpoint: channel.New(1024, mtu, ""), f: f, counts: c, trace: d}
}
func (e *wgLink) Attach(d stack.NetworkDispatcher) {
	e.Endpoint.Attach(d)
	if d == nil {
		return
	}
	e.once.Do(func() {
		ctx, cancel := context.WithCancel(context.Background())
		e.cancel = cancel
		e.wg.Add(2)
		go e.rx()
		go e.tx(ctx)
	})
}
func (e *wgLink) WritePackets(ps stack.PacketBufferList) (int, tcpip.Error) {
	for _, p := range ps.AsSlice() {
		b := p.ToBuffer()
		e.trace.Packet("SYN_TX", b.Flatten(), false)
		b.Release()
	}
	n, err := e.Endpoint.WritePackets(ps)
	if n < ps.Len() {
		e.trace.PacketTxDropped.Add(int64(ps.Len() - n))
	}
	return n, err
}
func (e *wgLink) rx() {
	e.trace.RXRunning.Add(1)
	defer e.trace.RXRunning.Add(-1)
	defer e.wg.Done()
	defer e.cancel()
	scratch := make([]byte, 65535)
	for {
		// Read a whole IP packet even if a peer violates the configured MTU.
		// A short SOCK_SEQPACKET read discards the remainder irreversibly.
		n, err := e.f.Read(scratch)
		if err != nil {
			if !errors.Is(err, os.ErrClosed) {
				e.trace.IOFailure("PACKET_SOCKET_RX", err)
			}
			return
		}
		if n == 0 {
			return
		}
		e.counts.rx.Add(1)
		e.rawMu.RLock()
		raw := e.raw
		e.rawMu.RUnlock()
		if raw != nil && raw.Inbound(scratch[:n]) {
			continue
		}
		data := append([]byte(nil), scratch[:n]...)
		var proto tcpip.NetworkProtocolNumber
		switch header.IPVersion(data) {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			e.trace.PacketRxDropped.Add(1)
			continue
		}
		if !e.IsAttached() {
			e.trace.PacketRxDropped.Add(1)
			continue
		}
		e.trace.Packet("SYNACK_RX", data, true)
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
		e.InjectInbound(proto, p)
		e.trace.Packet("GVISOR_DELIVER", data, true)
		p.DecRef()
	}
}
func (e *wgLink) tx(ctx context.Context) {
	e.trace.TXRunning.Add(1)
	defer e.trace.TXRunning.Add(-1)
	defer e.wg.Done()
	for {
		p := e.ReadContext(ctx)
		if p == nil {
			return
		}
		b := p.ToBuffer()
		data := b.Flatten()
		n, err := e.f.Write(data)
		if err != nil || n != len(data) {
			if err != nil && !errors.Is(err, os.ErrClosed) {
				e.trace.IOFailure("PACKET_SOCKET_TX", err)
			}
			e.trace.PacketTxDropped.Add(1)
		} else {
			e.counts.tx.Add(1)
			e.trace.Packet("PACKET_SOCKET_TX", data, false)
		}
		b.Release()
		p.DecRef()
		if err != nil {
			return
		}
	}
}
func (e *wgLink) Close() {
	e.closeOnce.Do(func() {
		if e.cancel != nil {
			e.cancel()
		}
		e.rawMu.RLock()
		raw := e.raw
		e.rawMu.RUnlock()
		if raw != nil {
			raw.Stop()
		}
		e.f.Close()
		e.Endpoint.Close()
	})
}
func (e *wgLink) Wait() {
	e.wg.Wait()
	e.rawMu.RLock()
	raw := e.raw
	e.rawMu.RUnlock()
	if raw != nil {
		raw.Wait()
	}
}

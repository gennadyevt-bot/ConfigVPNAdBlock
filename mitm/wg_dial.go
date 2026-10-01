package mitm

import (
	"configadblock/mitm/internal/transportdiag"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type trackedTCPConn struct {
	*gonet.TCPConn
	once   sync.Once
	closed func()
}

func (c *trackedTCPConn) Close() error {
	var err error
	c.once.Do(func() { err = c.TCPConn.Close(); c.closed() })
	return err
}

// Own the endpoint immediately. gonet.DialTCPWithBind in our pinned gVisor
// returns on an already-cancelled context (or Bind error) without closing it.
func dialTrackedTCP(ctx context.Context, u *wgUpstreamStack, remote tcpip.FullAddress, protocol tcpip.NetworkProtocolNumber) (net.Conn, error) {
	d := u.trace
	d.TCPDialStarted.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var q waiter.Queue
	ep, e := u.st.NewEndpoint(tcp.ProtocolNumber, protocol, &q)
	if e != nil {
		return nil, fmt.Errorf("endpoint: %s", e)
	}
	d.ActiveEndpoints.Add(1)
	closeCount := func() { d.EndpointClosed.Add(1); d.ActiveEndpoints.Add(-1) }
	owned := true
	defer func() {
		if owned {
			ep.Close()
			closeCount()
		}
	}()
	entry, ch := waiter.NewChannelEntry(waiter.WritableEvents)
	q.EventRegister(&entry)
	defer q.EventUnregister(&entry)
	localIP, err := netip.ParseAddr(u.local)
	if err != nil {
		return nil, err
	}
	if e := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(localIP.AsSlice())}); e != nil {
		return nil, fmt.Errorf("bind: %s", e)
	}
	local, e := ep.GetLocalAddress()
	if e != nil {
		return nil, fmt.Errorf("local address: %s", e)
	}
	remoteIP, ok := netip.AddrFromSlice(remote.Addr.AsSlice())
	if !ok {
		return nil, fmt.Errorf("invalid remote IP")
	}
	f := d.Begin(transportdiag.Key{Local: netip.AddrPortFrom(localIP, local.Port), Remote: netip.AddrPortFrom(remoteIP, remote.Port)})
	var dialErr error
	e = ep.Connect(remote)
	if _, pending := e.(*tcpip.ErrConnectStarted); pending {
		select {
		case <-ctx.Done():
			dialErr = ctx.Err()
		case <-ch:
			e = ep.LastError()
		}
	}
	if dialErr == nil && e != nil {
		dialErr = fmt.Errorf("connect: %s", e)
	}
	if dialErr != nil {
		// Release the endpoint/port before reporting a timeout or starting a retry.
		ep.Close()
		closeCount()
		owned = false
		detail := d.End(f, false, errors.Is(dialErr, context.DeadlineExceeded))
		flowLog("WG_DIAL_FAIL " + detail + " result=" + dialErr.Error())
		return nil, dialErr
	}
	d.End(f, true, false)
	owned = false
	return &trackedTCPConn{TCPConn: gonet.NewTCPConn(&q, ep), closed: closeCount}, nil
}

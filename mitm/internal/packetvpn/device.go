// Package packetvpn connects the VPN engine to a packet socket, not a kernel TUN.
package packetvpn

import (
	"configadblock/mitm/internal/transportdiag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun"
)

type packetTun struct {
	file   *os.File
	mtu    int
	events chan tun.Event
	once   sync.Once
	trace  *transportdiag.Trace
}

func newPacketTun(fd, mtu int) (*packetTun, error) {
	// fd ДОЛЖЕН быть nonblocking: amneziawg-go device.Close() join-ит
	// RoutineReadFromTUN, а close() не будит read(), заблокированный на
	// blocking fd -> deadlock при остановке. EAGAIN в этой версии
	// amneziawg-go НЕ фатален (регрессионный тест это фиксирует).
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &packetTun{file: os.NewFile(uintptr(fd), "vpn-packets"), mtu: mtu, events: make(chan tun.Event)}, nil
}
func (t *packetTun) File() *os.File           { return t.file }
func (t *packetTun) Name() (string, error)    { return "adblock-upstream", nil }
func (t *packetTun) MTU() (int, error)        { return t.mtu, nil }
func (t *packetTun) Events() <-chan tun.Event { return t.events }
func (t *packetTun) BatchSize() int           { return 1 }
func (t *packetTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := t.file.Read(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	if t.trace != nil {
		t.trace.Packet("PACKET_TO_WG", bufs[0][offset:offset+n], false)
	}
	sizes[0] = n
	return 1, nil
}
func (t *packetTun) Write(bufs [][]byte, offset int) (int, error) {
	for i, b := range bufs {
		if t.trace != nil {
			t.trace.Packet("PACKET_FROM_WG", b[offset:], true)
		}
		n, err := t.file.Write(b[offset:])
		if err != nil {
			if t.trace != nil {
				t.trace.PacketRxDropped.Add(int64(len(bufs) - i))
			}
			return i, err
		}
		if n != len(b)-offset {
			return i, io.ErrShortWrite
		}
	}
	return len(bufs), nil
}
func (t *packetTun) Close() error {
	var err error
	t.once.Do(func() { err = t.file.Close(); close(t.events) })
	return err
}

// Protect each newly opened UDP socket before the engine can send packets.
// This also covers sockets reopened by the engine after a network change.
type protectedBind struct {
	conn.Bind
	protect  func(int) bool
	logError func(string, ...any)
	trace    *transportdiag.Trace
}

// wgSocketBuf — буферы UDP-сокета WG (4 MiB на направление). Дефолтных
// ~212KB не хватает при всплесках: страница открывает десятки соединений
// разом -> переполнение -> дроп пакетов, включая SYN -> флап handshake
// ("то заходит, то нет"). Ядро при необходимости ужимает до rmem_max.
const wgSocketBuf = 4 << 20

func (b *protectedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actual, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	peek, ok := b.Bind.(conn.PeekLookAtSocketFd)
	if !ok {
		b.Bind.Close()
		return nil, 0, fmt.Errorf("VPN bind has no socket access")
	}
	count := 0
	for _, get := range []func() (int, error){peek.PeekLookAtSocketFd4, peek.PeekLookAtSocketFd6} {
		fd, e := socketFD(get)
		if e != nil || fd < 0 {
			continue
		}
		if !b.protect(fd) {
			b.Bind.Close()
			return nil, 0, fmt.Errorf("VPN socket protection rejected")
		}
		// alpha49: увеличиваем буферы UDP-сокета WG против дропа SYN
		// при всплесках одновременных соединений.
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, wgSocketBuf); err != nil && b.logError != nil {
			b.logError("WG SO_RCVBUF: %v", err)
		}
		if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, wgSocketBuf); err != nil && b.logError != nil {
			b.logError("WG SO_SNDBUF: %v", err)
		}
		count++
	}
	if b.logError != nil {
		b.logError("WG socket buffers requested on %d socket(s)", count)
	}
	if count == 0 {
		b.Bind.Close()
		return nil, 0, fmt.Errorf("VPN bind opened no sockets")
	}
	if b.trace != nil {
		for i, fn := range fns {
			fns[i] = func(p [][]byte, s []int, e []conn.Endpoint) (int, error) {
				n, err := fn(p, s, e)
				for j := 0; j < n; j++ {
					if s[j] > 0 {
						b.trace.OuterRX.Add(1)
					}
				}
				if err != nil {
					b.trace.OuterRXErrors.Add(1)
				}
				return n, err
			}
		}
	}
	return fns, actual, nil
}

func (b *protectedBind) Send(p [][]byte, ep conn.Endpoint) error {
	err := b.Bind.Send(p, ep)
	if b.trace != nil {
		if err == nil {
			b.trace.OuterTX.Add(uint64(len(p)))
		} else {
			b.trace.OuterTXErrors.Add(1)
		}
	}
	return err
}

// The Android upstream accessor dereferences a nil UDPConn when an address
// family is unavailable. Treat that family as absent, while still requiring
// successful protection of every socket that exists.
func socketFD(get func() (int, error)) (fd int, err error) {
	defer func() {
		if recover() != nil {
			fd = -1
			err = fmt.Errorf("socket family unavailable")
		}
	}()
	return get()
}

// Start takes ownership of fd, including on failure. settings is the userspace
// API format for WG or AWG. No kernel TUN ioctls are issued on the packet socket.
func Start(fd, mtu int, settings string, protect func(int) bool, logError func(string, ...any)) (*device.Device, error) {
	return StartTraced(fd, mtu, settings, protect, logError, nil)
}

func StartTraced(fd, mtu int, settings string, protect func(int) bool, logError func(string, ...any), trace *transportdiag.Trace) (*device.Device, error) {
	t, err := newPacketTun(fd, mtu)
	if err != nil {
		return nil, fmt.Errorf("packet socket: %w", err)
	}
	t.trace = trace
	bind := &protectedBind{Bind: conn.NewStdNetBind(), protect: protect, logError: logError, trace: trace}
	d := device.NewDevice(t, bind, &device.Logger{Verbosef: func(string, ...any) {}, Errorf: logError}, false, func(device.StatusCode) {})
	if err = d.IpcSet(settings); err != nil {
		d.Close()
		return nil, fmt.Errorf("VPN configuration rejected")
	}
	d.DisableSomeRoamingForBrokenMobileSemantics()
	if err = d.Up(); err != nil {
		d.Close()
		return nil, fmt.Errorf("VPN start: %w", err)
	}
	return d, nil
}

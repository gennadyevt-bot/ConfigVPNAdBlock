package mitm

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The two ends of socketpair are independent open-file descriptions.
// Set nonblocking on the upstream side without changing the engine side.
func TestWgUpstreamDoesNotAffectEngineFd(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	if err := startWgUpstream(int64(fds[0]), 1280, "10.99.0.2", ""); err != nil {
		t.Fatal(err)
	}
	defer stopWgUpstream()
	flags, err := unix.FcntlInt(uintptr(fds[1]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NONBLOCK != 0 {
		t.Fatal("engine end changed")
	}
	flags, err = unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatal("upstream cannot interrupt blocked I/O")
	}
}

func TestWgDialHonorsDeadlineWithSilentPeer(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	if err := startWgUpstream(int64(fds[0]), 1280, "10.99.0.2", ""); err != nil {
		t.Fatal(err)
	}
	defer stopWgUpstream()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	c, err := wgDialTCPContext(ctx, "10.99.0.1:443")
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("silent peer unexpectedly connected")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("dial failed before deadline: %v", err)
	}
	if time.Since(started) > time.Second {
		t.Fatalf("deadline not honored: %v", time.Since(started))
	}
	if wgUpstream.counts.tx.Load() == 0 {
		t.Fatal("no SYN reached VPN socket")
	}
}

func TestUpstreamStopInterruptsIdleRead(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	if err := startWgUpstream(int64(fds[0]), 1280, "10.99.0.2", ""); err != nil {
		t.Fatal(err)
	}
	link := wgUpstream.link
	done := make(chan struct{})
	go func() { stopWgUpstream(); link.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle RX survived shutdown")
	}
}

func TestFailedDialsReleaseEndpoints(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	if err := startWgUpstream(int64(fds[0]), 1280, "10.99.0.2", ""); err != nil {
		t.Fatal(err)
	}
	defer stopWgUpstream()
	for i := 0; i < 32; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		c, e := wgDialTCPContext(ctx, "10.99.0.1:443")
		cancel()
		if c != nil || e == nil {
			t.Fatalf("silent peer result: %v %v", c, e)
		}
	}
	d := wgUpstream.trace
	if d.ActiveEndpoints.Load() != 0 || d.EndpointClosed.Load() != 32 || d.ConnectTimeout.Load() != 32 {
		t.Fatal(d.Stats())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _ = wgDialTCPContext(ctx, "10.99.0.1:443")
	if d.ActiveEndpoints.Load() != 0 || d.EndpointClosed.Load() != 32 {
		t.Fatal("cancelled dial allocated endpoint: ", d.Stats())
	}
	if len(wgUpstream.st.RegisteredEndpoints()) != 0 {
		t.Fatal("failed endpoints still registered")
	}
}

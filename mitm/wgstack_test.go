package mitm

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Регрессия: startWgUpstream на dup(socketpair fd) НЕ должен переводить
// исходный endpoint в O_NONBLOCK — dup разделяет file-status flags,
// а nonblocking со стороны wireguard-go фатален (EAGAIN -> device.Close()).
func TestWgUpstreamDoesNotAffectOriginalFd(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	dupFd, err := unix.Dup(fds[0])
	if err != nil {
		t.Fatal(err)
	}
	flagsBefore, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := startWgUpstream(int64(dupFd), 1500, "10.99.0.2", ""); err != nil {
		t.Fatal(err)
	}
	flagsAfter, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	stopWgUpstream()
	if flagsBefore&unix.O_NONBLOCK != flagsAfter&unix.O_NONBLOCK {
		t.Fatalf("O_NONBLOCK changed on original endpoint: before=%x after=%x", flagsBefore, flagsAfter)
	}
}

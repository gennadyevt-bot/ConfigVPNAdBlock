package quicfast

import (
	"bytes"
	"net/netip"
)

// DiagnosticUDP443 and DiagnosticHello are passive helpers. They allocate no
// ports, enqueue no packets and do not change the normal Router's decisions.
func DiagnosticUDP443(b []byte) (client, dst netip.AddrPort, payload []byte, ok bool) {
	p, valid := parse(b)
	if !valid || p.dst.Port() != 443 {
		return
	}
	return p.src, p.dst, p.data[p.off+8:], true
}

type DiagnosticHello struct {
	h   hello
	cid []byte
}

func (d *DiagnosticHello) Inspect(payload []byte) string {
	if cid := initialConnectionID(payload); len(cid) > 0 && !bytes.Equal(cid, d.cid) {
		d.h = hello{}
		d.cid = append(d.cid[:0], cid...)
	}
	host, _ := d.h.inspect(payload)
	return host
}

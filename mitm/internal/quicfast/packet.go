// Package quicfast routes selected QUIC IP packets without a UDP socket relay.
package quicfast

import (
	"encoding/binary"
	"net/netip"
)

type packet struct {
	data     []byte
	off      int
	src, dst netip.AddrPort
	v6       bool
}

func parse(b []byte) (p packet, ok bool) {
	if len(b) < 28 {
		return
	}
	p.data = b
	switch b[0] >> 4 {
	case 4:
		p.off = int(b[0]&15) * 4
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if p.off < 20 || n != len(b) || p.off+8 > n || b[9] != 17 || binary.BigEndian.Uint16(b[6:8])&0x3fff != 0 || checksum(b[:p.off]) != 0 {
			return p, false
		}
		p.src = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[12:16])), binary.BigEndian.Uint16(b[p.off:]))
		p.dst = netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[16:20])), binary.BigEndian.Uint16(b[p.off+2:]))
	case 6:
		if len(b) < 48 || int(binary.BigEndian.Uint16(b[4:6]))+40 != len(b) || b[6] != 17 {
			return p, false
		}
		p.off = 40
		p.v6 = true
		p.src = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[8:24])), binary.BigEndian.Uint16(b[40:]))
		p.dst = netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[24:40])), binary.BigEndian.Uint16(b[42:]))
	default:
		return p, false
	}
	u := b[p.off:]
	if int(binary.BigEndian.Uint16(u[4:6])) != len(u) || len(u) < 8 {
		return p, false
	}
	if binary.BigEndian.Uint16(u[6:8]) == 0 {
		if p.v6 {
			return p, false
		}
	} else if udpChecksum(p) != 0 {
		return p, false
	}
	return p, true
}
func checksum(b []byte) uint16 {
	var s uint32
	for len(b) > 1 {
		s += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		s += uint32(b[0]) << 8
	}
	for s>>16 != 0 {
		s = (s & 65535) + (s >> 16)
	}
	return ^uint16(s)
}
func udpChecksum(p packet) uint16 {
	u := p.data[p.off:]
	h := make([]byte, 0, 40+len(u))
	if p.v6 {
		h = append(h, p.data[8:40]...)
		h = append(h, 0, 0, byte(len(u)>>8), byte(len(u)), 0, 0, 0, 17)
	} else {
		h = append(h, p.data[12:20]...)
		h = append(h, 0, 17, byte(len(u)>>8), byte(len(u)))
	}
	return checksum(append(h, u...))
}
func rewrite(p packet, port uint16, source bool) []byte {
	b := append([]byte(nil), p.data...)
	o := p.off
	if !source {
		o += 2
	}
	binary.BigEndian.PutUint16(b[o:], port)
	binary.BigEndian.PutUint16(b[p.off+6:], 0)
	p.data = b
	c := udpChecksum(p)
	if c == 0 {
		c = 65535
	}
	binary.BigEndian.PutUint16(b[p.off+6:], c)
	return b
}

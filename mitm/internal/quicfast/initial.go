package quicfast

// Only public Initial keys are used to classify ClientHello SNI. No application
// data is decrypted. RFC 9001 sections 5.2/5.4 and RFC 9369 sections 3.1/3.3.
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"golang.org/x/crypto/hkdf"
	"io"
	"strings"
)

type hello struct {
	cid        []byte
	data, seen [16384]byte
	maxPN      uint64
}

func label(secret []byte, name string, n int) []byte {
	name = "tls13 " + name
	info := []byte{byte(n >> 8), byte(n), byte(len(name))}
	info = append(info, []byte(name)...)
	info = append(info, 0)
	out := make([]byte, n)
	_, _ = io.ReadFull(hkdf.Expand(sha256.New, secret, info), out)
	return out
}
func varint(b []byte, off *int) (uint64, bool) {
	if *off >= len(b) {
		return 0, false
	}
	n := 1 << uint(b[*off]>>6)
	if len(b)-*off < n {
		return 0, false
	}
	v := uint64(b[*off] & 63)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[*off+i])
	}
	*off += n
	return v, true
}

func isInitial(b []byte) bool {
	if len(b) < 7 || b[0]&0xc0 != 0xc0 {
		return false
	}
	v := binary.BigEndian.Uint32(b[1:5])
	t := (b[0] >> 4) & 3
	return (v == 1 && t == 0) || (v == 0x6b3343cf && t == 1)
}

// inspect returns a complete SNI, or pending=true for authenticated fragments.
func (h *hello) inspect(datagram []byte) (host string, pending bool) {
	for len(datagram) > 0 {
		b := datagram
		if len(b) < 7 || b[0]&0xc0 != 0xc0 {
			return host, pending
		}
		version := binary.BigEndian.Uint32(b[1:5])
		prefix := "quic"
		salt := []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}
		if version == 0x6b3343cf {
			prefix = "quicv2"
			salt = []byte{0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9}
			if (b[0]>>4)&3 != 1 {
				return host, pending
			}
		} else if version != 1 || (b[0]>>4)&3 != 0 {
			return host, pending
		}
		dl := int(b[5])
		if dl == 0 || dl > 20 || 6+dl >= len(b) {
			return host, false
		}
		cid := b[6 : 6+dl]
		off := 6 + dl
		sl := int(b[off])
		off++
		if sl > 20 || off+sl > len(b) {
			return host, false
		}
		off += sl
		token, ok := varint(b, &off)
		if !ok || token > uint64(len(b)-off) {
			return host, false
		}
		off += int(token)
		length, ok := varint(b, &off)
		if !ok || length > uint64(len(b)-off) || length < 20 {
			return host, false
		}
		end := off + int(length)
		datagram = datagram[end:]
		b = append([]byte(nil), b[:end]...)
		secret := label(hkdf.Extract(sha256.New, cid, salt), "client in", 32)
		hp, _ := aes.NewCipher(label(secret, prefix+" hp", 16))
		if off+20 > len(b) {
			return host, false
		}
		var mask [16]byte
		hp.Encrypt(mask[:], b[off+4:off+20])
		b[0] ^= mask[0] & 15
		pnLen := int(b[0]&3) + 1
		var truncated uint64
		for i := 0; i < pnLen; i++ {
			b[off+i] ^= mask[i+1]
			truncated = truncated<<8 | uint64(b[off+i])
		}
		expected := h.maxPN + 1
		if !bytes.Equal(h.cid, cid) {
			expected = 0
		}
		window := uint64(1) << uint(pnLen*8)
		pn := (expected &^ (window - 1)) | truncated
		if pn+window/2 <= expected && pn+window < (uint64(1)<<62) {
			pn += window
		} else if pn > expected+window/2 && pn >= window {
			pn -= window
		}
		key, _ := aes.NewCipher(label(secret, prefix+" key", 16))
		aead, _ := cipher.NewGCM(key)
		iv := label(secret, prefix+" iv", 12)
		for i := 0; i < 8; i++ {
			iv[11-i] ^= byte(pn >> uint(i*8))
		}
		plain, err := aead.Open(nil, iv, b[off+pnLen:], b[:off+pnLen])
		if err != nil {
			return host, false
		}
		if !bytes.Equal(h.cid, cid) {
			*h = hello{cid: append([]byte(nil), cid...)}
		}
		if pn > h.maxPN {
			h.maxPN = pn
		}
		if !h.frames(plain) {
			return host, false
		}
		pending = true
		if h.seen[0] != 0 && h.seen[1] != 0 && h.seen[2] != 0 && h.seen[3] != 0 {
			n := 4 + (int(h.data[1]) << 16) + (int(h.data[2]) << 8) + int(h.data[3])
			if h.data[0] != 1 || n > len(h.data) {
				return "", false
			}
			complete := true
			for i := 0; i < n; i++ {
				if h.seen[i] == 0 {
					complete = false
					break
				}
			}
			if complete {
				return helloSNI(h.data[:n]), false
			}
		}
	}
	return host, pending
}
func (h *hello) frames(b []byte) bool {
	for o := 0; o < len(b); {
		t, ok := varint(b, &o)
		if !ok {
			return false
		}
		switch t {
		case 0, 1: // PADDING, PING
		case 2, 3: // ACK / ACK_ECN
			_, a := varint(b, &o)
			_, c := varint(b, &o)
			ranges, d := varint(b, &o)
			_, e := varint(b, &o)
			if !a || !c || !d || !e || ranges > 256 {
				return false
			}
			for i := uint64(0); i < ranges; i++ {
				_, a = varint(b, &o)
				_, c = varint(b, &o)
				if !a || !c {
					return false
				}
			}
			if t == 3 {
				for i := 0; i < 3; i++ {
					if _, ok := varint(b, &o); !ok {
						return false
					}
				}
			}
		case 6:
			at, a := varint(b, &o)
			n, c := varint(b, &o)
			if !a || !c || at > uint64(len(h.data)) || n > uint64(len(h.data))-at || n > uint64(len(b)-o) {
				return false
			}
			for i := uint64(0); i < n; i++ {
				v := b[o+int(i)]
				j := at + i
				if h.seen[j] != 0 && h.data[j] != v {
					return false
				}
				h.data[j] = v
				h.seen[j] = 1
			}
			o += int(n)
		default:
			return false
		}
	}
	return true
}
func helloSNI(b []byte) string {
	o := 38
	if len(b) <= o {
		return ""
	}
	o += 1 + int(b[o])
	if o+2 > len(b) {
		return ""
	}
	o += 2 + int(binary.BigEndian.Uint16(b[o:]))
	if o >= len(b) {
		return ""
	}
	o += 1 + int(b[o])
	if o+2 > len(b) {
		return ""
	}
	end := o + 2 + int(binary.BigEndian.Uint16(b[o:]))
	o += 2
	if end > len(b) {
		return ""
	}
	for o+4 <= end {
		t := binary.BigEndian.Uint16(b[o:])
		n := int(binary.BigEndian.Uint16(b[o+2:]))
		o += 4
		if o+n > end {
			return ""
		}
		if t == 0 {
			v := b[o : o+n]
			if len(v) < 5 || int(binary.BigEndian.Uint16(v))+2 != len(v) {
				return ""
			}
			for j := 2; j+3 <= len(v); {
				typ := v[j]
				l := int(binary.BigEndian.Uint16(v[j+1:]))
				j += 3
				if j+l > len(v) {
					return ""
				}
				if typ == 0 {
					return strings.ToLower(strings.TrimSuffix(string(v[j:j+l]), "."))
				}
				j += l
			}
		}
		o += n
	}
	return ""
}

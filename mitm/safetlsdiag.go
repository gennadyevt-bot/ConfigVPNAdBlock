package mitm

// Passive TLS metadata only. TLS 1.3 Finished, selected ALPN and alerts are
// encrypted: record arrival must never be labelled a completed handshake.
import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type safeTLSSession struct {
	mu    sync.Mutex
	flows []*safeTLSFlow
}

var safeTLSSessions atomic.Pointer[safeTLSSession]

func resetSafeTLS() { safeTLSSessions.Store(&safeTLSSession{}) }
func SafeTLSFlows() string {
	s := safeTLSSessions.Load()
	if s == nil {
		return "[]"
	}
	s.mu.Lock()
	fs := append([]*safeTLSFlow(nil), s.flows...)
	s.mu.Unlock()
	out := make([]safeTLSSummary, 0, len(fs))
	for _, f := range fs {
		f.mu.Lock()
		v := f.v
		if v.EndAt == 0 {
			v.DurationMs = time.Now().UnixMilli() - v.StartAt
		}
		f.mu.Unlock()
		out = append(out, v)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

type safeTLSSummary struct {
	TunPackets int64  `json:"tunPacketsToApp"`
	TunPayload int64  `json:"tunPayloadBytesToApp"`
	TunLastAt  int64  `json:"tunLastWriteAt"`
	AppACKs    int64  `json:"appACKCount"`
	AppACKAt   int64  `json:"appLastACKAt"`
	AppACK     uint32 `json:"appLastACK"`
	AppWindow  uint16 `json:"appWindowRaw"`
	TunDataEnd uint32 `json:"tunDataEndSeq"`
	Pending    int64  `json:"tcpUnackedBytes"`
	AppRST     bool   `json:"appRST"`
	TunRST     bool   `json:"tunRST"`
	AppFIN     bool   `json:"appFIN"`
	TunFIN     bool   `json:"tunFIN"`

	ClientReads         int64  `json:"clientReads"`
	ServerReads         int64  `json:"serverReads"`
	LastClientReadAt    int64  `json:"lastClientReadAt"`
	LastServerReadAt    int64  `json:"lastServerReadAt"`
	LastAppWriteAt      int64  `json:"lastAppWriteAt"`
	LastUpstreamWriteAt int64  `json:"lastUpstreamWriteAt"`
	ID                  int64  `json:"id"`
	SNI                 string `json:"sni"`
	Dst                 string `json:"dst"`
	StartAt             int64  `json:"startAt"`
	EndAt               int64  `json:"endAt"`
	DurationMs          int64  `json:"durationMs"`
	AppBytes            int64  `json:"appBytesSent"`
	UpstreamBytes       int64  `json:"upstreamBytesDelivered"`
	ClientHello         string `json:"clientHello"`
	ServerHello         string `json:"serverHello"`
	ClientEncrypted     bool   `json:"clientEncryptedRecords"`
	ServerEncrypted     bool   `json:"serverEncryptedRecords"`
	ClientEnd           string `json:"clientEnd"`
	UpstreamEnd         string `json:"upstreamEnd"`
	Reason              string `json:"reason"`
}
type safeTLSFlow struct {
	packetKey      string
	dataSeen       bool
	ackSeen        bool
	mu             sync.Mutex
	v              safeTLSSummary
	client, server tlsRecordObserver
}

func newSafeTLSFlow(id int64, host, dst string, raw []byte) *safeTLSFlow {
	f := &safeTLSFlow{v: safeTLSSummary{ID: id, SNI: host, Dst: dst, Pending: -1, StartAt: time.Now().UnixMilli()}}
	f.client.emit = func(event, detail string) { f.event(true, event, detail) }
	f.server.emit = func(event, detail string) { f.event(false, event, detail) }
	s := safeTLSSessions.Load()
	if s == nil {
		resetSafeTLS()
		s = safeTLSSessions.Load()
	}
	s.mu.Lock()
	if len(s.flows) >= 32 {
		s.flows = s.flows[1:]
	}
	s.flows = append(s.flows, f)
	s.mu.Unlock()
	f.client.feed(raw)
	return f
}
func (f *safeTLSFlow) event(client bool, event, detail string) {
	f.mu.Lock()
	switch event {
	case "HELLO":
		if client {
			f.v.ClientHello = detail
		} else {
			f.v.ServerHello = detail
		}
	case "ENCRYPTED":
		if client {
			f.v.ClientEncrypted = true
		} else {
			f.v.ServerEncrypted = true
		}
	}
	id, host, dst := f.v.ID, f.v.SNI, f.v.Dst
	elapsed := time.Now().UnixMilli() - f.v.StartAt
	f.mu.Unlock()
	direction := "server"
	if client {
		direction = "client"
	}
	flowLog(fmt.Sprintf("SAFE_TLS_%s id=%d sni=%q dst=%s direction=%s elapsedMs=%d %s", event, id, host, dst, direction, elapsed, detail))
}
func (f *safeTLSFlow) sent(client bool, n int) {
	if n <= 0 {
		return
	}
	f.mu.Lock()
	var before, after int64
	if client {
		before = f.v.AppBytes
		f.v.AppBytes += int64(n)
		f.v.LastUpstreamWriteAt = time.Now().UnixMilli()
		after = f.v.AppBytes
	} else {
		before = f.v.UpstreamBytes
		f.v.UpstreamBytes += int64(n)
		f.v.LastAppWriteAt = time.Now().UnixMilli()
		after = f.v.UpstreamBytes
	}
	f.mu.Unlock()
	for _, limit := range []int64{1, 10240, 102400} {
		if before < limit && after >= limit {
			f.event(client, "PROGRESS", fmt.Sprintf("deliveredBytes=%d", after))
			break
		}
	}
}
func (f *safeTLSFlow) end(client bool, err error) {
	f.mu.Lock()
	if client {
		f.v.ClientEnd = err.Error()
	} else {
		f.v.UpstreamEnd = err.Error()
	}
	f.mu.Unlock()
	f.event(client, "READ_END", fmt.Sprintf("err=%q", err.Error()))
}
func (f *safeTLSFlow) finish(reason string) {
	safeTLSDetachPackets(f)
	f.mu.Lock()
	f.v.EndAt = time.Now().UnixMilli()
	f.v.DurationMs = f.v.EndAt - f.v.StartAt
	f.v.Reason = reason
	v := f.v
	f.mu.Unlock()
	b, _ := json.Marshal(v)
	flowLog("SAFE_TLS_END " + string(b))
}

// Wrappers forward the exact bytes/errors; no TLS termination, deadline, retry,
// network selection or relay close policy changes.
type safeTLSConn struct {
	net.Conn
	f      *safeTLSFlow
	client bool
}

func (c *safeTLSConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	if n > 0 {
		c.f.mu.Lock()
		if c.client {
			c.f.v.ClientReads++
			c.f.v.LastClientReadAt = time.Now().UnixMilli()
		} else {
			c.f.v.ServerReads++
			c.f.v.LastServerReadAt = time.Now().UnixMilli()
		}
		c.f.mu.Unlock()
		if c.client {
			c.f.client.feed(p[:n])
		} else {
			c.f.server.feed(p[:n])
		}
	}
	if e != nil {
		c.f.end(c.client, e)
	}
	return n, e
}
func (c *safeTLSConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.f.sent(!c.client, n)
	if e != nil {
		c.f.event(!c.client, "WRITE_ERROR", fmt.Sprintf("err=%q", e.Error()))
	}
	return n, e
}

type tlsRecordObserver struct {
	buf, handshake             []byte
	emit                       func(string, string)
	disabled, hello, encrypted bool
	encryptedEpoch             bool
}

func (o *tlsRecordObserver) feed(p []byte) {
	if o.disabled {
		return
	}
	for len(p) > 0 {
		need := 5 - len(o.buf)
		if len(o.buf) >= 5 {
			size := int(binary.BigEndian.Uint16(o.buf[3:5]))
			if size > 18432 || o.buf[0] < 20 || o.buf[0] > 23 {
				o.disabled = true
				o.buf = nil
				o.handshake = nil
				o.emit("PARSE_LIMIT", "metadata_unavailable")
				return
			}
			need = 5 + size - len(o.buf)
		}
		if need > len(p) {
			need = len(p)
		}
		o.buf = append(o.buf, p[:need]...)
		p = p[need:]
		if len(o.buf) < 5 {
			continue
		}
		size := int(binary.BigEndian.Uint16(o.buf[3:5]))
		if len(o.buf) < 5+size {
			continue
		}
		o.record(o.buf[0], o.buf[5:])
		o.buf = nil
	}
}
func (o *tlsRecordObserver) record(kind byte, p []byte) {
	if kind == 20 {
		o.encryptedEpoch = true
		return
	}
	if kind == 23 || (o.encryptedEpoch && (kind == 21 || kind == 22)) {
		if !o.encrypted {
			o.encrypted = true
			o.emit("ENCRYPTED", "handshake_complete=unknown encrypted_metadata=unavailable")
		}
		return
	}
	if kind == 21 {
		if len(p) >= 2 {
			o.emit("ALERT", fmt.Sprintf("level=%d description=%d", p[0], p[1]))
		}
		return
	}
	if kind != 22 || o.hello {
		return
	}
	if len(o.handshake)+len(p) > 65536 {
		o.disabled = true
		o.handshake = nil
		o.emit("PARSE_LIMIT", "handshake_metadata_unavailable")
		return
	}
	o.handshake = append(o.handshake, p...)
	for len(o.handshake) >= 4 {
		n := int(o.handshake[1])<<16 | int(o.handshake[2])<<8 | int(o.handshake[3])
		if n > 65532 {
			o.disabled = true
			o.handshake = nil
			return
		}
		if len(o.handshake) < 4+n {
			return
		}
		typ := o.handshake[0]
		body := o.handshake[4 : 4+n]
		if typ == 1 || typ == 2 {
			o.hello = true
			o.emit("HELLO", helloMetadata(typ, body))
			o.handshake = nil
			return
		}
		o.handshake = o.handshake[4+n:]
	}
}
func helloMetadata(kind byte, p []byte) string {
	if len(p) < 35 {
		return "malformed_hello"
	}
	version := binary.BigEndian.Uint16(p[:2])
	off := 35 + int(p[34])
	if off > len(p) {
		return "malformed_hello"
	}
	if kind == 1 {
		if off+2 > len(p) {
			return "malformed_hello"
		}
		off += 2 + int(binary.BigEndian.Uint16(p[off:off+2]))
		if off >= len(p) {
			return "malformed_hello"
		}
		off += 1 + int(p[off])
	} else {
		off += 3
	}
	if off > len(p) {
		return "malformed_hello"
	}
	detail := fmt.Sprintf("legacyVersion=0x%04x", version)
	if off == len(p) {
		return detail
	}
	if off+2 > len(p) {
		return "malformed_extensions"
	}
	end := off + 2 + int(binary.BigEndian.Uint16(p[off:off+2]))
	off += 2
	if end > len(p) {
		return "malformed_extensions"
	}
	for off+4 <= end {
		typ := binary.BigEndian.Uint16(p[off : off+2])
		n := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		off += 4
		if off+n > end {
			return "malformed_extensions"
		}
		v := p[off : off+n]
		off += n
		switch typ {
		case 43:
			if kind == 2 && len(v) == 2 {
				version = binary.BigEndian.Uint16(v)
				detail += fmt.Sprintf(" selectedVersion=0x%04x", version)
			} else if kind == 1 && len(v) > 0 {
				detail += " offeredVersions="
				for i := 1; i+1 < len(v); i += 2 {
					detail += fmt.Sprintf("0x%04x,", binary.BigEndian.Uint16(v[i:i+2]))
				}
			}
		case 16:
			if len(v) >= 2 {
				label := " offeredALPN="
				if kind == 2 {
					label = " selectedALPN="
				}
				detail += label
				for i := 2; i < len(v); {
					n := int(v[i])
					i++
					if i+n > len(v) {
						break
					}
					detail += fmt.Sprintf("%q,", v[i:i+n])
					i += n
				}
			}
		}
	}
	if kind == 2 && version == tls.VersionTLS13 {
		detail += " selectedALPN=encrypted handshake_complete=unknown"
	}
	return detail
}

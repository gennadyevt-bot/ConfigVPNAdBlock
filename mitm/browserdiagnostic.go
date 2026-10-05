package mitm

import (
	"encoding/json"
	"fmt"
	"golang.org/x/net/dns/dnsmessage"
	"sort"
	"sync"
)

// Observe only metadata. Never retain packet contents, URLs or TLS plaintext.
// Both pump directions share this bounded, session-local table.
type browserDiagnostic struct {
	mu    sync.Mutex
	flows map[browserFlowKey]*browserDiagnosticFlow
}
type browserDiagnosticFlow struct {
	Client      string `json:"client"`
	Destination string `json:"dst"`
	Protocol    byte   `json:"proto"`
	Tx          uint64 `json:"tx"`
	Rx          uint64 `json:"rx"`
	Blocked     uint64 `json:"blocked"`
	Syn         uint64 `json:"syn"`
	SynAck      uint64 `json:"synAck"`
	TxPayload   uint64 `json:"txPayload"`
	RxPayload   uint64 `json:"rxPayload"`
	ClientRST   bool   `json:"clientRST"`
	ServerRST   bool   `json:"serverRST"`
}

func (d *browserDiagnostic) observe(b []byte, outbound, blocked bool) {
	p, ok := parseBrowserPacket(b)
	if !ok {
		return
	}
	key := browserFlowKey{p.src, p.dst, p.proto}
	if !outbound {
		key = browserFlowKey{p.dst, p.src, p.proto}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.flows == nil {
		d.flows = make(map[browserFlowKey]*browserDiagnosticFlow)
	}
	f := d.flows[key]
	if f == nil {
		if len(d.flows) >= 128 {
			return
		}
		f = &browserDiagnosticFlow{Client: key.src.String(), Destination: key.dst.String(), Protocol: p.proto}
		d.flows[key] = f
		flowLog(fmt.Sprintf("BROWSER_FLOW_OPEN proto=%d client=%s dst=%s", p.proto, key.src, key.dst))
	}
	if blocked {
		f.Blocked++
	} else if outbound {
		f.Tx++
	} else {
		f.Rx++
	}
	payload := len(b) - p.off - 8
	if p.proto == 6 {
		t := b[p.off:]
		payload = len(t) - int(t[12]>>4)*4
		if t[13]&2 != 0 {
			if outbound {
				f.Syn++
			} else if t[13]&16 != 0 {
				f.SynAck++
			}
		}
		if t[13]&4 != 0 {
			if outbound {
				f.ClientRST = true
			} else {
				f.ServerRST = true
			}
		}
	}
	if !blocked {
		if outbound {
			f.TxPayload += uint64(payload)
		} else {
			f.RxPayload += uint64(payload)
		}
	}
	if p.proto == 17 && (p.src.Port() == 53 || p.dst.Port() == 53) {
		var m dnsmessage.Message
		if m.Unpack(b[p.off+8:]) == nil {
			for _, q := range m.Questions {
				answers := []string{}
				for _, a := range m.Answers {
					switch v := a.Body.(type) {
					case *dnsmessage.AResource:
						answers = append(answers, fmt.Sprint(v.A))
					case *dnsmessage.AAAAResource:
						answers = append(answers, fmt.Sprint(v.AAAA))
					case *dnsmessage.CNAMEResource:
						answers = append(answers, v.CNAME.String())
					}
				}
				flowLog(fmt.Sprintf("BROWSER_DNS outbound=%t host=%q type=%d response=%t rcode=%d blocked=%t answers=%v", outbound, q.Name.String(), q.Type, m.Response, m.RCode, blocked, answers))
			}
		}
	}
}
func (d *browserDiagnostic) snapshot() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	rows := make([]browserDiagnosticFlow, 0, len(d.flows))
	for _, f := range d.flows {
		rows = append(rows, *f)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Destination != rows[j].Destination {
			return rows[i].Destination < rows[j].Destination
		}
		return rows[i].Client < rows[j].Client
	})
	b, _ := json.Marshal(rows)
	return string(b)
}

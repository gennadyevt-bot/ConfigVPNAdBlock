package mitm

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"sync"
	"testing"
)

func TestBrowserDiagnosticDirectionsAndPacketIdentity(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		var d browserDiagnostic
		syn := packetTCP(v6, 1, 2, nil)
		original := append([]byte(nil), syn...)
		d.observe(syn, true, false)
		if !bytes.Equal(syn, original) {
			t.Fatal("observer changed packet")
		}
		p, _ := parseBrowserPacket(syn)
		reply := browserReply(p, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 18, 0, 0, 0, 0, 0, 0})
		binary.BigEndian.PutUint16(reply[p.off:], p.dst.Port())
		binary.BigEndian.PutUint16(reply[p.off+2:], p.src.Port())
		d.observe(reply, false, false)
		data := packetTCP(v6, 2, 16, []byte("payload"))
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); d.observe(data, true, false); d.snapshot() }()
		}
		wg.Wait()
		d.observe(data, true, true)
		var rows []browserDiagnosticFlow
		if e := json.Unmarshal([]byte(d.snapshot()), &rows); e != nil {
			t.Fatal(e)
		}
		if len(rows) != 1 || rows[0].Syn != 1 || rows[0].SynAck != 1 || rows[0].Tx != 11 || rows[0].Rx != 1 || rows[0].TxPayload != 70 || rows[0].Blocked != 1 {
			t.Fatalf("wrong flow summary: %+v", rows)
		}
	}
}

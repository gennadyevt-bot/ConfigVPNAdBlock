package mitm

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestQUICDNSKnowledgeIsFreshAndUnambiguous(t *testing.T) {
	const ip = "192.0.2.99"
	dnsIPMapPut(ip, "ads.example.test", 60)
	if host, ok := dnsIPMapGet(ip); !ok || host != "ads.example.test" {
		t.Fatal("known DNS hostname lost")
	}
	dnsIPMapPut(ip, "video.example.test", 60)
	if _, ok := dnsIPMapGet(ip); ok {
		t.Fatal("shared CDN IP classified as single advertising domain")
	}
	dnsIPMapMu.Lock()
	dnsIPMap[ip] = map[string]time.Time{"ads.example.test": time.Now().Add(-time.Second)}
	dnsIPMapMu.Unlock()
	if _, ok := dnsIPMapGet(ip); ok {
		t.Fatal("expired association still classified")
	}
}
func TestRecordDNSAnswersHonorsTTL(t *testing.T) {
	query := []byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a', 'd', 's', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
	ans := append([]byte(nil), query...)
	ans[2] = 0x81
	ans[3] = 0x80
	ans[7] = 1
	ans = append(ans, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 100)
	recordDNSAnswers(query, ans)
	if name, ok := dnsIPMapGet("192.0.2.100"); !ok || name != "ads.test" {
		t.Fatal("DNS TTL association unavailable")
	}
	// Zero TTL answer provides no lasting QUIC hostname knowledge.
	binary.BigEndian.PutUint32(ans[len(ans)-10:len(ans)-6], 0)
	ans[len(ans)-1] = 101
	recordDNSAnswers(query, ans)
	if _, ok := dnsIPMapGet("192.0.2.101"); ok {
		t.Fatal("TTL zero persisted")
	}
}

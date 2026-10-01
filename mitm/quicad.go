package mitm

// QUIC-селективность: UDP/443 к известным РЕКЛАМНЫМ/фильтруемым доменам
// Яндекса ДРОПАЕМ (браузер откатывается на TCP -> SNI-блок/MITM работают).
// Остальной QUIC (Google, YouTube и пр.) РЕЛЕИМ как есть - их пиннинг всё
// равно не даёт MITM, а дроп только ломал скорость.
// IP-доменов периодически резолвим через DNS туннеля (wgResolve).

import (
	"strings"
	"sync"
	"time"
)

var (
	quicAdMu   sync.RWMutex
	quicAdIPs  = map[string]bool{}
	quicAdOnce sync.Once
)

var quicAdDomains = []string{
	"an.yandex.ru", "yabs.yandex.ru", "ads.adfox.ru", "adfox.ru",
	"mc.yandex.ru", "adfstat.yandex.ru", "dr.yandex.net", "dr2.yandex.net",
	"awaps.yandex.net", "dzen.ru", "www.dzen.ru",
}

func startQuicAdResolver() {
	quicAdOnce.Do(func() {
		go func() {
			for {
				refreshQuicAdIPs()
				time.Sleep(3 * time.Minute)
			}
		}()
	})
}

func refreshQuicAdIPs() {
	if !wgUpstreamActive() {
		return
	}
	ips := map[string]bool{}
	for _, d := range quicAdDomains {
		if ip, err := wgResolve(strings.TrimSpace(d)); err == nil && ip != nil {
			ips[ip.String()] = true
		}
	}
	quicAdMu.Lock()
	quicAdIPs = ips
	quicAdMu.Unlock()
}

func isQuicAdIP(ip string) bool {
	quicAdMu.RLock()
	defer quicAdMu.RUnlock()
	return quicAdIPs[ip]
}

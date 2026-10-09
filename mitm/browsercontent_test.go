package mitm

import (
	"testing"
)

func TestBrowserContentExceptionsUseSharedBlocklist(t *testing.T) {
	blockedMu.Lock()
	savedDomains, savedPaths := blockedDomains, blockedPaths
	blockedMu.Unlock()
	defer func() {
		SetBrowserCompatibility("OFF", "")
		blockedMu.Lock()
		blockedDomains, blockedPaths = savedDomains, savedPaths
		blockedMu.Unlock()
	}()
	loadBlocklist("../app/src/main/assets/blocklist.txt")
	for _, scope := range []struct {
		mode, apps string
		allow      bool
	}{
		{"INCLUDE", "com.android.chrome", true},
		{"INCLUDE", "com.android.chrome,com.google.android.googlequicksearchbox", true},
		{"GLOBAL", "", false},
		{"EXCLUDE", "com.android.chrome", false},
		{"OFF", "", false},
		{"INCLUDE", "", false},
		{"INCLUDE", "com.android.chrome,com.google.android.youtube", false},
	} {
		SetBrowserCompatibility(scope.mode, scope.apps)
		for _, host := range []string{"an.yandex.ru", "ssp.rambler.ru", "ads.adfox.ru", "AN.YANDEX.RU.", "ssp.rambler.ru:443"} {
			if got := isBlocked(host); got == scope.allow {
				t.Fatalf("%s %s host=%s blocked=%v", scope.mode, scope.apps, host, got)
			}
		}
		for _, host := range []string{"www.googleadservices.com", "child.an.yandex.ru", "child.ads.adfox.ru"} {
			if !isBlocked(host) {
				t.Fatalf("advertising escaped block: %s (%s)", host, scope.mode)
			}
		}
		for _, host := range []string{"lenta.ru", "dzen.ru"} {
			if isBlocked(host) {
				t.Fatalf("content host blocked: %s", host)
			}
		}
	}
	SetBrowserCompatibility("INCLUDE", "com.android.chrome")
	for _, host := range []string{"an.yandex.ru.evil.test", "other.yandex.ru", "adfox.ru"} {
		if browserContentAllowed(host) {
			t.Fatalf("exception too broad: %s", host)
		}
	}
}

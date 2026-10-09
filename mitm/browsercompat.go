package mitm

import (
	"fmt"
	"strings"
	"sync/atomic"
)

var browserCompatibility atomic.Bool
var appScopeContentAllowlist atomic.Bool

// SetBrowserCompatibility uses the established Android TUN application scope.
// Other applications and GLOBAL/EXCLUDE scopes keep their existing pipeline.
func SetBrowserCompatibility(mode, packages string) {
	enabled := mode == "INCLUDE" && strings.TrimSpace(packages) != ""
	for _, app := range strings.Split(packages, ",") {
		app = strings.TrimSpace(app)
		if app != "com.android.chrome" && app != "com.google.android.googlequicksearchbox" {
			enabled = false
		}
	}
	browserCompatibility.Store(enabled)
}

// Independent of the browser TLS/QUIC policy: every established INCLUDE
// TUN with AdBlock gets the content exceptions, including mixed app lists.
func SetAppScopeContentAllowlist(mode, packages string, adBlockEnabled bool) {
	enabled := adBlockEnabled && mode == "INCLUDE"
	apps := strings.Split(packages, ",")
	for _, app := range apps {
		if strings.TrimSpace(app) == "" {
			enabled = false
		}
	}
	appScopeContentAllowlist.Store(enabled)
	flowLog(fmt.Sprintf("APP_SCOPE_CONTENT_ALLOWLIST enabled=%t mode=%s adblock=%t apps=%q", enabled, mode, adBlockEnabled, packages))
	if enabled {
		flowLog("APP_SCOPE_CONTENT_ALLOWLIST hosts=an.yandex.ru,ssp.rambler.ru,ads.adfox.ru match=exact DNS_SNI_QUIC")
	}
}

func AppScopeContentAllowlistEnabled() bool { return appScopeContentAllowlist.Load() }

// A narrow compatibility exception for the AdBlock INCLUDE TUN.
// Keep the shared asset and GLOBAL/EXCLUDE rules intact. Do not exempt parent
// domains or arbitrary subdomains, which would allow unrelated advertising.
func browserContentAllowed(host string) bool {
	if !appScopeContentAllowlist.Load() {
		return false
	}
	switch host {
	case "an.yandex.ru", "ssp.rambler.ru", "ads.adfox.ru":
		return true
	default:
		return false
	}
}

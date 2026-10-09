package mitm

import (
	"strings"
	"sync/atomic"
)

var browserCompatibility atomic.Bool

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
	if enabled {
		flowLog("APP_SCOPE_CONTENT_ALLOWLIST enabled=true hosts=an.yandex.ru,ssp.rambler.ru,ads.adfox.ru match=exact DNS_SNI_QUIC")
	} else {
		flowLog("APP_SCOPE_CONTENT_ALLOWLIST enabled=false")
	}
}

// A narrow compatibility exception for the browser-only INCLUDE passthrough.
// Keep the shared asset and GLOBAL/EXCLUDE rules intact. Do not exempt parent
// domains or arbitrary subdomains, which would allow unrelated advertising.
func browserContentAllowed(host string) bool {
	if !browserCompatibility.Load() {
		return false
	}
	switch host {
	case "an.yandex.ru", "ssp.rambler.ru", "ads.adfox.ru":
		return true
	default:
		return false
	}
}

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
}

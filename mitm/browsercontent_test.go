package mitm

import (
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestBrowserContentExceptionsUseSharedBlocklist(t *testing.T) {
	blockedMu.Lock()
	savedDomains, savedPaths := blockedDomains, blockedPaths
	blockedMu.Unlock()
	defer func() {
		SetAppScopeContentAllowlist("OFF", "", false)
		blockedMu.Lock()
		blockedDomains, blockedPaths = savedDomains, savedPaths
		blockedMu.Unlock()
	}()
	loadBlocklist("../app/src/main/assets/blocklist.txt")
	for _, scope := range []struct {
		mode, apps     string
		adblock, allow bool
	}{
		{"INCLUDE", "com.android.chrome", true, true},
		{"INCLUDE", "com.android.chrome,com.google.android.googlequicksearchbox", true, true},
		{"GLOBAL", "", true, false},
		{"EXCLUDE", "com.android.chrome", true, false},
		{"OFF", "", false, false},
		{"INCLUDE", "", true, false},
		{"INCLUDE", "com.android.chrome,com.google.android.youtube", true, true},
		{"INCLUDE", "com.google.android.youtube", true, true},
		{"INCLUDE", "com.android.chrome", false, false},
		{"INCLUDE", "com.android.chrome,", true, false},
	} {
		SetAppScopeContentAllowlist(scope.mode, scope.apps, scope.adblock)
		if AppScopeContentAllowlistEnabled() != scope.allow {
			t.Fatal("wrong active state")
		}
		// Changing the independent TLS policy must not disable content exceptions.
		SetBrowserCompatibility("OFF", "")
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
	SetAppScopeContentAllowlist("INCLUDE", "com.android.chrome", true)
	for _, host := range []string{"an.yandex.ru.evil.test", "other.yandex.ru", "adfox.ru"} {
		if browserContentAllowed(host) {
			t.Fatalf("exception too broad: %s", host)
		}
	}
}

type contentDNSConn struct{ net.Conn }

func (c contentDNSConn) ID() stack.TransportEndpointID {
	return stack.TransportEndpointID{LocalAddress: tcpip.AddrFrom4([4]byte{1, 1, 1, 1}), LocalPort: 53}
}
func (c contentDNSConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Read(b)
	return n, c.RemoteAddr(), err
}
func (c contentDNSConn) WriteTo(b []byte, _ net.Addr) (int, error) { return c.Write(b) }

func TestAppScopeDNSHandlerAllowsContentAndLogsLenta(t *testing.T) {
	blockedMu.Lock()
	saved := blockedDomains
	blockedDomains = map[string]bool{"an.yandex.ru": true, "ssp.rambler.ru": true, "ads.adfox.ru": true, "googleadservices.com": true}
	blockedMu.Unlock()
	defer func() {
		SetAppScopeContentAllowlist("OFF", "", false)
		blockedMu.Lock()
		blockedDomains = saved
		blockedMu.Unlock()
	}()
	for _, mode := range []string{"INCLUDE", "GLOBAL"} {
		SetAppScopeContentAllowlist(mode, "com.android.chrome,com.google.android.youtube", true)
		for _, host := range []string{"an.yandex.ru", "ssp.rambler.ru", "ads.adfox.ru", "lenta.ru", "dzen.ru", "www.googleadservices.com"} {
			name, err := dnsmessage.NewName(host + ".")
			if err != nil {
				t.Fatal(err)
			}
			query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 0xbeef}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
			if err != nil {
				t.Fatal(err)
			}
			// A cached successful response lets this test exercise the actual
			// UDP handler without depending on external DNS or a live VPN.
			cached := transportDNSError(query, 0)
			dnsCachePut(string(query), cached)
			app, tun := net.Pipe()
			app.SetDeadline(time.Now().Add(2 * time.Second))
			done := make(chan struct{})
			go func() { (&tunHandler{}).HandleUDP(contentDNSConn{tun}); close(done) }()
			if _, err := app.Write(query); err != nil {
				t.Fatal(err)
			}
			answer := make([]byte, 4096)
			n, err := app.Read(answer)
			app.Close()
			if err != nil {
				t.Fatal(err)
			}
			<-done
			dnsCacheMu.Lock()
			delete(dnsCache, string(query))
			dnsCacheMu.Unlock()
			var msg dnsmessage.Message
			if err := msg.Unpack(answer[:n]); err != nil {
				t.Fatal(err)
			}
			wantBlocked := host == "www.googleadservices.com" || (mode == "GLOBAL" && host != "lenta.ru" && host != "dzen.ru")
			if (msg.RCode == dnsmessage.RCodeNameError) != wantBlocked {
				t.Fatalf("%s %s rcode=%v", mode, host, msg.RCode)
			}
			if mode == "INCLUDE" && !strings.Contains(FlowLog(), "APP_SCOPE_DNS_QUERY host=\""+host+"\"") {
				t.Fatalf("query missing from log: %s", host)
			}
		}
	}
}

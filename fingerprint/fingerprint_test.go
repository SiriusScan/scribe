package fingerprint

import (
	"fmt"
	"net/http"
	"regexp"
	"testing"
)

func TestMatch(t *testing.T) {
	m := Default()
	f := m.Match("SSH-2.0-OpenSSH_9.0", nil)
	if f.Product != "OpenSSH" || f.Version != "9.0" {
		t.Fatal(f)
	}
	f = m.Match("", http.Header{"Server": []string{"nginx/1.2"}})
	if f.Version != "1.2" {
		t.Fatal(f)
	}
	if m.Match("unknown", nil) != (Facts{}) {
		t.Fatal("unknown matched")
	}
	custom := New(Rule{Pattern: regexp.MustCompile(`hello (\d+)`), Product: "custom"})
	if custom.Match("hello 42", nil).Version != "42" {
		t.Fatal("custom rule")
	}
}

func TestExpandedPinnedBanners(t *testing.T) {
	for _, tt := range []struct{ banner, product string }{
		{"220 mail ESMTP Postfix", "Postfix"},
		{"220 ProFTPD 1.3.9 Server (Debian)", "ProFTPD"},
		{"SSH-2.0-dropbear_2025.88", "Dropbear"},
		{"220 Pure-FTPd ready", "Pure-FTPd"},
		{"220 mail Sendmail 8.17.1 ready", "Sendmail"},
		{"220 mail ESMTP Exim 4.97", "Exim"},
		{"220 (vsFTPd 3.0.5)", "vsftpd"},
		{"220 ProFTPD 1.3.8 Server", "ProFTPD"},
		{"SSH-2.0-dropbear_2024.86", "Dropbear"},
		{"redis_version:7.2.4\r\n", "Redis"},
		{"\x0a10.11.6-MariaDB", "MariaDB"},
		{"\x0a8.0.36", "MySQL"},
	} {
		if got := Default().Match(tt.banner, nil); got.Product != tt.product {
			t.Errorf("%q: %+v", tt.banner, got)
		}
	}
}

// Original pinned header observations exercise every built-in HTTP family.
func TestPinnedHTTPIdentities(t *testing.T) {
	for _, tt := range []struct{ header, product, version string }{
		{"Caddy/2.8.4", "Caddy", "2.8.4"},
		{"openresty/1.25.3.2", "OpenResty", "1.25.3.2"},
		{"Microsoft-IIS/10.0", "IIS", "10.0"},
		{"lighttpd/1.4.76", "lighttpd", "1.4.76"},
		{"Apache Tomcat/9.0.98", "Tomcat", "9.0.98"},
		{"Jetty(9.4.56.v20240826)", "Jetty", "9.4.56.v20240826"},
		{"Apache/2.4.62", "Apache", "2.4.62"},
		{"nginx/1.26.2", "nginx", "1.26.2"},
	} {
		t.Run(tt.product, func(t *testing.T) {
			got := Default().Match("", http.Header{"Server": {tt.header}})
			if got != (Facts{Service: "http", Product: tt.product, Version: tt.version}) {
				t.Fatal(got)
			}
		})
	}
}

func TestPinnedUnknownIdentities(t *testing.T) {
	for _, input := range []string{"", "unknown", "HTTP/1.1 200 OK", "SSH-2.0-unknown", "220 mail ready", "redis_version:", "Postfix", "Exim 4.97"} {
		if got := Default().Match(input, nil); got != (Facts{}) {
			t.Errorf("%q inferred %+v", input, got)
		}
	}
	for _, header := range []string{"", "unknown", "OpenSSH_9.0", "application server", "proxy nginx/1.26.2", "Caddyshack", "openrestyled", "proxy Apache/2.4.62", "proxy Microsoft-IIS/10.0", "proxy lighttpd/1.4.76", "proxy Jetty(9.4.56)"} {
		if got := Default().Match("", http.Header{"Server": {header}}); got != (Facts{}) {
			t.Errorf("%q inferred %+v", header, got)
		}
	}
}

// Original observations pin HAProxy identity boundaries, not upstream compatibility.
func TestHAProxyIdentity(t *testing.T) {
	for _, tc := range []struct {
		header, version string
		match           bool
	}{
		{"HAProxy/3.0.5", "3.0.5", true},
		{"haproxy/2.9.12", "2.9.12", true},
		{"HAProxy", "", true},
		{"HAProxy/3.0.5 proxy", "3.0.5", true},
		{"HAProxyish", "", false},
		{"proxy HAProxy/3.0.5", "", false},
		{"HAProxy/3.0.5evil", "", false},
		{"HAProxy/", "", false},
		{"HAProxy/3..5", "", false},
	} {
		got := Default().Match("", http.Header{"Server": {tc.header}})
		want := Facts{}
		if tc.match {
			want = Facts{Service: "http", Product: "HAProxy", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.header, got, want)
		}
	}
}

// Original observations pin Envoy identity boundaries, not upstream compatibility.
func TestEnvoyIdentity(t *testing.T) {
	for _, tc := range []struct {
		header, version string
		match           bool
	}{
		{"Envoy/3.0.5", "3.0.5", true},
		{"envoy/2.9.12", "2.9.12", true},
		{"Envoy", "", true},
		{"Envoy/3.0.5 proxy", "3.0.5", true},
		{"Envoyish", "", false},
		{"proxy Envoy/3.0.5", "", false},
		{"Envoy/3.0.5evil", "", false},
		{"Envoy/", "", false},
		{"Envoy/3..5", "", false},
	} {
		got := Default().Match("", http.Header{"Server": {tc.header}})
		want := Facts{}
		if tc.match {
			want = Facts{Service: "http", Product: "Envoy", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.header, got, want)
		}
	}
}

// Default rules are shared read-only; custom matchers retain their own rule slice.
func TestDefaultParallelIsolation(t *testing.T) {
	for i := 0; i < 32; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			custom := New(Rule{Service: "custom"})
			if got := custom.Match("", nil); got != (Facts{}) {
				t.Fatal(got)
			}
			got := Default().Match("SSH-2.0-OpenSSH_9.9", nil)
			if got.Product != "OpenSSH" || got.Version != "9.9" {
				t.Fatal(got)
			}
		})
	}
}

func BenchmarkDefaultMatch(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if got := Default().Match("SSH-2.0-OpenSSH_9.9", nil); got.Product != "OpenSSH" {
			b.Fatal(got)
		}
	}
}

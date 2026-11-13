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

// Original observations pin Varnish identity boundaries, not upstream compatibility.
func TestVarnishIdentity(t *testing.T) {
	for _, tc := range []struct {
		header, version string
		match           bool
	}{
		{"Varnish/3.0.5", "3.0.5", true},
		{"varnish/2.9.12", "2.9.12", true},
		{"Varnish", "", true},
		{"Varnish/3.0.5 proxy", "3.0.5", true},
		{"Varnishish", "", false},
		{"proxy Varnish/3.0.5", "", false},
		{"Varnish/3.0.5evil", "", false},
		{"Varnish/", "", false},
		{"Varnish/3..5", "", false},
	} {
		got := Default().Match("", http.Header{"Server": {tc.header}})
		want := Facts{}
		if tc.match {
			want = Facts{Service: "http", Product: "Varnish", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.header, got, want)
		}
	}
}

// Original observations pin Squid identity boundaries, not upstream compatibility.
func TestSquidIdentity(t *testing.T) {
	for _, tc := range []struct {
		header, version string
		match           bool
	}{
		{"Squid/3.0.5", "3.0.5", true},
		{"squid/2.9.12", "2.9.12", true},
		{"Squid", "", true},
		{"Squid/3.0.5 proxy", "3.0.5", true},
		{"Squidish", "", false},
		{"proxy Squid/3.0.5", "", false},
		{"Squid/3.0.5evil", "", false},
		{"Squid/", "", false},
		{"Squid/3..5", "", false},
	} {
		got := Default().Match("", http.Header{"Server": {tc.header}})
		want := Facts{}
		if tc.match {
			want = Facts{Service: "http", Product: "Squid", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.header, got, want)
		}
	}
}

// Original observations pin Traefik identity boundaries, not upstream compatibility.
func TestTraefikIdentity(t *testing.T) {
	for _, tc := range []struct {
		header, version string
		match           bool
	}{
		{"Traefik/3.0.5", "3.0.5", true},
		{"traefik/2.9.12", "2.9.12", true},
		{"Traefik", "", true},
		{"Traefik/3.0.5 proxy", "3.0.5", true},
		{"Traefikish", "", false},
		{"proxy Traefik/3.0.5", "", false},
		{"Traefik/3.0.5evil", "", false},
		{"Traefik/", "", false},
		{"Traefik/3..5", "", false},
	} {
		got := Default().Match("", http.Header{"Server": {tc.header}})
		want := Facts{}
		if tc.match {
			want = Facts{Service: "http", Product: "Traefik", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.header, got, want)
		}
	}
}

// Original observations pin H2O identity boundaries, not upstream compatibility.
func TestH2OIdentity(t *testing.T) {
	for _, tc := range []struct {
		header, version string
		match           bool
	}{
		{"H2O/3.0.5", "3.0.5", true},
		{"h2o/2.9.12", "2.9.12", true},
		{"H2O", "", true},
		{"H2O/3.0.5 proxy", "3.0.5", true},
		{"H2Oish", "", false},
		{"proxy H2O/3.0.5", "", false},
		{"H2O/3.0.5evil", "", false},
		{"H2O/", "", false},
		{"H2O/3..5", "", false},
	} {
		got := Default().Match("", http.Header{"Server": {tc.header}})
		want := Facts{}
		if tc.match {
			want = Facts{Service: "http", Product: "H2O", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.header, got, want)
		}
	}
}

// Original observations pin LiteSpeed identity boundaries, not upstream compatibility.
func TestLiteSpeedIdentity(t *testing.T) {
	for _, tc := range []struct {
		header, version string
		match           bool
	}{
		{"LiteSpeed/3.0.5", "3.0.5", true},
		{"litespeed/2.9.12", "2.9.12", true},
		{"LiteSpeed", "", true},
		{"LiteSpeed/3.0.5 proxy", "3.0.5", true},
		{"LiteSpeedish", "", false},
		{"proxy LiteSpeed/3.0.5", "", false},
		{"LiteSpeed/3.0.5evil", "", false},
		{"LiteSpeed/", "", false},
		{"LiteSpeed/3..5", "", false},
	} {
		got := Default().Match("", http.Header{"Server": {tc.header}})
		want := Facts{}
		if tc.match {
			want = Facts{Service: "http", Product: "LiteSpeed", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.header, got, want)
		}
	}
}

// Original observations pin Cherokee identity boundaries, not upstream compatibility.
func TestCherokeeIdentity(t *testing.T) {
	for _, tc := range []struct {
		header, version string
		match           bool
	}{
		{"Cherokee/3.0.5", "3.0.5", true},
		{"cherokee/2.9.12", "2.9.12", true},
		{"Cherokee", "", true},
		{"Cherokee/3.0.5 proxy", "3.0.5", true},
		{"Cherokeeish", "", false},
		{"proxy Cherokee/3.0.5", "", false},
		{"Cherokee/3.0.5evil", "", false},
		{"Cherokee/", "", false},
		{"Cherokee/3..5", "", false},
	} {
		got := Default().Match("", http.Header{"Server": {tc.header}})
		want := Facts{}
		if tc.match {
			want = Facts{Service: "http", Product: "Cherokee", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.header, got, want)
		}
	}
}

func TestFileZillaIdentity(t *testing.T) {
	for _, tc := range []struct {
		banner, version string
		match           bool
	}{
		{"220 FileZilla Server 1.9.4 ready\r\n", "1.9.4", true},
		{"220-FileZilla Server", "", true},
		{"220 FileZilla Serverish", "", false},
		{"220 FileZilla Server 1..4", "", false},
		{"220 FileZilla Server 1.9evil", "", false},
		{"500 FileZilla Server 1.9.4", "", false},
		{"220 proxy FileZilla Server 1.9.4", "", false},
		{"220 FileZilla Server\r\nother", "", false},
	} {
		got := Default().Match(tc.banner, nil)
		want := Facts{}
		if tc.match {
			want = Facts{Service: "ftp", Product: "FileZilla", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.banner, got, want)
		}
	}
}

func TestDovecotIdentity(t *testing.T) {
	for _, tc := range []struct {
		banner, version string
		match           bool
	}{
		{"+OK Dovecot 2.3.21 ready.\r\n", "2.3.21", true},
		{"+OK Dovecot ready.", "", true},
		{"+OK Dovecotish ready.", "", false},
		{"+OK Dovecot 2..3 ready.", "", false},
		{"+OK Dovecot 2.3evil ready.", "", false},
		{"-ERR Dovecot ready.", "", false},
		{"+OK proxy Dovecot ready.", "", false},
		{"+OK Dovecot ready.\r\nother", "", false},
	} {
		got := Default().Match(tc.banner, nil)
		want := Facts{}
		if tc.match {
			want = Facts{Service: "pop3", Product: "Dovecot", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.banner, got, want)
		}
	}
}

func TestIISIdentityBoundaries(t *testing.T) {
	for _, tt := range []struct{ header, version string }{{"Microsoft-IIS", ""}, {"Microsoft-IIS/10.0", "10.0"}, {"microsoft-iis/8.5 extra", "8.5"}} {
		if got := Default().Match("", http.Header{"Server": {tt.header}}); got != (Facts{Service: "http", Product: "IIS", Version: tt.version}) {
			t.Fatalf("%q: %+v", tt.header, got)
		}
	}
}

func TestTomcatIdentityBoundaries(t *testing.T) {
	for _, tt := range []struct{ header, version string }{{"Tomcat", ""}, {"Tomcat/10.0", "10.0"}, {"Apache Tomcat/8.5 extra", "8.5"}} {
		if got := Default().Match("", http.Header{"Server": {tt.header}}); got != (Facts{Service: "http", Product: "Tomcat", Version: tt.version}) {
			t.Fatalf("%q: %+v", tt.header, got)
		}
	}
}

func TestDovecotIMAPIdentity(t *testing.T) {
	for _, tc := range []struct {
		banner, version string
		match           bool
	}{
		{"* OK Dovecot ready.\r\n", "", true},
		{"* OK [CAPABILITY IMAP4rev1 IDLE] Dovecot 2.3.21 ready.\r\n", "2.3.21", true},
		{"* OK Dovecotish ready.", "", false},
		{"* OK Dovecot 2..3 ready.", "", false},
		{"* OK Dovecot 2.3evil ready.", "", false},
		{"* BYE Dovecot ready.", "", false},
		{"* OK proxy Dovecot ready.", "", false},
		{"* OK Dovecot ready.\r\nother", "", false},
	} {
		got := Default().Match(tc.banner, nil)
		want := Facts{}
		if tc.match {
			want = Facts{Service: "imap", Product: "Dovecot", Version: tc.version}
		}
		if got != want {
			t.Errorf("%q: got %+v want %+v", tc.banner, got, want)
		}
	}
}

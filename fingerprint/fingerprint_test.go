package fingerprint

import (
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
	for _, header := range []string{"", "unknown", "OpenSSH_9.0", "application server"} {
		if got := Default().Match("", http.Header{"Server": {header}}); got != (Facts{}) {
			t.Errorf("%q inferred %+v", header, got)
		}
	}
}

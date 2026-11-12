// Package fingerprint provides optional caller-side hints, never vulnerability verdicts.
package fingerprint

import (
	"net/http"
	"regexp"
)

// Facts contains inferred endpoint identity, never a vulnerability verdict.
type Facts struct {
	// Service is inferred service text; empty means unknown.
	Service string
	// Product is inferred product text; empty means unknown.
	Product string
	// Version is capture group one; empty means unavailable.
	Version string
}

// Rule matches either a TCP banner (Header empty) or an HTTP header.
// Capture group one, when present, supplies the version. First match wins.
type Rule struct {
	// Header selects an HTTP header; empty selects the TCP banner.
	Header string
	// Pattern matches identity text; nil disables the rule.
	Pattern *regexp.Regexp
	// Service and Product are returned identity text; empty supplies no identity.
	Service, Product string
}

// Matcher applies an ordered snapshot of rules; the first match wins.
// A zero Matcher has no rules and returns unknown (empty) facts.
type Matcher struct{ rules []Rule }

// New copies the rule slice. Callers must not mutate the referenced patterns.
func New(rules ...Rule) *Matcher { return &Matcher{append([]Rule(nil), rules...)} }

// Default returns the built-in banner and HTTP Server header rules.
func Default() *Matcher { return defaultMatcher }

// Rules and compiled expressions are immutable after initialization.
var defaultMatcher = New(
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^envoy(?:/([0-9]+(?:\.[0-9]+)*))?(?:$|\s)`), Service: "http", Product: "Envoy"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^Varnish(?:/([0-9]+(?:\.[0-9]+)*))?(?:$|\s)`), Service: "http", Product: "Varnish"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^Squid(?:/([0-9]+(?:\.[0-9]+)*))?(?:$|\s)`), Service: "http", Product: "Squid"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^Traefik(?:/([0-9]+(?:\.[0-9]+)*))?(?:$|\s)`), Service: "http", Product: "Traefik"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^HAProxy(?:/([0-9]+(?:\.[0-9]+)*))?(?:$|\s)`), Service: "http", Product: "HAProxy"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^Caddy(?:/([0-9.]+))?(?:$|\s)`), Service: "http", Product: "Caddy"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^openresty(?:/([0-9.]+))?(?:$|\s)`), Service: "http", Product: "OpenResty"},
	Rule{Pattern: regexp.MustCompile(`^220[^\r\n]*Pure-FTPd`), Service: "ftp", Product: "Pure-FTPd"},
	Rule{Pattern: regexp.MustCompile(`^220[^\r\n]*Sendmail ([0-9.]+)`), Service: "smtp", Product: "Sendmail"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^Microsoft-IIS(?:/([0-9.]+))?`), Service: "http", Product: "IIS"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^lighttpd(?:/([0-9.]+))?`), Service: "http", Product: "lighttpd"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^(?:Apache Tomcat|Tomcat)(?:/([0-9.]+))?`), Service: "http", Product: "Tomcat"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^Jetty[/(]([0-9.v]+)`), Service: "http", Product: "Jetty"},
	Rule{Header: "", Pattern: regexp.MustCompile(`^220[^\r\n]*\bPostfix\b`), Service: "smtp", Product: "Postfix"},
	Rule{Header: "", Pattern: regexp.MustCompile(`^220[^\r\n]*\bExim ([0-9.]+)`), Service: "smtp", Product: "Exim"},
	Rule{Header: "", Pattern: regexp.MustCompile(`^220[^\r\n]*\bvsFTPd ([0-9.]+)`), Service: "ftp", Product: "vsftpd"},
	Rule{Header: "", Pattern: regexp.MustCompile(`^220[^\r\n]*\bProFTPD ([0-9.]+)`), Service: "ftp", Product: "ProFTPD"},
	Rule{Header: "", Pattern: regexp.MustCompile(`^\x0a([0-9.]+)-MariaDB`), Service: "mysql", Product: "MariaDB"},
	Rule{Header: "", Pattern: regexp.MustCompile(`^\x0a([0-9.]+)[^\r\n]*`), Service: "mysql", Product: "MySQL"},
	Rule{Header: "", Pattern: regexp.MustCompile(`(?m)^redis_version:([0-9.]+)\r?$`), Service: "redis", Product: "Redis"},
	Rule{Header: "", Pattern: regexp.MustCompile(`^SSH-\S+-dropbear_([0-9.]+)`), Service: "ssh", Product: "Dropbear"},

	Rule{Pattern: regexp.MustCompile(`^SSH-\S+-OpenSSH_([^\s]+)`), Service: "ssh", Product: "OpenSSH"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^nginx(?:/([^\s]+))?(?:$|\s)`), Service: "http", Product: "nginx"},
	Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^Apache(?:/([^\s]+))?`), Service: "http", Product: "Apache"},
)

// Match bounds each input to 8 KiB. Callers decide whether to adopt inferred facts.
func (m *Matcher) Match(banner string, headers http.Header) Facts {
	for _, r := range m.rules {
		if r.Pattern == nil {
			continue
		}
		v := banner
		if r.Header != "" {
			v = headers.Get(r.Header)
		}
		if len(v) > 8192 {
			v = v[:8192]
		}
		s := r.Pattern.FindStringSubmatch(v)
		if s != nil {
			f := Facts{Service: r.Service, Product: r.Product}
			if len(s) > 1 {
				f.Version = s[1]
			}
			return f
		}
	}
	return Facts{}
}

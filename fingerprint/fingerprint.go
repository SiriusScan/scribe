// Package fingerprint provides optional caller-side hints, never vulnerability verdicts.
package fingerprint

import (
	"net/http"
	"regexp"
)

type Facts struct{ Service, Product, Version string }

// Rule matches either a TCP banner (Header empty) or an HTTP header.
// Capture group one, when present, supplies the version. First match wins.
type Rule struct {
	Header           string
	Pattern          *regexp.Regexp
	Service, Product string
}
type Matcher struct{ rules []Rule }

func New(rules ...Rule) *Matcher { return &Matcher{append([]Rule(nil), rules...)} }
func Default() *Matcher {
	return New(
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
		Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)nginx(?:/([^\s]+))?`), Service: "http", Product: "nginx"},
		Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)^Apache(?:/([^\s]+))?`), Service: "http", Product: "Apache"},
	)
}

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

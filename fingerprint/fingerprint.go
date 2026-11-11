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
		Rule{Pattern: regexp.MustCompile(`^SSH-\S+-OpenSSH_([^\s]+)`), Service: "ssh", Product: "OpenSSH"},
		Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)nginx(?:/([^\s]+))?`), Service: "http", Product: "nginx"},
		Rule{Header: "Server", Pattern: regexp.MustCompile(`(?i)Apache(?:/([^\s]+))?`), Service: "http", Product: "Apache"},
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

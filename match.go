package scribe

import (
	"fmt"
	"golang.org/x/mod/semver"
	"regexp"
	"strings"
)

// Match combines fields with AND; alternatives within a field use OR.
// Ports are advisory and never exclude an endpoint.
type Match struct {
	OnUnknown   string   `json:"on_unknown,omitempty"`
	Ports       []uint16 `json:"ports,omitempty"`
	Services    []string `json:"services,omitempty"`
	Products    []string `json:"products,omitempty"`
	Protocols   []string `json:"protocols,omitempty"`
	MinVersion  string   `json:"min_version,omitempty"`
	MaxVersion  string   `json:"max_version,omitempty"`
	BannerRegex string   `json:"banner_regex,omitempty"`
	AnyOf       []Match  `json:"any_of,omitempty"`
	AllOf       []Match  `json:"all_of,omitempty"`
}

func version(v string) string {
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}
func (m Match) validate(depth int) error {
	if m.OnUnknown != "" && m.OnUnknown != "run" && m.OnUnknown != "skip" && m.OnUnknown != "probe" {
		return fmt.Errorf("invalid on_unknown policy")
	}
	if depth > 8 {
		return fmt.Errorf("match nesting exceeds 8")
	}
	if len(m.AnyOf)+len(m.AllOf) > 64 {
		return fmt.Errorf("too many match branches")
	}
	for _, v := range []string{m.MinVersion, m.MaxVersion} {
		if v != "" && !semver.IsValid(version(v)) {
			return fmt.Errorf("invalid semantic version %q", v)
		}
	}
	if m.MinVersion != "" && m.MaxVersion != "" && semver.Compare(version(m.MinVersion), version(m.MaxVersion)) > 0 {
		return fmt.Errorf("reversed version range")
	}
	if len(m.BannerRegex) > 4096 {
		return fmt.Errorf("banner regex too long")
	}
	if _, err := regexp.Compile(m.BannerRegex); err != nil {
		return err
	}
	for _, group := range [][]Match{m.AnyOf, m.AllOf} {
		for _, child := range group {
			if err := child.validate(depth + 1); err != nil {
				return err
			}
		}
	}
	return nil
}

// evaluate returns applicability and positive product identification separately.
func (m Match) evaluate(t Target) (bool, bool) {
	if m.OnUnknown == "run" && m.missing(t) {
		return true, false
	}
	identified := len(m.Products) > 0 && t.Product != "" && contains(m.Products, t.Product)
	for _, pair := range []struct {
		values []string
		fact   string
	}{{m.Services, t.Service}, {m.Products, t.Product}, {m.Protocols, t.Protocol}} {
		if len(pair.values) > 0 && !contains(pair.values, pair.fact) {
			return false, false
		}
	}
	if m.MinVersion != "" || m.MaxVersion != "" {
		v := version(t.Version)
		if !semver.IsValid(v) {
			return false, false
		}
		if m.MinVersion != "" && semver.Compare(v, version(m.MinVersion)) < 0 {
			return false, false
		}
		if m.MaxVersion != "" && semver.Compare(v, version(m.MaxVersion)) > 0 {
			return false, false
		}
	}
	if m.BannerRegex != "" && !regexp.MustCompile(m.BannerRegex).MatchString(t.Banner) {
		return false, false
	}
	for _, child := range m.AllOf {
		ok, id := child.evaluate(t)
		if !ok {
			return false, false
		}
		identified = identified || id
	}
	if len(m.AnyOf) > 0 {
		ok := false
		for _, child := range m.AnyOf {
			yes, id := child.evaluate(t)
			ok = ok || yes
			identified = identified || (yes && id)
		}
		if !ok {
			return false, false
		}
	}
	return true, identified
}

func (m Match) missing(t Target) bool {
	if len(m.Services) > 0 && t.Service == "" || len(m.Products) > 0 && t.Product == "" || len(m.Protocols) > 0 && t.Protocol == "" || (m.MinVersion != "" || m.MaxVersion != "") && t.Version == "" || m.BannerRegex != "" && t.Banner == "" {
		return true
	}
	for _, group := range [][]Match{m.AnyOf, m.AllOf} {
		for _, c := range group {
			if c.missing(t) {
				return true
			}
		}
	}
	return false
}

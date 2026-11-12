package scribe

import (
	"fmt"
	"golang.org/x/mod/semver"
	"regexp"
	"strings"
)

// Match combines fields with AND; alternatives within a field use OR.
// The zero Match accepts every endpoint but supplies no product identification.
// Ports are advisory and never exclude an endpoint.
type Match struct {
	bannerPattern *regexp.Regexp
	// CPE contains accepted CPE alternatives; nil imposes no CPE constraint.
	CPE []string `json:"cpe,omitempty"`
	// Confidence is minimum identity confidence in [0,1]; zero imposes no threshold.
	Confidence float64 `json:"confidence,omitempty"`
	// OnUnknown selects run, skip or probe for missing facts; empty uses normal matching.
	OnUnknown string `json:"on_unknown,omitempty"`
	// Ports contains advisory port numbers; nil supplies no hints and ports never exclude.
	Ports []uint16 `json:"ports,omitempty"`
	// Services contains accepted service names; nil imposes no service constraint.
	Services []string `json:"services,omitempty"`
	// Products contains accepted product names; nil supplies no positive product identification.
	Products []string `json:"products,omitempty"`
	// Protocols contains accepted transports; nil imposes no transport constraint.
	Protocols []string `json:"protocols,omitempty"`
	// ExcludeVersions removes exact semantic versions from otherwise applicable ranges.
	ExcludeVersions []string `json:"exclude_versions,omitempty"`
	// MinVersion is an inclusive semantic-version lower bound; empty is unbounded.
	MinVersion string `json:"min_version,omitempty"`
	// MaxVersion is an inclusive semantic-version upper bound; empty is unbounded.
	MaxVersion string `json:"max_version,omitempty"`
	// MinVersionExclusive excludes the lower boundary when MinVersion is set.
	MinVersionExclusive bool `json:"min_version_exclusive,omitempty"`
	// MaxVersionExclusive excludes the upper boundary when MaxVersion is set.
	MaxVersionExclusive bool `json:"max_version_exclusive,omitempty"`
	// BannerRegex is a Go regular expression bounded to 4096 bytes; empty imposes no banner constraint.
	BannerRegex string `json:"banner_regex,omitempty"`
	// AnyOf contains alternative child matches; nil adds no condition.
	AnyOf []Match `json:"any_of,omitempty"`
	// AllOf contains required child matches; nil adds no condition.
	AllOf []Match `json:"all_of,omitempty"`
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
	if !(m.Confidence >= 0 && m.Confidence <= 1) {
		return fmt.Errorf("confidence must be between zero and one")
	}
	if m.MinVersionExclusive && m.MinVersion == "" || m.MaxVersionExclusive && m.MaxVersion == "" {
		return fmt.Errorf("exclusive version boundary requires its version bound")
	}
	if len(m.ExcludeVersions) > 64 {
		return fmt.Errorf("too many excluded versions")
	}
	for _, v := range m.ExcludeVersions {
		if v == "" {
			return fmt.Errorf("empty excluded version")
		}
	}
	if depth > 8 {
		return fmt.Errorf("match nesting exceeds 8")
	}
	if len(m.AnyOf)+len(m.AllOf) > 64 {
		return fmt.Errorf("too many match branches")
	}
	for _, v := range append([]string{m.MinVersion, m.MaxVersion}, m.ExcludeVersions...) {
		if v != "" && !semver.IsValid(version(v)) {
			return fmt.Errorf("invalid semantic version %q", v)
		}
	}
	if m.MinVersion != "" && m.MaxVersion != "" && (semver.Compare(version(m.MinVersion), version(m.MaxVersion)) > 0 || semver.Compare(version(m.MinVersion), version(m.MaxVersion)) == 0 && (m.MinVersionExclusive || m.MaxVersionExclusive)) {
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
	if t.Confidence < m.Confidence {
		return false, false
	}
	if len(m.CPE) > 0 {
		matched := false
		for _, c := range t.CPE {
			if contains(m.CPE, c) {
				matched = true
				break
			}
		}
		if !matched {
			return false, false
		}
	}
	if m.OnUnknown == "run" && m.missing(t) {
		return m.partialMatch(t), false
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
	if m.MinVersion != "" || m.MaxVersion != "" || len(m.ExcludeVersions) > 0 {
		v := version(t.Version)
		if !semver.IsValid(v) {
			return false, false
		}
		if m.excludesVersion(t.Version) {
			return false, false
		}
		if m.MinVersion != "" && (semver.Compare(v, version(m.MinVersion)) < 0 || m.MinVersionExclusive && semver.Compare(v, version(m.MinVersion)) == 0) {
			return false, false
		}
		if m.MaxVersion != "" && (semver.Compare(v, version(m.MaxVersion)) > 0 || m.MaxVersionExclusive && semver.Compare(v, version(m.MaxVersion)) == 0) {
			return false, false
		}
	}
	if m.BannerRegex != "" && !m.matchesBanner(t.Banner) {
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
			// Once applicability and product evidence are established, later
			// alternatives cannot change either result.
			if ok && identified {
				break
			}
		}
		if !ok {
			return false, false
		}
	}
	return true, identified
}

func (m Match) missing(t Target) bool {
	// Probes fill absent facts; they cannot repair observed contradictions.
	if !m.probePossible(t) {
		return false
	}
	if len(m.CPE) > 0 && len(t.CPE) == 0 || t.Confidence < m.Confidence {
		return true
	}
	if len(m.Services) > 0 && t.Service == "" || len(m.Products) > 0 && t.Product == "" || len(m.Protocols) > 0 && t.Protocol == "" || (m.MinVersion != "" || m.MaxVersion != "" || len(m.ExcludeVersions) > 0) && t.Version == "" || m.BannerRegex != "" && t.Banner == "" {
		return true
	}
	for _, c := range m.AllOf {
		if c.missing(t) {
			return true
		}
	}
	// A satisfied alternative needs no additional identification. Only seek
	// missing facts when no alternative already establishes applicability.
	missingAlternative := false
	for _, c := range m.AnyOf {
		if ok, _ := c.evaluate(t); ok {
			return false
		}
		missingAlternative = missingAlternative || c.missing(t)
	}
	return missingAlternative
}

func (m Match) skipReason(t Target) string {
	if t.Confidence < m.Confidence {
		return "declarative match: identification confidence below script threshold"
	}
	if len(m.Products) > 0 {
		if t.Product == "" {
			return "declarative match: product identification missing"
		}
		if !contains(m.Products, t.Product) {
			return "declarative match: product identification mismatched"
		}
	}
	for _, field := range []struct {
		name     string
		required bool
		missing  bool
		matches  bool
	}{
		{"service", len(m.Services) > 0, t.Service == "", contains(m.Services, t.Service)},
		{"transport", len(m.Protocols) > 0, t.Protocol == "", contains(m.Protocols, t.Protocol)},
		{"version", m.MinVersion != "" || m.MaxVersion != "" || len(m.ExcludeVersions) > 0, t.Version == "", !m.excludesVersion(t.Version) && semver.IsValid(version(t.Version)) && (m.MinVersion == "" || (semver.Compare(version(t.Version), version(m.MinVersion)) > 0 || !m.MinVersionExclusive && semver.Compare(version(t.Version), version(m.MinVersion)) == 0)) && (m.MaxVersion == "" || (semver.Compare(version(t.Version), version(m.MaxVersion)) < 0 || !m.MaxVersionExclusive && semver.Compare(version(t.Version), version(m.MaxVersion)) == 0))},
		{"banner", m.BannerRegex != "", t.Banner == "", m.matchesBanner(t.Banner)},
	} {
		if field.required && !field.matches {
			state := "mismatched"
			if field.missing {
				state = "missing"
			}
			return "declarative match: " + field.name + " identification " + state
		}
	}
	if len(m.CPE) > 0 {
		matched := false
		for _, c := range t.CPE {
			matched = matched || contains(m.CPE, c)
		}
		if !matched {
			if len(t.CPE) == 0 {
				return "declarative match: CPE identification missing"
			}
			return "declarative match: CPE identification mismatched"
		}
	}
	for _, child := range m.AllOf {
		if ok, _ := child.evaluate(t); !ok {
			return child.skipReason(t)
		}
	}
	if len(m.AnyOf) > 0 {
		for _, child := range m.AnyOf {
			if ok, _ := child.evaluate(t); ok {
				return "declarative match: required identification facts missing or mismatched"
			}
		}
		// Every alternative failed. Preserve a specific reason when all
		// alternatives agree; mixed failures require the general diagnostic.
		reason := m.AnyOf[0].skipReason(t)
		for _, child := range m.AnyOf[1:] {
			if child.skipReason(t) != reason {
				return "declarative match: required identification facts missing or mismatched"
			}
		}
		return reason
	}
	return "declarative match: required identification facts missing or mismatched"
}

// prepare owns compiled expressions within an index snapshot. Expressions are
// immutable and safe for concurrent selection; mutable match trees are not shared.
func (m *Match) prepare() {
	if m.BannerRegex != "" {
		m.bannerPattern = regexp.MustCompile(m.BannerRegex)
	}
	for i := range m.AnyOf {
		m.AnyOf[i].prepare()
	}
	for i := range m.AllOf {
		m.AllOf[i].prepare()
	}
}

func (m Match) matchesBanner(banner string) bool {
	p := m.bannerPattern
	if p == nil || p.String() != m.BannerRegex {
		var err error
		p, err = regexp.Compile(m.BannerRegex)
		if err != nil {
			return false
		}
	}
	return p.MatchString(banner)
}

// partialMatch permits absent facts, but never overrides observed contradictions.
// Evaluate the same field predicates after removing only unavailable facts.
func (m Match) partialMatch(t Target) bool {
	m.OnUnknown = ""
	if t.Service == "" {
		m.Services = nil
	}
	if t.Product == "" {
		m.Products = nil
	}
	if t.Protocol == "" {
		m.Protocols = nil
	}
	if t.Version == "" {
		m.MinVersion, m.MaxVersion = "", ""
		m.ExcludeVersions = nil
	}
	if t.Banner == "" {
		m.BannerRegex = ""
	}
	all, any := m.AllOf, m.AnyOf
	m.AllOf, m.AnyOf = nil, nil
	if ok, _ := m.evaluate(t); !ok {
		return false
	}
	for _, child := range all {
		if !child.partialMatch(t) {
			return false
		}
	}
	if len(any) > 0 {
		for _, child := range any {
			if child.partialMatch(t) {
				return true
			}
		}
		return false
	}
	return true
}

// probePossible retains observed constraints while allowing missing identity facts.
func (m Match) probePossible(t Target) bool {
	local := m
	local.AllOf, local.AnyOf = nil, nil
	local.Confidence = 0
	if len(t.CPE) == 0 {
		local.CPE = nil
	}
	if !local.partialMatch(t) {
		return false
	}
	for _, child := range m.AllOf {
		if !child.probePossible(t) {
			return false
		}
	}
	if len(m.AnyOf) > 0 {
		for _, child := range m.AnyOf {
			if child.probePossible(t) {
				return true
			}
		}
		return false
	}
	return true
}

func (m Match) excludesVersion(v string) bool {
	for _, excluded := range m.ExcludeVersions {
		if semver.Compare(version(v), version(excluded)) == 0 {
			return true
		}
	}
	return false
}

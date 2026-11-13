// Package pingpp adapts ping++ scan documents to caller-supplied Scribe facts.
// Schema reference: SiriusScan/pingpp PR #1, ff4085905039cbbc759a0a75fab897b49316ef1a.
package pingpp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/SiriusScan/scribe"
)

// SchemaVersion is the supported ping++ wire schema.
const SchemaVersion = "pingpp.scan/v1"

// Document contains the endpoint facts consumed from the versioned wire schema.
// Unused upstream evidence is deliberately not interpreted as a verdict.
type Document struct {
	// SchemaVersion must equal pingpp.scan/v1; empty is invalid.
	SchemaVersion string `json:"schema_version"`
	// Error is raw upstream error JSON; absent or null means no reported error.
	Error json.RawMessage `json:"error"`
	// Asset contains endpoint and identity evidence; nil is invalid.
	Asset *struct {
		// Endpoints contains discovered endpoints; nil selects none.
		Endpoints []Endpoint `json:"endpoints"`
		// Claims contains optional identity assertions; nil supplies no identity.
		Claims []Claim `json:"claims"`
	} `json:"asset"`
}

// Endpoint records a discovery endpoint and its execution state.
type Endpoint struct {
	// Address must be an IP literal; empty is invalid.
	Address string `json:"address"`
	// Port is the transport port; zero is invalid.
	Port uint16 `json:"port"`
	// Transport must be tcp or udp; empty is invalid.
	Transport string `json:"transport"`
	// State must be open for selection; empty is invalid.
	State string `json:"state"`
	// Execution must be attempted for selection; empty is ineligible.
	Execution string `json:"execution"`
}

// Claim carries an endpoint identity assertion and contradiction references.
type Claim struct {
	// Subject identifies the endpoint claim subject; empty does not identify an endpoint.
	Subject string `json:"subject"`
	// Kind identifies protocol, service or product evidence; empty is ignored.
	Kind string `json:"kind"`
	// Product contains asserted product identity; empty provides none.
	Product string `json:"product"`
	// Value contains the asserted claim value; empty provides none.
	Value string `json:"value"`
	// CPE contains the upstream product CPE hint; empty supplies none.
	CPE string `json:"cpe"`
	// Version contains asserted product version text; empty is unknown.
	Version string `json:"version"`
	// Confidence must be exact or strong to accept identity; empty supplies none.
	Confidence string `json:"confidence"`
	// ContradictionIDs references contradictory claims; nil supplies none.
	ContradictionIDs []string `json:"contradiction_ids"`
}

// Targets returns only confirmed open, attempted endpoints. Conflicting claims
// leave the corresponding fact unknown; host-wide claims never identify a port.
func Targets(d Document) ([]scribe.Target, error) {
	if d.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported ping++ schema %q", boundedDiagnostic(d.SchemaVersion))
	}
	if len(d.Error) > 0 && string(d.Error) != "null" {
		return nil, fmt.Errorf("ping++ target error: %s", boundedDiagnostic(string(d.Error)))
	}
	if d.Asset == nil {
		return nil, fmt.Errorf("ping++ document missing asset")
	}
	if len(d.Asset.Endpoints) > 65536 || len(d.Asset.Claims) > 262144 {
		return nil, fmt.Errorf("ping++ document exceeds endpoint (65536) or claim (262144) limit")
	}
	seen := make(map[string]bool, len(d.Asset.Endpoints))
	for _, e := range d.Asset.Endpoints {
		ip := net.ParseIP(e.Address)
		if ip == nil || e.Port == 0 || (e.Transport != "tcp" && e.Transport != "udp") {
			return nil, fmt.Errorf("invalid ping++ endpoint address=%q port=%d transport=%q", boundedDiagnostic(e.Address), e.Port, boundedDiagnostic(e.Transport))
		}
		key := fmt.Sprintf("%s/%s/%d", ip.String(), e.Transport, e.Port)
		if seen[key] {
			return nil, fmt.Errorf("duplicate ping++ endpoint %q", key)
		}
		seen[key] = true
		switch e.State {
		case "open", "closed", "filtered", "responsive", "unknown":
		default:
			return nil, fmt.Errorf("invalid ping++ endpoint state %q", boundedDiagnostic(e.State))
		}
	}
	// Index once so multi-endpoint documents do not repeatedly scan all claims.
	// One-based links reserve zero as the chain terminator. Claim reduction
	// is order independent; reverse chains avoid per-subject slice growth.
	claims := make(map[string]int)
	next := make([]int, len(d.Asset.Claims))
	for i := range d.Asset.Claims {
		c := &d.Asset.Claims[i]
		// Reject unusable evidence before canonicalizing subjects or growing the
		// index. Reduction retains its checks as defense for future index users.
		if (c.Confidence != "exact" && c.Confidence != "strong") || len(c.ContradictionIDs) > 0 {
			continue
		}
		if c.Kind != "protocol" && c.Kind != "service" && c.Kind != "product" {
			continue
		}
		if key, ok := canonicalSubject(c.Subject); ok && seen[key] {
			next[i] = claims[key]
			claims[key] = i + 1
		}
	}
	var out []scribe.Target
	for _, e := range d.Asset.Endpoints {
		ip := net.ParseIP(e.Address)
		key := fmt.Sprintf("%s/%s/%d", ip.String(), e.Transport, e.Port)
		if e.State != "open" || e.Execution != "attempted" {
			continue
		}
		t := scribe.Target{Host: ip.String(), IP: ip.String(), Port: e.Port, Protocol: e.Transport, State: "open"}
		// Use the same canonical endpoint identity for claims and duplicate checks.
		services := map[string]bool{}
		products := map[string]string{}
		conflict := false
		productConfidence := 0.0
		cpes := map[string]bool{}
		transportConflict := false
		for entry := claims[key]; entry != 0; entry = next[entry-1] {
			c := &d.Asset.Claims[entry-1]
			if (c.Confidence != "exact" && c.Confidence != "strong") || len(c.ContradictionIDs) > 0 {
				continue
			}
			v := c.Value
			if v == "" {
				v = c.Product
			}
			switch c.Kind {
			case "protocol", "service":
				if v == "tcp" || v == "udp" {
					if v != e.Transport {
						transportConflict = true
					}
					continue
				}
				if base := implicitTLSService(v); base != "" {
					if e.Transport != "tcp" {
						transportConflict = true
					}
					t.TLS = true
					services[base] = true
					continue
				}
				if v == "tls" {
					// TLS claims describe TCP TLS, never DTLS or QUIC.
					if e.Transport != "tcp" {
						transportConflict = true
					}
					t.TLS = true
				} else if v != "" {
					services[v] = true
				}
			case "product":
				if c.Product != "" {
					if c.CPE != "" {
						cpes[c.CPE] = true
					}
					confidence := 0.8 // Adapter policy: strong identity evidence.
					if c.Confidence == "exact" {
						confidence = 1
					}
					if confidence > productConfidence {
						productConfidence = confidence
					}
					if old, ok := products[c.Product]; ok && old != "" && c.Version != "" && old != c.Version {
						conflict = true
					}
					if c.Version != "" || products[c.Product] == "" {
						products[c.Product] = c.Version
					}
				}
			}
		}
		if transportConflict || len(services) > 1 {
			// Contradictory transport or service evidence cannot establish endpoint identity.
			t.TLS = false
			out = append(out, t)
			continue
		}
		if len(services) == 1 {
			for s := range services {
				t.Service = s
			}
		}
		// Version disagreements do not contradict an otherwise agreed product.
		if len(products) == 1 {
			for p, v := range products {
				t.Product = p
				t.Confidence = productConfidence
				if !conflict {
					t.Version = v
					for cpe := range cpes {
						t.CPE = append(t.CPE, cpe)
					}
					sort.Strings(t.CPE)
				}
			}
		}
		if err := t.Validate(); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// canonicalSubject accepts only exact endpoint subjects, never host-wide claims.
func canonicalSubject(subject string) (string, bool) {
	address, rest, ok := strings.Cut(subject, "/")
	transport, portText, complete := strings.Cut(rest, "/")
	if !ok || !complete || (transport != "tcp" && transport != "udp") {
		return "", false
	}
	ip := net.ParseIP(address)
	port, err := strconv.ParseUint(portText, 10, 16)
	if ip == nil || err != nil || port == 0 || portText[0] == '0' || portText[0] == '+' {
		return "", false
	}
	canonical := ip.String()
	if canonical == address {
		return subject, true
	}
	return canonical + "/" + rest, true
}

// boundedDiagnostic limits untrusted details before formatting can expand them.
func boundedDiagnostic(detail string) string {
	const limit = 1024
	if len(detail) > limit {
		return detail[:limit] + "... (truncated)"
	}
	return detail
}

// Reader reads bounded JSONL documents and exposes a RunTargetStream producer.
// The caller owns the input and must arrange interruption of blocking reads.
// The zero Reader is not usable; initialize it with NewReader.
type Reader struct {
	scan    *bufio.Scanner
	pending []scribe.Target
	lines   int
	err     error
}

// NewReader creates a bounded JSONL reader over caller-owned input.
func NewReader(r io.Reader) *Reader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 4<<20)
	return &Reader{scan: s}
}

// Next returns the next eligible endpoint, or false at end of input. The caller owns interruption of blocking reads.
func (r *Reader) Next(ctx context.Context) (scribe.Target, bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return scribe.Target{}, false, err
		}
		if r.err != nil {
			r.scan = nil
			return scribe.Target{}, false, r.err
		}
		if len(r.pending) > 0 {
			t := r.pending[0]
			r.pending[0] = scribe.Target{}
			r.pending = r.pending[1:]
			if len(r.pending) == 0 {
				r.pending = nil
			}
			return t, true, nil
		}
		if r.scan == nil {
			return scribe.Target{}, false, nil
		}
		if !r.scan.Scan() {
			r.err = r.scan.Err()
			r.scan = nil
			if r.err == nil && r.lines == 0 {
				r.err = fmt.Errorf("empty ping++ stream")
			}
			return scribe.Target{}, false, r.err
		}
		r.lines++
		if r.lines > 65536 {
			r.err = fmt.Errorf("ping++ stream exceeds 65536 documents")
			continue
		}
		var d Document
		err := validateWire(r.scan.Bytes())
		if err == nil {
			err = json.Unmarshal(r.scan.Bytes(), &d)
		}
		if err == nil {
			r.pending, err = Targets(d)
		}
		if err != nil {
			r.err = fmt.Errorf("ping++ line %d: %s", r.lines, boundedDiagnostic(err.Error()))
		}
	}
}

// implicitTLSService maps explicit implicit-TLS identities, never STARTTLS hints.
func implicitTLSService(service string) string {
	switch service {
	case "wss":
		return "ws"
	case "https":
		return "http"
	case "imaps":
		return "imap"
	case "pop3s":
		return "pop3"
	case "smtps":
		return "smtp"
	case "ldaps":
		return "ldap"
	case "ftps":
		return "ftp"
	case "nntps":
		return "nntp"
	case "mqtts":
		return "mqtt"
	case "rediss":
		return "redis"
	default:
		return ""
	}
}

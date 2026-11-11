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

	"github.com/SiriusScan/scribe"
)

const SchemaVersion = "pingpp.scan/v1"

// Document contains the endpoint facts consumed from the versioned wire schema.
// Unused upstream evidence is deliberately not interpreted as a verdict.
type Document struct {
	SchemaVersion string          `json:"schema_version"`
	Error         json.RawMessage `json:"error"`
	Asset         *struct {
		Endpoints []Endpoint `json:"endpoints"`
		Claims    []Claim    `json:"claims"`
	} `json:"asset"`
}
type Endpoint struct {
	Address   string `json:"address"`
	Port      uint16 `json:"port"`
	Transport string `json:"transport"`
	State     string `json:"state"`
	Execution string `json:"execution"`
}
type Claim struct {
	Subject          string   `json:"subject"`
	Kind             string   `json:"kind"`
	Product          string   `json:"product"`
	Value            string   `json:"value"`
	Version          string   `json:"version"`
	Confidence       string   `json:"confidence"`
	ContradictionIDs []string `json:"contradiction_ids"`
}

// Targets returns only confirmed open, attempted endpoints. Conflicting claims
// leave the corresponding fact unknown; host-wide claims never identify a port.
func Targets(d Document) ([]scribe.Target, error) {
	if d.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported ping++ schema %q", d.SchemaVersion)
	}
	if len(d.Error) > 0 && string(d.Error) != "null" {
		return nil, fmt.Errorf("ping++ target error: %s", d.Error)
	}
	if d.Asset == nil {
		return nil, fmt.Errorf("ping++ document missing asset")
	}
	var out []scribe.Target
	for _, e := range d.Asset.Endpoints {
		if net.ParseIP(e.Address) == nil || e.Port == 0 || (e.Transport != "tcp" && e.Transport != "udp") {
			return nil, fmt.Errorf("invalid ping++ endpoint %+v", e)
		}
		switch e.State {
		case "open", "closed", "filtered", "responsive", "unknown":
		default:
			return nil, fmt.Errorf("invalid ping++ endpoint state %q", e.State)
		}
		if e.State != "open" || e.Execution != "attempted" {
			continue
		}
		t := scribe.Target{Host: e.Address, IP: e.Address, Port: e.Port, Protocol: e.Transport, State: "open"}
		key := fmt.Sprintf("%s/%s/%d", e.Address, e.Transport, e.Port)
		services := map[string]bool{}
		products := map[string]string{}
		conflict := false
		for _, c := range d.Asset.Claims {
			if c.Subject != key || (c.Confidence != "exact" && c.Confidence != "strong") || len(c.ContradictionIDs) > 0 {
				continue
			}
			v := c.Value
			if v == "" {
				v = c.Product
			}
			switch c.Kind {
			case "protocol", "service":
				if v == "tls" {
					t.TLS = true
				} else if v != "" {
					services[v] = true
				}
			case "product":
				if c.Product != "" {
					if old, ok := products[c.Product]; ok && old != c.Version {
						conflict = true
					}
					products[c.Product] = c.Version
				}
			}
		}
		if len(services) == 1 {
			for s := range services {
				t.Service = s
			}
		}
		if len(products) == 1 && !conflict {
			for p, v := range products {
				t.Product = p
				t.Version = v
			}
		}
		if err := t.Validate(); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// Reader reads bounded JSONL documents and exposes a RunTargetStream producer.
// The caller owns the input and must arrange interruption of blocking reads.
type Reader struct {
	scan    *bufio.Scanner
	pending []scribe.Target
	lines   int
	err     error
}

func NewReader(r io.Reader) *Reader {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 4096), 4<<20)
	return &Reader{scan: s}
}
func (r *Reader) Next(ctx context.Context) (scribe.Target, bool, error) {
	for {
		if err := ctx.Err(); err != nil {
			return scribe.Target{}, false, err
		}
		if r.err != nil {
			return scribe.Target{}, false, r.err
		}
		if len(r.pending) > 0 {
			t := r.pending[0]
			r.pending = r.pending[1:]
			return t, true, nil
		}
		if !r.scan.Scan() {
			r.err = r.scan.Err()
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
		err := json.Unmarshal(r.scan.Bytes(), &d)
		if err == nil {
			r.pending, err = Targets(d)
		}
		if err != nil {
			r.err = fmt.Errorf("ping++ line %d: %w", r.lines, err)
		}
	}
}

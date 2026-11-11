package scribe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Hints are optional selection alternatives. Protocol constrains all alternatives.
type Hints struct {
	Services  []string `json:"services"`
	Products  []string `json:"products"`
	Ports     []uint16 `json:"ports"`
	Protocols []string `json:"protocols"`
}
type indexedScript struct {
	script Script
	hints  Hints
}

// Index caches script-declared metadata and owns a snapshot of source bytes.
// Declare metadata on one line: -- scribe: {"services":["http"],"ports":[80]}
// Scripts without hints and endpoints without identifying facts run conservatively.
type Index struct{ entries []indexedScript }

func NewIndex(scripts []Script) (*Index, error) {
	idx := &Index{}
	for _, s := range scripts {
		if s.ID == "" || len(s.Source) == 0 || len(s.Source) > MaxSourceBytes || (s.Dialect != Sirius && s.Dialect != NSE) {
			return nil, fmt.Errorf("invalid script %q", s.ID)
		}
		var h Hints
		found := false
		for _, line := range strings.Split(string(s.Source), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-- scribe:") {
				if found {
					return nil, fmt.Errorf("duplicate metadata: %s", s.ID)
				}
				found = true
				dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(strings.TrimPrefix(line, "-- scribe:"))))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&h); err != nil {
					return nil, fmt.Errorf("%s: %w", s.ID, err)
				}
			}
		}
		s.Source = append([]byte(nil), s.Source...)
		idx.entries = append(idx.entries, indexedScript{s, h})
	}
	return idx, nil
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}
func (h Hints) matches(t Target) bool {
	if t.Protocol != "" && len(h.Protocols) > 0 && !contains(h.Protocols, t.Protocol) {
		return false
	}
	if len(h.Services)+len(h.Products)+len(h.Ports) == 0 {
		return true
	}
	if t.Port == 0 && t.Service == "" && t.Product == "" {
		return true
	}
	if contains(h.Services, t.Service) && t.Service != "" || contains(h.Products, t.Product) && t.Product != "" {
		return true
	}
	for _, p := range h.Ports {
		if p == t.Port {
			return true
		}
	}
	// Missing facts for a declared category cannot exclude its scripts.
	return len(h.Services) > 0 && t.Service == "" || len(h.Products) > 0 && t.Product == "" || len(h.Ports) > 0 && t.Port == 0
}

// Select returns owned source snapshots; selection does not establish a verdict.
func (idx *Index) Select(t Target) []Script {
	var out []Script
	for _, e := range idx.entries {
		if e.hints.matches(t) {
			s := e.script
			s.Source = append([]byte(nil), s.Source...)
			out = append(out, s)
		}
	}
	return out
}

// RunSelected expands matching scripts across supplied endpoints using Run's bounded pool.
func (e *Engine) RunSelected(ctx context.Context, idx *Index, targets []Target, sink func(Result) error) error {
	if idx == nil {
		return fmt.Errorf("index is required")
	}
	var tasks []Task
	for _, t := range targets {
		if err := t.Validate(); err != nil {
			return err
		}
		for _, s := range idx.Select(t) {
			tasks = append(tasks, Task{Script: s, Target: t})
		}
	}
	return e.Run(ctx, tasks, sink)
}

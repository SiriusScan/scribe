package scribe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// selectionHints are optional selection alternatives. Protocol constrains all alternatives.
type selectionHints struct {
	Match     *Match   `json:"match,omitempty"`
	Services  []string `json:"services"`
	Products  []string `json:"products"`
	Ports     []uint16 `json:"ports"`
	Protocols []string `json:"protocols"`
}
type indexedScript struct {
	script Script
	hints  selectionHints
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
		var h selectionHints
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
		if h.Match != nil {
			if err := h.Match.validate(0); err != nil {
				return nil, fmt.Errorf("%s: %w", s.ID, err)
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
func (h selectionHints) matches(t Target) bool {
	if h.Match != nil {
		ok, _ := h.Match.evaluate(t)
		return ok
	}
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

// Matches reports whether any indexed script matches supplied facts, without
// copying source or constructing an interpreter.
func (idx *Index) Matches(t Target) bool {
	for _, e := range idx.entries {
		if e.hints.matches(t) {
			return true
		}
	}
	return false
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

// RunSelected schedules indexed scripts across supplied endpoints. Hint exclusions
// emit skipped records. Cancellation drains all pairs from this known target slice.
func (e *Engine) RunSelected(ctx context.Context, idx *Index, targets []Target, sink func(Result) error) error {
	if idx == nil {
		return fmt.Errorf("index is required")
	}
	for _, t := range targets {
		if err := t.Validate(); err != nil {
			return err
		}
	}
	next := 0
	return e.runTargets(ctx, idx, func(context.Context) (Target, bool, error) {
		if next == len(targets) {
			return Target{}, false, nil
		}
		t := targets[next]
		next++
		return t, true, nil
	}, sink, true)
}

// RunTargetStream consumes targets with bounded task lookahead. Every script /
// endpoint pair emits a record, including hint exclusions with a skip reason.
// The producer must honor ctx; false signals EOF. On cancellation only accepted
// pairs emit terminal records; unread input has never been submitted.
func (e *Engine) RunTargetStream(ctx context.Context, idx *Index, next func(context.Context) (Target, bool, error), sink func(Result) error) error {
	return e.runTargets(ctx, idx, next, sink, false)
}

func (e *Engine) runTargets(ctx context.Context, idx *Index, next func(context.Context) (Target, bool, error), sink func(Result) error, drain bool) error {
	if ctx == nil || idx == nil || next == nil || sink == nil {
		return fmt.Errorf("context, index, target producer and sink are required")
	}
	cache := make(probeCache)
	var target Target
	pos := len(idx.entries)
	return e.run(ctx, func(ctx context.Context) (Task, bool, error) {
		if pos == len(idx.entries) {
			t, ok, err := next(ctx)
			if err != nil || !ok {
				return Task{}, ok, err
			}
			if err := t.Validate(); err != nil {
				return Task{}, false, err
			}
			for _, entry := range idx.entries {
				if m := entry.hints.Match; m != nil && m.OnUnknown == "probe" && m.missing(t) {
					t = cache.enrich(ctx, t, e.options.MaxHosts)
					break
				}
			}
			target = t
			pos = 0
		}
		if len(idx.entries) == 0 {
			return Task{}, false, fmt.Errorf("index must contain scripts")
		}
		entry := idx.entries[pos]
		pos++
		t := Task{Script: entry.script, Target: target}
		if !entry.hints.matches(target) {
			t.plannerExcluded = true
			if !e.options.Exhaustive {
				t.planSkip = "script hints exclude supplied endpoint facts"
			}
		}
		return t, true, nil
	}, sink, drain)
}

// CheckIdentification checks whether metadata declares a product identification.
// Runtime facts must still match before a strict clean verdict is accepted.
func CheckIdentification(s Script) error {
	idx, err := NewIndex([]Script{s})
	if err != nil {
		return err
	}
	h := idx.entries[0].hints
	var declared func(Match) bool
	declared = func(m Match) bool {
		if len(m.Products) > 0 {
			return true
		}
		for _, g := range [][]Match{m.AnyOf, m.AllOf} {
			for _, c := range g {
				if declared(c) {
					return true
				}
			}
		}
		return false
	}
	if len(h.Products) > 0 || h.Match != nil && declared(*h.Match) {
		return nil
	}
	return fmt.Errorf("clean verdict requires declared product identification")
}

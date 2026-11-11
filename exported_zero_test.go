package scribe

import (
	"context"
	"math"
	"testing"
)

func TestTargetConfidenceDomain(t *testing.T) {
	for _, confidence := range []float64{-1, 1.01, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if err := (Target{Host: "localhost", Confidence: confidence}).Validate(); err == nil {
			t.Errorf("accepted confidence %v", confidence)
		}
	}
	for _, confidence := range []float64{0, .5, 1} {
		if err := (Target{Host: "localhost", Confidence: confidence}).Validate(); err != nil {
			t.Errorf("rejected confidence %v: %v", confidence, err)
		}
	}
}

func TestAuditedOptionsDefaultsAndRejections(t *testing.T) {
	// A runtime is required even when checking orchestration defaults.
	runtime := auditRuntime{}
	e, err := New(Options{}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if e.options.Concurrency != 4 || e.options.HostConcurrency != 4 || e.options.Window != 256 || e.options.MaxHosts != 65536 || e.options.Strategy != ScriptSpray {
		t.Fatalf("defaults: %+v", e.options)
	}
	for _, o := range []Options{{Concurrency: -1}, {HostConcurrency: -1}, {Window: -1}, {MaxHosts: -1}, {ScriptTimeout: -1}, {GlobalInterval: -1}, {HostInterval: -1}, {HostErrorBudget: -1}, {Strategy: "invalid"}} {
		if _, err := New(o, runtime); err == nil {
			t.Errorf("accepted invalid options %+v", o)
		}
	}
}

type auditRuntime struct{}

func (auditRuntime) Dialect() Dialect                              { return Sirius }
func (auditRuntime) Execute(context.Context, Task) (Output, error) { return Output{}, nil }

func TestAuditedMatchZeroAndInclusiveBounds(t *testing.T) {
	if err := (Match{}).validate(0); err != nil {
		t.Fatal(err)
	}
	if ok, identified := (Match{}).evaluate(Target{}); !ok || identified {
		t.Fatalf("zero match: %v %v", ok, identified)
	}
	m := Match{Products: []string{"example"}, MinVersion: "1.0.0", MaxVersion: "2.0.0", Ports: []uint16{443}}
	for _, v := range []string{"1.0.0", "2.0.0"} {
		if ok, id := m.evaluate(Target{Product: "example", Version: v, Port: 80}); !ok || !id {
			t.Errorf("inclusive/advisory match failed for %s", v)
		}
	}
	for _, v := range []string{"", "0.9.0", "2.0.1"} {
		if ok, _ := m.evaluate(Target{Product: "example", Version: v}); ok {
			t.Errorf("accepted version %q", v)
		}
	}
}

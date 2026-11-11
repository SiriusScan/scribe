package scribe

import (
	"context"
	"testing"
)

func TestUnknownPolicies(t *testing.T) {
	for _, policy := range []string{"run", "probe", "skip"} {
		m := Match{Products: []string{"OpenSSH"}, OnUnknown: policy}
		if err := m.validate(0); err != nil {
			t.Fatal(err)
		}
		ok, id := m.evaluate(Target{})
		if ok != (policy == "run") || id {
			t.Fatalf("%s: %v %v", policy, ok, id)
		}
	}
	if (Match{OnUnknown: "invalid"}).validate(0) == nil {
		t.Fatal("accepted invalid policy")
	}
}
func TestProbeMergePreservesFacts(t *testing.T) {
	got := mergeProbe(Target{Product: "known", Version: "1"}, Target{Product: "other", Version: "2", Service: "ssh"})
	if got.Product != "known" || got.Version != "1" || got.Service != "ssh" {
		t.Fatal(got)
	}
}

func TestStrictLegacy(t *testing.T) {
	task := Task{Script: Script{ID: "legacy", Dialect: Sirius, Source: []byte("-- legacy")}, Target: Target{Host: "localhost"}}
	for _, strict := range []bool{false, true} {
		e, _ := New(Options{StrictIdentification: strict}, cleanMatchRuntime{})
		r := e.execute(context.Background(), task)
		if (r.Verdict == NotVulnerable) == strict {
			t.Fatalf("strict=%v: %+v", strict, r)
		}
	}
}
func TestExhaustiveMiss(t *testing.T) {
	e, _ := New(Options{Exhaustive: true}, cleanMatchRuntime{})
	s := Script{ID: "legacy", Dialect: Sirius, Source: []byte("-- scribe: {\"services\":[\"ssh\"]}")}
	idx, err := NewIndex([]Script{s})
	if err != nil {
		t.Fatal(err)
	}
	err = e.RunSelected(context.Background(), idx, []Target{{Host: "localhost", Service: "http"}}, func(r Result) error {
		if !r.PlannerMiss {
			t.Fatalf("%+v", r)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestProbeConflictingIdentityEvidence(t *testing.T) {
	for _, product := range []string{"nginx", "Apache"} {
		got := mergeProbe(Target{Product: product}, Target{Product: "nginx", Confidence: .9, CPE: []string{"cpe:/a:nginx:nginx"}})
		if product == "nginx" {
			if got.Confidence != .9 || len(got.CPE) != 1 {
				t.Fatalf("matching evidence lost: %+v", got)
			}
		} else if got.Confidence != 0 || len(got.CPE) != 0 {
			t.Fatalf("conflicting evidence promoted: %+v", got)
		}
	}
}

func FuzzProbeIdentityAuthority(f *testing.F) {
	f.Add("Apache", "nginx", .9)
	f.Add("nginx", "nginx", .5)
	f.Fuzz(func(t *testing.T, supplied, probed string, confidence float64) {
		if len(supplied) > 256 || len(probed) > 256 {
			t.Skip()
		}
		got := mergeProbe(Target{Product: supplied, Version: "caller"}, Target{Product: probed, Version: "probe", Confidence: confidence, CPE: []string{"probe"}})
		if supplied != "" && got.Product != supplied {
			t.Fatal("replaced caller product")
		}
		if got.Version != "caller" {
			t.Fatal("replaced caller version")
		}
	})
}

func TestProductSkipReasonsAndCleanGuard(t *testing.T) {
	m := Match{Products: []string{"nginx"}}
	for _, tc := range []struct{ product, reason string }{{"", "declarative match: product identification missing"}, {"Apache", "declarative match: product identification mismatched"}} {
		if got := m.skipReason(Target{Product: tc.product}); got != tc.reason {
			t.Fatalf("%q", got)
		}
		if ok, id := m.evaluate(Target{Product: tc.product}); ok || id {
			t.Fatal("unrelated identity admitted")
		}
	}
}

package scribe

import (
	"context"
	"testing"
)

func TestExcludedPortsPolicy(t *testing.T) {
	for _, policy := range []string{"", "run", "probe", "skip"} {
		m := Match{ExcludePorts: []uint16{443}, Products: []string{"example"}, OnUnknown: policy}
		blocked := Target{Port: 443}
		if ok, id := m.evaluate(blocked); ok || id || m.missing(blocked) || m.probePossible(blocked) {
			t.Fatalf("excluded endpoint eligible under %q", policy)
		}
		if got := m.skipReason(blocked); got != "declarative match: port explicitly excluded" {
			t.Fatal(got)
		}
		allowed := Target{Port: 8443, Product: "example"}
		if ok, id := m.evaluate(allowed); !ok || !id {
			t.Fatal("allowed endpoint lost")
		}
		nested := Match{AnyOf: []Match{m, {Products: []string{"other"}}}}
		if ok, _ := nested.evaluate(Target{Port: 443, Product: "example"}); ok {
			t.Fatal("excluded alternative matched")
		}
		if ok, id := nested.evaluate(Target{Port: 443, Product: "other"}); !ok || !id {
			t.Fatal("independent alternative excluded")
		}
	}
	for _, ports := range [][]uint16{{0}, make([]uint16, 65)} {
		if err := (Match{ExcludePorts: ports}).validate(0); err == nil {
			t.Fatal("invalid exclusions accepted")
		}
	}
}

func TestExcludedPortExecution(t *testing.T) {
	for _, exhaustive := range []bool{false, true} {
		e, err := New(Options{Exhaustive: exhaustive}, cleanMatchRuntime{})
		if err != nil {
			t.Fatal(err)
		}
		for _, port := range []uint16{443, 8443} {
			r := e.execute(context.Background(), Task{Script: Script{ID: "ports", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"products":["widget"],"exclude_ports":[443]}}`)}, Target: Target{Host: "localhost", Port: port, Product: "widget"}})
			if port == 8443 {
				if r.Verdict != NotVulnerable {
					t.Fatalf("%+v", r)
				}
			} else {
				if r.Verdict != Unknown {
					t.Fatalf("%+v", r)
				}
				if !exhaustive && r.Output.SkipReason != "declarative match: port explicitly excluded" {
					t.Fatalf("%+v", r)
				}
			}
		}
	}
}

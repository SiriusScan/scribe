package scribe

import (
	"context"
	"testing"
)

func TestExcludedServicesPolicy(t *testing.T) {
	for _, policy := range []string{"", "run", "probe", "skip"} {
		m := Match{ExcludeServices: []string{"example"}, Services: []string{"example"}, OnUnknown: policy}
		blocked := Target{Service: "example"}
		m.Services = []string{"allowed"}
		if ok, id := m.evaluate(blocked); ok || id || m.missing(blocked) || m.probePossible(blocked) {
			t.Fatalf("excluded endpoint eligible under %q", policy)
		}
		if got := m.skipReason(blocked); got != "declarative match: service explicitly excluded" {
			t.Fatal(got)
		}
		allowed := Target{Port: 8443, Service: "allowed"}
		m.Services = []string{"allowed"}
		if ok, id := m.evaluate(allowed); !ok || id {
			t.Fatal("allowed endpoint lost")
		}
		nested := Match{AnyOf: []Match{m, {Services: []string{"other"}}}}
		if ok, _ := nested.evaluate(Target{Port: 443, Service: "example"}); ok {
			t.Fatal("excluded alternative matched")
		}
		if ok, id := nested.evaluate(Target{Port: 443, Service: "other"}); !ok || id {
			t.Fatal("independent alternative excluded")
		}
	}
}

func TestExcludedServiceExecution(t *testing.T) {
	for _, exhaustive := range []bool{false, true} {
		e, err := New(Options{Exhaustive: exhaustive}, cleanMatchRuntime{})
		if err != nil {
			t.Fatal(err)
		}
		for _, port := range []uint16{443, 8443} {
			r := e.execute(context.Background(), Task{Script: Script{ID: "ports", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"products":["widget"],"services":["widget"],"exclude_services":["blocked"]}}`)}, Target: Target{Host: "localhost", Port: port, Product: "widget", Service: map[uint16]string{443: "blocked", 8443: "widget"}[port]}})
			if port == 8443 {
				if r.Verdict != NotVulnerable {
					t.Fatalf("%+v", r)
				}
			} else {
				if r.Verdict != Unknown {
					t.Fatalf("%+v", r)
				}
				if !exhaustive && r.Output.SkipReason != "declarative match: service explicitly excluded" {
					t.Fatalf("%+v", r)
				}
			}
		}
	}
}

func TestServiceExclusionDoesNotIdentify(t *testing.T) {
	m := Match{ExcludeServices: []string{"blocked"}, OnUnknown: "run"}
	for _, target := range []Target{{}, {Service: "other"}} {
		if ok, identified := m.evaluate(target); !ok || identified {
			t.Fatal("exclusion supplied identification")
		}
	}
	for _, names := range [][]string{{""}, make([]string, 65)} {
		if err := (Match{ExcludeServices: names}).validate(0); err == nil {
			t.Fatal("invalid exclusions accepted")
		}
	}
}

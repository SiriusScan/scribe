package scribe

import (
	"context"
	"testing"
)

func TestExcludedProtocolsPolicy(t *testing.T) {
	for _, policy := range []string{"", "run", "probe", "skip"} {
		m := Match{ExcludeProtocols: []string{"udp"}, Protocols: []string{"udp"}, OnUnknown: policy}
		blocked := Target{Protocol: "udp"}
		m.Protocols = []string{"tcp"}
		if ok, id := m.evaluate(blocked); ok || id || m.missing(blocked) || m.probePossible(blocked) {
			t.Fatalf("excluded endpoint eligible under %q", policy)
		}
		if got := m.skipReason(blocked); got != "declarative match: transport explicitly excluded" {
			t.Fatal(got)
		}
		allowed := Target{Port: 8443, Protocol: "tcp"}
		m.Protocols = []string{"tcp"}
		if ok, id := m.evaluate(allowed); !ok || id {
			t.Fatal("allowed endpoint lost")
		}
		nested := Match{AnyOf: []Match{m, {Protocols: []string{"other"}}}}
		if ok, _ := nested.evaluate(Target{Port: 443, Protocol: "udp"}); ok {
			t.Fatal("excluded alternative matched")
		}
		if ok, id := nested.evaluate(Target{Port: 443, Protocol: "other"}); !ok || id {
			t.Fatal("independent alternative excluded")
		}
	}
}

func TestExcludedProtocolExecution(t *testing.T) {
	for _, exhaustive := range []bool{false, true} {
		e, err := New(Options{Exhaustive: exhaustive}, cleanMatchRuntime{})
		if err != nil {
			t.Fatal(err)
		}
		for _, port := range []uint16{443, 8443} {
			r := e.execute(context.Background(), Task{Script: Script{ID: "ports", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"products":["tcp"],"protocols":["tcp"],"exclude_protocols":["udp"]}}`)}, Target: Target{Host: "localhost", Port: port, Product: "tcp", Protocol: map[uint16]string{443: "udp", 8443: "tcp"}[port]}})
			if port == 8443 {
				if r.Verdict != NotVulnerable {
					t.Fatalf("%+v", r)
				}
			} else {
				if r.Verdict != Unknown {
					t.Fatalf("%+v", r)
				}
				if !exhaustive && r.Output.SkipReason != "declarative match: transport explicitly excluded" {
					t.Fatalf("%+v", r)
				}
			}
		}
	}
}

func TestProtocolExclusionDoesNotIdentify(t *testing.T) {
	m := Match{ExcludeProtocols: []string{"udp"}, OnUnknown: "run"}
	for _, target := range []Target{{}, {Protocol: "other"}} {
		if ok, identified := m.evaluate(target); !ok || identified {
			t.Fatal("exclusion supplied identification")
		}
	}
	for _, names := range [][]string{{""}, make([]string, 65)} {
		if err := (Match{ExcludeProtocols: names}).validate(0); err == nil {
			t.Fatal("invalid exclusions accepted")
		}
	}
}

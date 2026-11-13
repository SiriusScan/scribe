package scribe

import (
	"context"
	"testing"
)

func TestRequiredPorts(t *testing.T) {
	m := Match{RequiredPorts: []uint16{443, 8443}, Products: []string{"widget"}, OnUnknown: "run"}
	for _, port := range []uint16{443, 8443} {
		ok, id := m.evaluate(Target{Port: port, Product: "widget"})
		if !ok || !id {
			t.Fatal("matching identity rejected")
		}
		ok, id = m.evaluate(Target{Port: port})
		if !ok || id {
			t.Fatal("missing identity must remain unidentified")
		}
	}
	target := Target{Port: 80}
	if ok, _ := m.evaluate(target); ok {
		t.Fatal("wrong port accepted")
	}
	if m.missing(target) {
		t.Fatal("wrong port requested probe")
	}
	if m.skipReason(target) != "declarative match: required port mismatched" {
		t.Fatal(m.skipReason(target))
	}
	nested := Match{AnyOf: []Match{m, {RequiredPorts: []uint16{80}, Products: []string{"other"}}}}
	if ok, id := nested.evaluate(Target{Port: 80, Product: "other"}); !ok || !id {
		t.Fatal("alternative rejected")
	}
	for _, bad := range []Match{{RequiredPorts: []uint16{0}}, {RequiredPorts: make([]uint16, 65)}} {
		if bad.validate(0) == nil {
			t.Fatal("invalid ports accepted")
		}
	}
}

func TestRequiredPortExecution(t *testing.T) {
	for _, exhaustive := range []bool{false, true} {
		e, err := New(Options{Exhaustive: exhaustive}, cleanMatchRuntime{})
		if err != nil {
			t.Fatal(err)
		}
		for _, port := range []uint16{443, 8443} {
			r := e.execute(context.Background(), Task{Script: Script{ID: "ports", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"products":["tcp"],"protocols":["tcp"],"required_ports":[8443]}}`)}, Target: Target{Host: "localhost", Port: port, Product: "tcp", Protocol: map[uint16]string{443: "udp", 8443: "tcp"}[port]}})
			if port == 8443 {
				if r.Verdict != NotVulnerable {
					t.Fatalf("%+v", r)
				}
			} else {
				if r.Verdict != Unknown {
					t.Fatalf("%+v", r)
				}
				if !exhaustive && r.Output.SkipReason != "declarative match: required port mismatched" {
					t.Fatalf("%+v", r)
				}
			}
		}
	}
}

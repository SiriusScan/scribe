package scribe

import (
	"context"
	"os"
	"testing"
)

func TestDeclarativeIdentification(t *testing.T) {
	m := Match{Products: []string{"Acme"}, MinVersion: "1.2.0", MaxVersion: "2.0.0", BannerRegex: "Acme", AnyOf: []Match{{Services: []string{"http"}}, {Services: []string{"https"}}}}
	if err := m.validate(0); err != nil {
		t.Fatal(err)
	}
	target := Target{Product: "Acme", Version: "1.5.0", Banner: "Acme server", Service: "http"}
	if ok, id := m.evaluate(target); !ok || !id {
		t.Fatal("expected identified match")
	}
	for _, mutate := range []func(*Target){func(v *Target) { v.Product = "" }, func(v *Target) { v.Version = "garbage" }, func(v *Target) { v.Version = "3.0.0" }, func(v *Target) { v.Banner = "other" }, func(v *Target) { v.Service = "ssh" }} {
		v := target
		mutate(&v)
		if ok, _ := m.evaluate(v); ok {
			t.Fatalf("unexpected match: %+v", v)
		}
	}
	if ok, id := (Match{Ports: []uint16{80}}).evaluate(Target{Port: 999}); !ok || id {
		t.Fatal("ports must neither exclude nor identify")
	}
	if err := (Match{BannerRegex: "["}).validate(0); err == nil {
		t.Fatal("invalid regex accepted")
	}
}

type cleanMatchRuntime struct{}

func (cleanMatchRuntime) Dialect() Dialect { return Sirius }
func (cleanMatchRuntime) Execute(context.Context, Task) (Output, error) {
	return Output{Verdict: NotVulnerable}, nil
}
func TestMatchCleanGate(t *testing.T) {
	e, _ := New(Options{}, cleanMatchRuntime{})
	source, err := os.ReadFile("testdata/matching/acme.lua")
	if err != nil {
		t.Fatal(err)
	}
	for _, product := range []string{"Acme", "", "Other"} {
		task := Task{Script: Script{ID: "fixture", Dialect: Sirius, Source: source}, Target: Target{Host: "localhost", Product: product, Service: "http", Version: "1.5.0"}}
		r := e.execute(context.Background(), task)
		if product == "Acme" {
			if r.Verdict != NotVulnerable {
				t.Fatalf("%+v", r)
			}
		} else if r.Verdict != Unknown || r.Status != Skipped || r.Output.SkipReason == "" {
			t.Fatalf("%+v", r)
		}
	}
	task := Task{Script: Script{ID: "service", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"services":["http"]}}`)}, Target: Target{Host: "localhost", Service: "http"}}
	if r := e.execute(context.Background(), task); r.Verdict != Unknown || r.Status != Skipped {
		t.Fatalf("%+v", r)
	}
}

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

// Identity hints for real service families never authorize a different product's clean result.
func TestServiceCorpusFalseClean(t *testing.T) {
	for _, product := range []string{"Caddy", "OpenResty", "OpenSSH", "Dropbear", "vsftpd", "Pure-FTPd", "Postfix", "Sendmail", "MySQL", "MariaDB", "Redis", "PostgreSQL", "MongoDB", "Apache", "IIS", "Exim", "Dovecot", "ProFTPD", "lighttpd", "Tomcat", "Jetty"} {
		for _, exhaustive := range []bool{false, true} {
			e, err := New(Options{StrictIdentification: true, Exhaustive: exhaustive}, cleanMatchRuntime{})
			if err != nil {
				t.Fatal(err)
			}
			source := []byte(`-- scribe: {"match":{"products":["` + product + `"]}}`)
			for _, supplied := range []string{"", "unrelated", product} {
				r := e.execute(context.Background(), Task{Script: Script{ID: product, Dialect: Sirius, Source: source}, Target: Target{Host: "fixture.invalid", Product: supplied, TLS: true}})
				if supplied == product {
					if r.Verdict != NotVulnerable {
						t.Fatalf("%s: %+v", product, r)
					}
				} else if r.Verdict != Unknown || r.Status != Skipped || r.Output.SkipReason == "" {
					t.Fatalf("%s: %+v", product, r)
				}
			}
		}
	}
}

func TestCombinedMatchBoundaries(t *testing.T) {
	source := []byte(`-- scribe: {"match":{"ports":[80],"services":["http"],"products":["Acme"],"min_version":"1.2.0","max_version":"2.0.0","cpe":["cpe:/a:acme:server"]}}`)
	for _, exhaustive := range []bool{false, true} {
		e, _ := New(Options{Exhaustive: exhaustive}, cleanMatchRuntime{})
		for _, v := range []string{"1.2.0", "2.0.0", "1.1.9", "2.0.1", ""} {
			task := Task{Script: Script{ID: "combined", Dialect: Sirius, Source: source}, Target: Target{Host: "localhost", Port: 999, Service: "http", Product: "Acme", Version: v, CPE: []string{"cpe:/a:acme:server"}}}
			r := e.execute(context.Background(), task)
			valid := v == "1.2.0" || v == "2.0.0"
			if valid && r.Verdict != NotVulnerable {
				t.Fatalf("%+v", r)
			}
			if !valid && (r.Verdict != Unknown || (!exhaustive && r.Output.SkipReason == "")) {
				t.Fatalf("%+v", r)
			}
		}
	}
}

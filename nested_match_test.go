package scribe

import (
	"context"
	"testing"
)

func TestNestedMatcherSelection(t *testing.T) {
	source := []byte("-- scribe: " + `{"match":{"all_of":[{"products":["Acme"]},{"any_of":[{"services":["http"],"all_of":[{"min_version":"1.0.0","max_version":"2.0.0"}]},{"services":["ssh"],"banner_regex":"^Acme"}]}]}}`)
	for _, exhaustive := range []bool{false, true} {
		e, err := New(Options{StrictIdentification: true, Exhaustive: exhaustive}, cleanMatchRuntime{})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			service, version, banner, product string
			match                             bool
		}{
			{"http", "1.0.0", "", "Acme", true},
			{"http", "2.0.0", "", "Acme", true},
			{"http", "", "", "Acme", false},
			{"ssh", "", "", "Acme", false},
			{"", "1.0.0", "", "Acme", false},
			{"http", "2.0.1", "", "Acme", false},
			{"ssh", "", "Acme fixture", "Acme", true},
			{"ssh", "", "Other", "Acme", false},
			{"smtp", "1.0.0", "", "Acme", false},
			{"http", "1.0.0", "", "Other", false},
			{"http", "1.0.0", "", "", false},
		} {
			reason := "declarative match: required identification facts missing or mismatched"
			if tc.service == "" {
				reason = "declarative match: service identification missing"
			} else if tc.service == "smtp" {
				reason = "declarative match: service identification mismatched"
			}
			if tc.product == "Other" {
				reason = "declarative match: product identification mismatched"
			} else if tc.product == "" {
				reason = "declarative match: product identification missing"
			}
			if exhaustive {
				reason = "clean verdict requires a matching declared product identification"
			}
			r := e.execute(context.Background(), Task{Script: Script{ID: "nested", Dialect: Sirius, Source: source}, Target: Target{Host: "fixture", Service: tc.service, Version: tc.version, Banner: tc.banner, Product: tc.product}})
			if tc.match {
				if r.Status != Completed || r.Verdict != NotVulnerable {
					t.Fatalf("%+v: %+v", tc, r)
				}
			} else if r.Verdict != Unknown || r.Status != Skipped || r.Output.SkipReason != reason {
				t.Fatalf("%+v: %+v", tc, r)
			}
		}
	}
}

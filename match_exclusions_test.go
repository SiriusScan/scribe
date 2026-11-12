package scribe

import (
	"context"
	"testing"
)

func TestExcludedVersions(t *testing.T) {
	for _, nested := range []bool{false, true} {
		m := Match{Products: []string{"widget"}, MinVersion: "1.0.0", MaxVersion: "2.0.0", ExcludeVersions: []string{"1.5.0"}}
		if nested {
			m = Match{AllOf: []Match{m}}
		}
		for _, v := range []string{"1.4.0", "1.5.0", "v1.5.0+patched", "1.6.0", ""} {
			target := Target{Product: "widget", Version: v}
			ok, id := m.evaluate(target)
			want := v == "1.4.0" || v == "1.6.0"
			if ok != want || id != want {
				t.Fatalf("%q: %v/%v", v, ok, id)
			}
			if !want {
				reason := "declarative match: version explicitly excluded"
				if v == "" {
					reason = "declarative match: version identification missing"
				}
				if m.skipReason(target) != reason {
					t.Fatal(m.skipReason(target))
				}
				if m.missing(target) != (v == "") {
					t.Fatal("incorrect probe eligibility")
				}
			}
		}
		m.OnUnknown = "run"
		if ok, id := m.evaluate(Target{Product: "widget"}); !ok || id {
			t.Fatal("missing version clean gate")
		}
		if ok, _ := m.evaluate(Target{Product: "widget", Version: "1.5.0"}); ok {
			t.Fatal("excluded release ran")
		}
	}
	for _, values := range [][]string{{""}, {"garbage"}, make([]string, 65)} {
		if (Match{ExcludeVersions: values}).validate(0) == nil {
			t.Fatal("invalid exclusions accepted")
		}
	}
}

func TestExcludedVersionExecution(t *testing.T) {
	source := []byte(`-- scribe: {"match":{"products":["widget"],"exclude_versions":["1.5.0"]}}`)
	for _, exhaustive := range []bool{false, true} {
		e, err := New(Options{Exhaustive: exhaustive}, cleanMatchRuntime{})
		if err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{"1.4.0", "1.5.0", ""} {
			r := e.execute(context.Background(), Task{Script: Script{ID: "exclude", Dialect: Sirius, Source: source}, Target: Target{Host: "localhost", Port: 80, Product: "widget", Version: v}})
			if v == "1.4.0" {
				if r.Verdict != NotVulnerable {
					t.Fatalf("%+v", r)
				}
			} else {
				if !exhaustive && v == "1.5.0" && r.Output.SkipReason != "declarative match: version explicitly excluded" {
					t.Fatalf("excluded execution: %+v", r)
				}
				if r.Verdict != Unknown || (!exhaustive && r.Output.SkipReason == "") {
					t.Fatalf("%+v", r)
				}
			}
		}
	}
}

func TestExcludedVersionAlternativeReasons(t *testing.T) {
	excluded := Match{ExcludeVersions: []string{"1.5.0"}}
	target := Target{Version: "1.5.0"}
	for _, m := range []Match{excluded, {AllOf: []Match{excluded}}, {AnyOf: []Match{excluded, excluded}}} {
		if got := m.skipReason(target); got != "declarative match: version explicitly excluded" {
			t.Fatal(got)
		}
		if ok, id := m.evaluate(target); ok || id || m.missing(target) {
			t.Fatal("excluded version eligible")
		}
	}
	mixed := Match{AnyOf: []Match{excluded, {Services: []string{"ssh"}}}}
	if got := mixed.skipReason(target); got != "declarative match: required identification facts missing or mismatched" {
		t.Fatal(got)
	}
	outside := Match{MaxVersion: "1.0.0"}
	if got := outside.skipReason(target); got != "declarative match: version identification mismatched" {
		t.Fatal(got)
	}
}

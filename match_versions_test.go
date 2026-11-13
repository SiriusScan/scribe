package scribe

import (
	"context"
	"testing"
)

func TestExactVersions(t *testing.T) {
	for _, nested := range []bool{false, true} {
		m := Match{Products: []string{"widget"}, MinVersion: "1.0.0", MaxVersion: "2.0.0", Versions: []string{"1.4.0", "1.6.0"}}
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
				reason := "declarative match: version identification mismatched"
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
		if (Match{Versions: values}).validate(0) == nil {
			t.Fatal("invalid exclusions accepted")
		}
	}
}

func TestExactVersionExecution(t *testing.T) {
	source := []byte(`-- scribe: {"match":{"products":["widget"],"versions":["1.4.0","1.6.0"]}}`)
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
				if !exhaustive && v == "1.5.0" && r.Output.SkipReason != "declarative match: version identification mismatched" {
					t.Fatalf("excluded execution: %+v", r)
				}
				if r.Verdict != Unknown || (!exhaustive && r.Output.SkipReason == "") {
					t.Fatalf("%+v", r)
				}
			}
		}
	}
}

func TestExactVersionsIntersection(t *testing.T) {
	m := Match{Products: []string{"widget"}, Versions: []string{"1.0.0", "2.0.0", "3.0.0"}, MinVersion: "2.0.0", ExcludeVersions: []string{"3.0.0"}}
	for _, v := range []string{"1.0.0", "2.0.0", "3.0.0", "4.0.0"} {
		ok, id := m.evaluate(Target{Product: "widget", Version: v})
		if ok != (v == "2.0.0") || id != ok {
			t.Fatalf("%s: %v/%v", v, ok, id)
		}
	}
}

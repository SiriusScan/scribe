package scribe

import "testing"

func TestExclusiveVersionBounds(t *testing.T) {
	for _, lower := range []bool{false, true} {
		m := Match{Products: []string{"widget"}, MinVersion: "1.0.0", MaxVersion: "2.0.0", MinVersionExclusive: lower, MaxVersionExclusive: !lower}
		if err := m.validate(0); err != nil {
			t.Fatal(err)
		}
		for _, v := range []string{"1.0.0", "1.5.0", "2.0.0", ""} {
			target := Target{Product: "widget", Version: v}
			want := v == "1.5.0" || v == "1.0.0" && !lower || v == "2.0.0" && lower
			ok, id := m.evaluate(target)
			if ok != want || id != want {
				t.Fatalf("lower=%v version=%q got %v/%v", lower, v, ok, id)
			}
			if !ok && v != "" && m.skipReason(target) != "declarative match: version identification mismatched" {
				t.Fatal(m.skipReason(target))
			}
		}
		m.OnUnknown = "run"
		if ok, id := m.evaluate(Target{Product: "widget"}); !ok || id {
			t.Fatal("missing version must run without clean identification")
		}
	}
	for _, m := range []Match{{MinVersionExclusive: true}, {MaxVersionExclusive: true}, {MinVersion: "1.0.0", MaxVersion: "1.0.0", MaxVersionExclusive: true}} {
		if m.validate(0) == nil {
			t.Fatal("invalid exclusive range accepted")
		}
	}
}

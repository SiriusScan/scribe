package scribe

import "testing"

func TestCPESelectionPreservesProductGate(t *testing.T) {
	for _, tc := range []struct {
		name             string
		cpe              []string
		product          string
		want, identified bool
	}{
		{"first", []string{"accepted", "other"}, "acme", true, true},
		{"last", []string{"other", "accepted"}, "acme", true, true},
		{"absent", []string{"other"}, "acme", false, false},
		{"missing", nil, "acme", false, false},
		{"wrong product", []string{"accepted"}, "other", false, false},
		{"missing product", []string{"accepted"}, "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := Target{CPE: tc.cpe, Product: tc.product}
			m := Match{CPE: []string{"accepted"}, Products: []string{"acme"}}
			ok, id := m.evaluate(target)
			if ok != tc.want || id != tc.identified {
				t.Fatalf("evaluate = %v, %v", ok, id)
			}
			if tc.product == "" && m.skipReason(target) != "declarative match: product identification missing" {
				t.Fatal(m.skipReason(target))
			}
			if tc.product == "other" && m.skipReason(target) != "declarative match: product identification mismatched" {
				t.Fatal(m.skipReason(target))
			}
			// CPE evidence alone must never establish the explicit product clean gate.
			m.Products = nil
			_, id = m.evaluate(target)
			if id {
				t.Fatal("CPE alone identified a product")
			}
		})
	}
}

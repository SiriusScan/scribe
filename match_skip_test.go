package scribe

import "testing"

func TestNestedSkipDiagnostics(t *testing.T) {
	const missing = "declarative match: product identification missing"
	const mismatch = "declarative match: product identification mismatched"
	const general = "declarative match: required identification facts missing or mismatched"
	for _, tc := range []struct {
		name   string
		match  Match
		target Target
		reason string
	}{
		{"required product", Match{AllOf: []Match{{Products: []string{"redis"}}}}, Target{}, missing},
		{"required mismatch", Match{AllOf: []Match{{Products: []string{"redis"}}}}, Target{Product: "mysql"}, mismatch},
		{"agreed alternatives", Match{AnyOf: []Match{{Products: []string{"redis"}}, {Products: []string{"mysql"}}}}, Target{}, missing},
		{"mixed alternatives", Match{AnyOf: []Match{{Confidence: 1}, {Products: []string{"mysql"}}}}, Target{}, general},
		{"satisfied alternative", Match{AnyOf: []Match{{Confidence: 1}, {}}, AllOf: []Match{{Products: []string{"redis"}}}}, Target{}, missing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if ok, id := tc.match.evaluate(tc.target); ok || id {
				t.Fatal("failed selection supplied applicability or identification")
			}
			if got := tc.match.skipReason(tc.target); got != tc.reason {
				t.Fatalf("got %q want %q", got, tc.reason)
			}
		})
	}
}

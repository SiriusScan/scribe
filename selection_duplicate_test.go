package scribe

import "testing"

func TestSelectionRejectsDuplicateConstraints(t *testing.T) {
	for _, metadata := range []string{
		`{"match":{"products":["nginx"],"products":["apache"]}}`,
		`{"match":{"any_of":[{"products":["nginx"],"produc\u0074s":["apache"]}]}}`,
		`{"match":{},"match":{"products":["apache"]}}`,
	} {
		if _, err := NewIndex([]Script{{ID: "ambiguous", Dialect: Sirius, Source: []byte("-- scribe: " + metadata + "\n")}}); err == nil {
			t.Fatalf("accepted ambiguous metadata: %s", metadata)
		}
	}
	if _, err := NewIndex([]Script{{ID: "independent", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"any_of":[{"products":["nginx"]},{"products":["apache"]}]}}`)}}); err != nil {
		t.Fatal(err)
	}
}

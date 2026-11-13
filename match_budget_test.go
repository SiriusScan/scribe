package scribe

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMatchTotalNodeBudget(t *testing.T) {
	// Both branch groups consume one shared budget, including their parent.
	m := Match{Products: []string{"acme"}}
	for i := 0; i < 4; i++ {
		child := Match{}
		for j := 0; j < 63; j++ {
			child.AllOf = append(child.AllOf, Match{})
		}
		m.AnyOf = append(m.AnyOf, child)
	}
	if err := m.validate(0); err == nil || !strings.Contains(err.Error(), "256 nodes") {
		t.Fatalf("oversized tree: %v", err)
	}
	encoded, err := json.Marshal(map[string]any{"match": m})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewIndex([]Script{{ID: "oversized", Dialect: Sirius, Source: append(append([]byte("-- scribe: "), encoded...), []byte("\nreturn {}")...)}}); err == nil || !strings.Contains(err.Error(), "256 nodes") {
		t.Fatalf("index accepted oversized metadata: %v", err)
	}
	m.AnyOf[3].AllOf = m.AnyOf[3].AllOf[:62]
	if err := m.validate(0); err != nil {
		t.Fatal(err)
	}
	if ok, id := m.evaluate(Target{Product: "acme"}); !ok || !id {
		t.Fatalf("boundary tree lost identification: %v %v", ok, id)
	}
	if ok, id := m.evaluate(Target{}); ok || id {
		t.Fatal("missing product accepted")
	}
}

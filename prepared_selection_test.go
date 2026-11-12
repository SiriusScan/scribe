package scribe

import (
	"context"
	"testing"
)

// Selected tasks share immutable metadata; endpoint verdict gates still evaluate
// each target independently rather than caching a prior target's decision.
func TestPreparedSelectionEndpointIsolation(t *testing.T) {
	idx, err := NewIndex([]Script{{ID: "prepared", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"products":["nginx"]}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	hints := &idx.entries[0].hints
	for i := 0; i < 100; i++ {
		for _, product := range []string{"nginx", "apache", ""} {
			matched, identified := hints.Match.evaluate(Target{Host: "localhost", Product: product})
			if product == "nginx" {
				if !matched || !identified {
					t.Fatal("matching product lost")
				}
			} else if identified {
				t.Fatalf("false identification for %q", product)
			}
		}
	}
}

type preparedRuntime struct{ t *testing.T }

func (r preparedRuntime) Dialect() Dialect { return Sirius }
func (r preparedRuntime) Execute(_ context.Context, task Task) (Output, error) {
	if task.preparedHints == nil {
		r.t.Error("selected task reparses metadata")
	}
	return Output{Verdict: NotVulnerable}, nil
}
func TestPreparedSelectionCleanGate(t *testing.T) {
	idx, err := NewIndex([]Script{{ID: "prepared", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"products":["nginx"]}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	e, err := New(Options{Exhaustive: true, Concurrency: 4}, preparedRuntime{t})
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	err = e.RunSelected(context.Background(), idx, []Target{{Host: "localhost", Product: "nginx"}, {Host: "localhost", Product: "apache"}, {Host: "localhost"}}, func(r Result) error {
		count++
		if r.Target.Product == "nginx" {
			if r.Verdict != NotVulnerable {
				t.Errorf("matching verdict: %+v", r)
			}
		} else if r.Verdict != Unknown || r.Status != Skipped {
			t.Errorf("false clean: %+v", r)
		}
		return nil
	})
	if err != nil || count != 3 {
		t.Fatalf("delivery count=%d err=%v", count, err)
	}
}

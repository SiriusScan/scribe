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

func TestDirectRunPreparedMetadata(t *testing.T) {
	e, err := New(Options{StrictIdentification: true}, preparedRuntime{t})
	if err != nil {
		t.Fatal(err)
	}
	script := Script{ID: "direct", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"products":["nginx"]}}`)}
	var tasks []Task
	for _, product := range []string{"nginx", "apache", "", "nginx"} {
		tasks = append(tasks, Task{Script: script, Target: Target{Host: "localhost", Product: product}})
	}
	count := 0
	err = e.Run(context.Background(), tasks, func(r Result) error {
		count++
		if r.Target.Product == "nginx" {
			if r.Verdict != NotVulnerable {
				t.Errorf("matching result: %+v", r)
			}
		} else if r.Verdict != Unknown {
			t.Errorf("false clean: %+v", r)
		}
		return nil
	})
	if err != nil || count != len(tasks) {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestDirectRunInvalidMetadataRemainsFailed(t *testing.T) {
	e, err := New(Options{}, preparedRuntime{t})
	if err != nil {
		t.Fatal(err)
	}
	task := Task{Script: Script{ID: "invalid", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"bogus":true}}`)}, Target: Target{Host: "localhost"}}
	count := 0
	err = e.Run(context.Background(), []Task{task, task}, func(r Result) error {
		count++
		if r.Status != Failed || r.Verdict != Unknown {
			t.Errorf("invalid metadata: %+v", r)
		}
		return nil
	})
	if err == nil || count != 2 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestMetadataPreparationSourceOwnership(t *testing.T) {
	source := []byte("-- scribe: {\"match\":{\"products\":[\"nginx\"]}}\n")
	script := Script{ID: "ownership", Dialect: Sirius, Source: source}
	owned, err := NewIndex([]Script{script})
	if err != nil {
		t.Fatal(err)
	}
	local, err := newIndex([]Script{script}, false)
	if err != nil {
		t.Fatal(err)
	}
	if &owned.entries[0].script.Source[0] == &source[0] {
		t.Fatal("public index borrowed source")
	}
	if &local.entries[0].script.Source[0] != &source[0] {
		t.Fatal("metadata preparation copied source")
	}
	source[0] = '!'
	if owned.entries[0].script.Source[0] != '-' {
		t.Fatal("public snapshot changed")
	}
	for _, idx := range []*Index{owned, local} {
		ok, identified := idx.entries[0].hints.Match.evaluate(Target{Host: "localhost", Product: "nginx"})
		if !ok || !identified {
			t.Fatal("prepared metadata lost")
		}
	}
}

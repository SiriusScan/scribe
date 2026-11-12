package scribe_test

import (
	"context"
	"fmt"
	"github.com/SiriusScan/scribe"
	"testing"
)

// Multiple windows require workers to accept successive tasks; repeated runs
// require the pool to close without retaining work from the previous run.
func TestWorkerPoolRepeatedWindows(t *testing.T) {
	for _, concurrency := range []int{1, 8} {
		t.Run(fmt.Sprint(concurrency), func(t *testing.T) {
			e, err := scribe.New(scribe.Options{Concurrency: concurrency, Window: 16}, testRuntime{execute: func(_ context.Context, task scribe.Task) (scribe.Output, error) {
				return scribe.Output{Data: task.Script.ID}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			for run := 0; run < 3; run++ {
				seen := map[string]bool{}
				err = e.Run(context.Background(), tasks(257), func(r scribe.Result) error {
					if seen[r.ScriptID] || r.Status != scribe.Completed || r.Verdict != scribe.Unknown || r.Output.Data != r.ScriptID {
						t.Errorf("unexpected result: %+v", r)
					}
					seen[r.ScriptID] = true
					return nil
				})
				if err != nil || len(seen) != 257 {
					t.Fatalf("run %d: count=%d err=%v", run, len(seen), err)
				}
			}
		})
	}
}

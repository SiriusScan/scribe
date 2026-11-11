package scribe_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/report"
)

// The file is a fake consumer store, independent of any live workflow service.
func TestCancellationPersistenceAcceptance(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		var active atomic.Int32
		started := make(chan struct{}, 1)
		engine := newEngine(t, 1, func(ctx context.Context, _ scribe.Task) (scribe.Output, error) {
			active.Add(1)
			defer active.Add(-1)
			started <- struct{}{}
			<-ctx.Done()
			return scribe.Output{}, ctx.Err()
		})
		file, err := os.CreateTemp(t.TempDir(), "reports-*.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- engine.Run(ctx, tasks(12), func(r scribe.Result) error { return json.NewEncoder(file).Encode(report.Map(r)) })
		}()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatal("runtime did not start")
		}
		cancel()
		if err := await(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("run: %v", err)
		}
		if active.Load() != 0 {
			t.Fatal("runtime survived shutdown")
		}
		if err := file.Sync(); err != nil {
			t.Fatal(err)
		}
		name := file.Name()
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		stored, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(stored)
		seen := map[string]bool{}
		for {
			var e report.Envelope
			err := decoder.Decode(&e)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			r := e.Evidence
			if seen[r.ScriptID] || r.Status != scribe.Cancelled || e.Assessment != "inconclusive" || e.Verdict != scribe.Unknown || e.Source.Config["script_sha256"] == "" {
				t.Fatalf("invalid persisted terminal record: %+v", e)
			}
			seen[r.ScriptID] = true
		}
		stored.Close()
		if len(seen) != 12 {
			t.Fatalf("incomplete store: %d", len(seen))
		}
	}
}

package scribe_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
)

type testRuntime struct {
	execute func(context.Context, scribe.Task) (scribe.Output, error)
}

func (testRuntime) Dialect() scribe.Dialect { return scribe.Sirius }
func (r testRuntime) Execute(ctx context.Context, task scribe.Task) (scribe.Output, error) {
	return r.execute(ctx, task)
}

func tasks(count int) []scribe.Task {
	result := make([]scribe.Task, count)
	for i := range result {
		result[i] = scribe.Task{
			Script: scribe.Script{ID: fmt.Sprint(i), Dialect: scribe.Sirius, Source: []byte("source")},
			Target: scribe.Target{Host: "example.internal"},
		}
	}
	return result
}

func newEngine(t *testing.T, workers int, execute func(context.Context, scribe.Task) (scribe.Output, error)) *scribe.Engine {
	t.Helper()
	engine, err := scribe.New(scribe.Options{Concurrency: workers}, testRuntime{execute: execute})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func await(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("execution did not finish")
		return nil
	}
}

func TestRunBoundsConcurrencyAndSerializesCallbacks(t *testing.T) {
	const workers, count = 3, 40
	var active, maximum, callbackActive, overlap, received atomic.Int32
	started := make(chan struct{}, count)
	release := make(chan struct{})
	engine := newEngine(t, workers, func(context.Context, scribe.Task) (scribe.Output, error) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); n > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, n) {
				break
			}
		}
		started <- struct{}{}
		<-release
		return scribe.Output{}, nil
	})
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(context.Background(), tasks(count), func(scribe.Result) error {
			if callbackActive.Add(1) != 1 {
				overlap.Add(1)
			}
			defer callbackActive.Add(-1)
			for range 10 {
				runtime.Gosched()
			}
			received.Add(1)
			return nil
		})
	}()
	for range workers {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("workers did not start")
		}
	}
	select {
	case <-started:
		close(release)
		t.Fatal("runtime exceeded configured concurrency")
	default:
	}
	close(release)
	if err := await(t, done); err != nil {
		t.Fatal(err)
	}
	if maximum.Load() != workers || active.Load() != 0 || received.Load() != count || overlap.Load() != 0 {
		t.Fatalf("max=%d active=%d results=%d callback overlap=%d", maximum.Load(), active.Load(), received.Load(), overlap.Load())
	}
}

func TestRunValidatesEveryTaskBeforeExecution(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*scribe.Task)
	}{
		{"unregistered dialect", func(task *scribe.Task) { task.Script.Dialect = scribe.NSE }},
		{"invalid endpoint", func(task *scribe.Task) { task.Target.Host = "https://example.internal" }},
		{"empty ID", func(task *scribe.Task) { task.Script.ID = "" }},
		{"empty source", func(task *scribe.Task) { task.Script.Source = nil }},
		{"oversized source", func(task *scribe.Task) { task.Script.Source = make([]byte, scribe.MaxSourceBytes+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var executions, callbacks atomic.Int32
			engine := newEngine(t, 2, func(context.Context, scribe.Task) (scribe.Output, error) {
				executions.Add(1)
				return scribe.Output{}, nil
			})
			request := tasks(2)
			tc.mutate(&request[1])
			err := engine.Run(context.Background(), request, func(scribe.Result) error { callbacks.Add(1); return nil })
			if err == nil || executions.Load() != 0 || callbacks.Load() != 0 {
				t.Fatalf("err=%v executions=%d callbacks=%d", err, executions.Load(), callbacks.Load())
			}
		})
	}
}

func TestCallbackErrorCancelsAndDrainsActiveExecutions(t *testing.T) {
	callbackErr := errors.New("result destination failed")
	var started, finished, callbacks atomic.Int32
	engine := newEngine(t, 3, func(ctx context.Context, task scribe.Task) (scribe.Output, error) {
		started.Add(1)
		defer finished.Add(1)
		if task.Script.ID == "0" {
			return scribe.Output{}, nil
		}
		<-ctx.Done()
		return scribe.Output{}, ctx.Err()
	})
	done := make(chan error, 1)
	go func() {
		done <- engine.Run(context.Background(), tasks(30), func(scribe.Result) error {
			callbacks.Add(1)
			return callbackErr
		})
	}()
	if err := await(t, done); !errors.Is(err, callbackErr) {
		t.Fatalf("got %v, want callback error", err)
	}
	if callbacks.Load() != 1 || started.Load() != finished.Load() || started.Load() >= 30 {
		t.Fatalf("callbacks=%d started=%d finished=%d", callbacks.Load(), started.Load(), finished.Load())
	}
}

func TestExecutionErrorsRemainSeparateFromFindings(t *testing.T) {
	finding := scribe.Finding{ID: "check-1", Title: "Observed issue", Severity: "low", Evidence: "fixture"}
	engine := newEngine(t, 2, func(_ context.Context, task scribe.Task) (scribe.Output, error) {
		switch task.Script.ID {
		case "0":
			return scribe.Output{Findings: []scribe.Finding{finding}}, nil
		case "1":
			return scribe.Output{Findings: []scribe.Finding{finding}}, errors.New("probe failed")
		case "2":
			return scribe.Output{Skipped: true}, nil
		default:
			return scribe.Output{}, nil
		}
	})
	results := make(map[string]scribe.Result)
	err := engine.Run(context.Background(), tasks(4), func(result scribe.Result) error {
		results[result.ScriptID] = result
		return nil
	})
	if err == nil || len(results) != 4 {
		t.Fatalf("summary=%v results=%d", err, len(results))
	}
	if result := results["0"]; result.Status != scribe.Completed || len(result.Output.Findings) != 1 || result.Error != "" {
		t.Fatalf("affirmative result: %+v", result)
	}
	if result := results["1"]; result.Status != scribe.Failed || result.Error != "probe failed" || len(result.Output.Findings) != 0 {
		t.Fatalf("failed result must not retain findings: %+v", result)
	}
	if result := results["2"]; result.Status != scribe.Skipped || len(result.Output.Findings) != 0 {
		t.Fatalf("skipped result: %+v", result)
	}
	if result := results["3"]; result.Status != scribe.Completed || len(result.Output.Findings) != 0 {
		t.Fatalf("empty completed result: %+v", result)
	}
}

func TestCanceledContextDoesNotStartExecution(t *testing.T) {
	var executions atomic.Int32
	engine := newEngine(t, 1, func(context.Context, scribe.Task) (scribe.Output, error) {
		executions.Add(1)
		return scribe.Output{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := engine.Run(ctx, tasks(1), func(scribe.Result) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context cancellation", err)
	}
	if executions.Load() != 0 {
		t.Fatal("runtime executed after prior cancellation")
	}
}

func TestEngineSupportsConcurrentRuns(t *testing.T) {
	const runs, count = 8, 12
	var executions atomic.Int32
	engine := newEngine(t, 3, func(_ context.Context, task scribe.Task) (scribe.Output, error) {
		executions.Add(1)
		runtime.Gosched()
		return scribe.Output{Data: task.Script.ID}, nil
	})
	var wg sync.WaitGroup
	errorsCh := make(chan error, runs)
	for range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			seen := make(map[string]bool)
			err := engine.Run(context.Background(), tasks(count), func(result scribe.Result) error {
				if seen[result.ScriptID] || result.Output.Data != result.ScriptID {
					return fmt.Errorf("duplicate or mismatched result: %+v", result)
				}
				seen[result.ScriptID] = true
				return nil
			})
			if err == nil && len(seen) != count {
				err = fmt.Errorf("received %d results, want %d", len(seen), count)
			}
			errorsCh <- err
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if executions.Load() != runs*count {
		t.Fatalf("executions=%d, want %d", executions.Load(), runs*count)
	}
}

func TestInvocationDeadlineDoesNotCancelSibling(t *testing.T) {
	engine, err := scribe.New(scribe.Options{Concurrency: 2, ScriptTimeout: 20 * time.Millisecond}, testRuntime{execute: func(ctx context.Context, task scribe.Task) (scribe.Output, error) {
		if task.Script.ID == "0" {
			<-ctx.Done()
			return scribe.Output{}, ctx.Err()
		}
		return scribe.Output{}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]scribe.Result{}
	if err := engine.Run(context.Background(), tasks(2), func(r scribe.Result) error { seen[r.ScriptID] = r; return nil }); err == nil {
		t.Fatal("expected aggregated deadline error")
	}
	if len(seen) != 2 {
		t.Fatalf("missing terminal records: %+v", seen)
	}
	if seen["0"].Status == scribe.Completed || seen["0"].Verdict != scribe.Unknown || seen["1"].Status != scribe.Completed {
		t.Fatalf("deadline leaked or became verdict: %+v", seen)
	}
}

package scribe_test

import (
	"context"
	"errors"
	"github.com/SiriusScan/scribe"
	"sync"
	"testing"
	"time"
)

func TestHostControls(t *testing.T) {
	var mu sync.Mutex
	active := map[string]int{}
	peaks := map[string]int{}
	starts := map[string][]time.Time{}
	r := testRuntime{execute: func(ctx context.Context, task scribe.Task) (scribe.Output, error) {
		h := task.Target.Host
		mu.Lock()
		active[h]++
		peaks[h] = max(peaks[h], active[h])
		starts[h] = append(starts[h], time.Now())
		mu.Unlock()
		select {
		case <-time.After(4 * time.Millisecond):
		case <-ctx.Done():
		}
		mu.Lock()
		active[h]--
		mu.Unlock()
		return scribe.Output{}, nil
	}}
	e, err := scribe.New(scribe.Options{Concurrency: 4, HostConcurrency: 1, HostInterval: 10 * time.Millisecond, Strategy: scribe.HostSpray}, r)
	if err != nil {
		t.Fatal(err)
	}
	ts := tasks(12)
	for i := range ts {
		if i%2 == 0 {
			ts[i].Target.Host = "other.internal"
		}
	}
	if err = e.Run(context.Background(), ts, func(scribe.Result) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for h, times := range starts {
		if peaks[h] != 1 {
			t.Fatalf("host %s peak %d", h, peaks[h])
		}
		for i := 1; i < len(times); i++ {
			if times[i].Sub(times[i-1]) < 8*time.Millisecond {
				t.Fatalf("host %s starts too close: %v", h, times)
			}
		}
	}
}

func TestBudgetAndStrategies(t *testing.T) {
	for _, strategy := range []scribe.Strategy{scribe.HostSpray, scribe.ScriptSpray} {
		t.Run(string(strategy), func(t *testing.T) {
			var order []string
			e, err := scribe.New(scribe.Options{Concurrency: 1, HostErrorBudget: 1, Strategy: strategy}, testRuntime{execute: func(_ context.Context, t scribe.Task) (scribe.Output, error) {
				order = append(order, t.Target.Host)
				if t.Target.Host == "bad" {
					return scribe.Output{}, errors.New("endpoint failed")
				}
				return scribe.Output{Verdict: scribe.Vulnerable}, nil
			}})
			if err != nil {
				t.Fatal(err)
			}
			ts := tasks(6)
			for i := range ts {
				ts[i].Target.Host = "healthy"
				if i >= 3 {
					ts[i].Target.Host = "bad"
				}
			}
			var records []scribe.Result
			err = e.Run(context.Background(), ts, func(r scribe.Result) error { records = append(records, r); return nil })
			if err == nil || len(records) != 6 {
				t.Fatalf("records %d err %v", len(records), err)
			}
			if strategy == scribe.HostSpray && order[1] != "bad" {
				t.Fatalf("host spray order %v", order)
			}
			if strategy == scribe.ScriptSpray && order[1] != "healthy" {
				t.Fatalf("script spray order %v", order)
			}
			skipped := 0
			for _, r := range records {
				if r.Status == scribe.Skipped {
					skipped++
					if r.Verdict != scribe.Unknown || r.Output.SkipReason == "" {
						t.Fatalf("bad skip %+v", r)
					}
				}
			}
			if skipped != 2 {
				t.Fatalf("budget skipped %d", skipped)
			}
		})
	}
}

func TestPacedCancellationHasTerminalRecords(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, _ := scribe.New(scribe.Options{Concurrency: 2, HostInterval: time.Hour}, testRuntime{execute: func(context.Context, scribe.Task) (scribe.Output, error) { return scribe.Output{}, nil }})
	count := 0
	err := e.Run(ctx, tasks(10), func(r scribe.Result) error { count++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || count != 10 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestStreamHintSkipsNeverExecute(t *testing.T) {
	idx, err := scribe.NewIndex([]scribe.Script{{ID: "ssh", Dialect: scribe.Sirius, Source: []byte("-- scribe: {\"services\":[\"ssh\"]}")}})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := scribe.New(scribe.Options{}, testRuntime{execute: func(context.Context, scribe.Task) (scribe.Output, error) {
		t.Error("excluded task executed")
		return scribe.Output{}, nil
	}})
	count := 0
	err = e.RunSelected(context.Background(), idx, []scribe.Target{{Host: "host", Service: "http"}}, func(r scribe.Result) error {
		count++
		if r.Status != scribe.Skipped || r.Verdict != scribe.Unknown || r.Output.SkipReason == "" {
			t.Fatalf("bad skip %+v", r)
		}
		return nil
	})
	if err != nil || count != 1 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestSelectedCancellationDrainsKnownPairs(t *testing.T) {
	scripts := []scribe.Script{{ID: "a", Dialect: scribe.Sirius, Source: []byte("source")}, {ID: "b", Dialect: scribe.Sirius, Source: []byte("source")}}
	idx, _ := scribe.NewIndex(scripts)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, _ := scribe.New(scribe.Options{Concurrency: 1, Window: 1}, testRuntime{execute: func(context.Context, scribe.Task) (scribe.Output, error) { return scribe.Output{}, nil }})
	count := 0
	err := e.RunSelected(ctx, idx, []scribe.Target{{Host: "one"}, {Host: "two"}, {Host: "three"}}, func(scribe.Result) error { count++; cancel(); return nil })
	if !errors.Is(err, context.Canceled) || count != 6 {
		t.Fatalf("count=%d err=%v", count, err)
	}
}

func TestHintSkipsDoNotConsumeHostPacing(t *testing.T) {
	idx, _ := scribe.NewIndex([]scribe.Script{
		{ID: "skip", Dialect: scribe.Sirius, Source: []byte("-- scribe: {\"services\":[\"ssh\"]}")},
		{ID: "run", Dialect: scribe.Sirius, Source: []byte("source")},
	})
	e, _ := scribe.New(scribe.Options{Concurrency: 1, HostInterval: time.Hour}, testRuntime{execute: func(context.Context, scribe.Task) (scribe.Output, error) { return scribe.Output{}, nil }})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	records := 0
	err := e.RunSelected(ctx, idx, []scribe.Target{{Host: "host", Service: "http"}}, func(scribe.Result) error { records++; return nil })
	if err != nil || records != 2 {
		t.Fatalf("records=%d err=%v", records, err)
	}
}

func TestHostLimitKeepsOtherHostsRunnable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan string, 2)
	e, _ := scribe.New(scribe.Options{Concurrency: 2, HostConcurrency: 1}, testRuntime{execute: func(ctx context.Context, task scribe.Task) (scribe.Output, error) {
		started <- task.Target.Host
		<-ctx.Done()
		return scribe.Output{}, ctx.Err()
	}})
	ts := tasks(3)
	ts[2].Target.Host = "other"
	done := make(chan error, 1)
	go func() { done <- e.Run(ctx, ts, func(scribe.Result) error { return nil }) }()
	seen := map[string]bool{}
	for range 2 {
		select {
		case host := <-started:
			seen[host] = true
		case <-time.After(5 * time.Second):
			t.Fatal("host limit blocked another host")
		}
	}
	if len(seen) != 2 {
		t.Fatalf("concurrent hosts=%v", seen)
	}
	cancel()
	if err := await(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

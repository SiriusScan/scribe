package scribe

import (
	"context"
	"errors"
	"testing"
	"time"
)

type failStopRuntime struct {
	execute func(context.Context, Task) (Output, error)
}

func (r failStopRuntime) Dialect() Dialect { return Sirius }
func (r failStopRuntime) Execute(ctx context.Context, task Task) (Output, error) {
	return r.execute(ctx, task)
}

func TestSchedulerFailStopDoesNotPullOrPrepare(t *testing.T) {
	for _, observer := range []bool{false, true} {
		name := "result"
		if observer {
			name = "observer"
		}
		t.Run(name, func(t *testing.T) {
			sentinel := errors.New("callback failed")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			active := make(chan struct{})
			stopped := make(chan error, 1)
			vm := failStopRuntime{execute: func(ctx context.Context, task Task) (Output, error) {
				if task.Target.Host == "second" {
					close(active)
					<-ctx.Done()
					stopped <- ctx.Err()
					return Output{}, ctx.Err()
				}
				select {
				case <-active:
				case <-ctx.Done():
				}
				return Output{}, nil
			}}
			opts := Options{Concurrency: 2, Window: 2}
			if observer {
				opts.OnEvent = func(Event) error { return sentinel }
			}
			e, err := New(opts, vm)
			if err != nil {
				t.Fatal(err)
			}
			pulls, prepared, writes := 0, 0, 0
			err = e.run(ctx, func(context.Context) (Task, bool, error) {
				pulls++
				host := "third"
				if pulls <= 2 {
					host = []string{"first", "second"}[pulls-1]
				}
				return Task{Script: Script{ID: host, Dialect: Sirius, Source: []byte("fixture")}, Target: Target{Host: host}}, pulls <= 5, nil
			}, func(_ context.Context, task Task) Task {
				prepared++
				return task
			}, func(Result) error {
				writes++
				return sentinel
			}, true)
			wantWrites := 1
			if observer {
				wantWrites = 0
			}
			if err != sentinel || pulls != 2 || prepared != 2 || writes != wantWrites {
				t.Fatalf("error=%v pulls=%d prepared=%d writes=%d", err, pulls, prepared, writes)
			}
			select {
			case err := <-stopped:
				if err != context.Canceled {
					t.Fatalf("active worker: %v", err)
				}
			default:
				t.Fatal("run returned before the admitted worker stopped")
			}
		})
	}
}

func TestSchedulerCancellationUsesRawIdentity(t *testing.T) {
	for _, drain := range []bool{true, false} {
		name := "stream"
		if drain {
			name = "slice"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runs := make(chan struct{}, 3)
			vm := failStopRuntime{execute: func(context.Context, Task) (Output, error) {
				runs <- struct{}{}
				return Output{}, nil
			}}
			e, err := New(Options{Concurrency: 1, Window: 1}, vm)
			if err != nil {
				t.Fatal(err)
			}
			pulls, prepared := 0, 0
			var records []Result
			hosts := []string{"one", "two", "three"}
			err = e.run(ctx, func(context.Context) (Task, bool, error) {
				if pulls == len(hosts) {
					return Task{}, false, nil
				}
				host := hosts[pulls]
				pulls++
				return Task{Script: Script{ID: host, Dialect: Sirius, Source: []byte("fixture")}, Target: Target{Host: host}}, true, nil
			}, func(_ context.Context, task Task) Task {
				prepared++
				task.Target.Product = "prepared"
				return task
			}, func(r Result) error {
				records = append(records, r)
				cancel()
				return nil
			}, drain)
			want := 1
			if drain {
				want = len(hosts)
			}
			if err != context.Canceled || pulls != want || len(records) != want || prepared != 1 || len(runs) != 1 {
				t.Fatalf("error=%v pulls=%d prepared=%d executions=%d records=%+v", err, pulls, prepared, len(runs), records)
			}
			for i, r := range records[1:] {
				host := hosts[i+1]
				if r.Status != Cancelled || r.Verdict != Unknown || r.Target.Host != host ||
					r.Target.Product != "" || r.ScriptID != host || r.ScriptSHA256 != records[0].ScriptSHA256 {
					t.Errorf("invalid raw cancellation record: %+v", r)
				}
			}
		})
	}
}

func TestPublicRunsPreserveCallbackFailure(t *testing.T) {
	for _, selected := range []bool{false, true} {
		for _, observer := range []bool{false, true} {
			sentinel := errors.New("callback failed")
			runs, writes := 0, 0
			vm := failStopRuntime{execute: func(context.Context, Task) (Output, error) {
				runs++
				return Output{}, nil
			}}
			opts := Options{Concurrency: 1, Window: 1}
			if observer {
				opts.OnEvent = func(Event) error { return sentinel }
			}
			e, err := New(opts, vm)
			if err != nil {
				t.Fatal(err)
			}
			script := Script{ID: "fixture", Dialect: Sirius, Source: []byte("fixture")}
			var targets []Target
			var batch []Task
			for range 32 {
				target := Target{Host: "fixture.example"}
				targets = append(targets, target)
				batch = append(batch, Task{Script: script, Target: target})
			}
			sink := func(Result) error {
				writes++
				return sentinel
			}
			if selected {
				idx, indexErr := NewIndex([]Script{script})
				if indexErr != nil {
					t.Fatal(indexErr)
				}
				err = e.RunSelected(context.Background(), idx, targets, sink)
			} else {
				err = e.Run(context.Background(), batch, sink)
			}
			if err != sentinel || runs != 1 || (observer && writes != 0) || (!observer && writes != 1) {
				t.Errorf("selected=%t observer=%t err=%v runs=%d writes=%d", selected, observer, err, runs, writes)
			}
		}
	}
}

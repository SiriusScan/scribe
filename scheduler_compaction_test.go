package scribe_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/SiriusScan/scribe"
)

func TestLargePendingCancellationOrder(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, err := scribe.New(scribe.Options{Concurrency: 1, Window: 4096}, testRuntime{execute: func(context.Context, scribe.Task) (scribe.Output, error) {
		return scribe.Output{}, context.Canceled
	}})
	if err != nil {
		t.Fatal(err)
	}
	tasks := make([]scribe.Task, 4096)
	for i := range tasks {
		tasks[i] = scribe.Task{Script: scribe.Script{ID: fmt.Sprint(i), Dialect: scribe.Sirius, Source: []byte("return {}")}, Target: scribe.Target{Host: "localhost", Port: 80, Protocol: "tcp"}}
	}
	seen := make(map[string]bool)
	last := 0
	err = e.Run(ctx, tasks, func(r scribe.Result) error {
		cancel()
		if seen[r.ScriptID] || r.Status != scribe.Cancelled || r.Verdict != scribe.Unknown {
			t.Fatalf("unexpected record: %+v", r)
		}
		seen[r.ScriptID] = true
		if r.ScriptID != fmt.Sprint(last) {
			t.Fatalf("order: got %s want %d", r.ScriptID, last)
		}
		last++
		return nil
	})
	if !errors.Is(err, context.Canceled) || len(seen) != len(tasks) {
		t.Fatalf("records=%d err=%v", len(seen), err)
	}
}

func TestLargePendingOrderedExecution(t *testing.T) {
	const count = 4096
	next := 0
	e, err := scribe.New(scribe.Options{Concurrency: 1, Window: count, Strategy: scribe.ScriptSpray}, testRuntime{execute: func(_ context.Context, task scribe.Task) (scribe.Output, error) {
		if task.Script.ID != fmt.Sprint(next) {
			return scribe.Output{}, fmt.Errorf("action %s, want %d", task.Script.ID, next)
		}
		next++
		return scribe.Output{Data: task.Script.ID}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	records := 0
	err = e.Run(context.Background(), tasks(count), func(r scribe.Result) error {
		if r.Status != scribe.Completed || r.Verdict != scribe.Unknown || r.Output.Data != fmt.Sprint(records) {
			t.Errorf("record %d: %+v", records, r)
		}
		records++
		return nil
	})
	if err != nil || records != count || next != count {
		t.Fatalf("err=%v records=%d actions=%d", err, records, next)
	}
}

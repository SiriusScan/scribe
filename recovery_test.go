package scribe_test

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/capability/tcpcap"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

func TestSiriusCorpusLoad(t *testing.T) {
	before := runtime.NumGoroutine()
	started := time.Now()
	vm, err := lua54.NewNative(lua54.Options{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 8}, vm)
	if err != nil {
		t.Fatal(err)
	}
	var batch []scribe.Task
	wants := map[string]scribe.Verdict{}
	for _, verdict := range []scribe.Verdict{scribe.Vulnerable, scribe.NotVulnerable, scribe.Unknown} {
		source, err := os.ReadFile("testdata/sirius/" + string(verdict) + ".lua")
		if err != nil {
			t.Fatal(err)
		}
		for script := 0; script < 12; script++ {
			for endpoint := 0; endpoint < 16; endpoint++ {
				id := fmt.Sprintf("%s-%d-%d", verdict, script, endpoint)
				wants[id] = verdict
				batch = append(batch, scribe.Task{Script: scribe.Script{ID: id, Dialect: scribe.Sirius, Source: source}, Target: scribe.Target{Host: fmt.Sprintf("endpoint-%d.invalid", endpoint)}})
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	seen := map[string]bool{}
	if err := engine.Run(ctx, batch, func(r scribe.Result) error {
		if seen[r.ScriptID] || r.Status != scribe.Completed || r.Verdict != wants[r.ScriptID] {
			t.Errorf("unexpected result: %+v", r)
		}
		seen[r.ScriptID] = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(batch) {
		t.Fatalf("results=%d want=%d", len(seen), len(batch))
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
	after := runtime.NumGoroutine()
	t.Logf("executions=%d elapsed=%s goroutines before=%d after=%d", len(batch), time.Since(started), before, after)
	if after > before {
		t.Fatalf("goroutines grew: %d -> %d", before, after)
	}
}

func TestLuaBatchFaultRecovery(t *testing.T) {
	vm, err := lua54.NewNative(lua54.Options{Limits: scribe.Limits{Timeout: 30 * time.Millisecond}, Functions: map[string]scribe.Function{
		"panic":        func(context.Context, scribe.Target, []any) (any, error) { panic("fixture") },
		"bad_endpoint": tcpcap.Function,
		"wait":         func(ctx context.Context, _ scribe.Target, _ []any) (any, error) { <-ctx.Done(); return nil, ctx.Err() },
	}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 2}, vm)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`error('fixture')`, `sirius.call('panic')`, `sirius.call('bad_endpoint')`, `while true do end`, `sirius.call('wait')`} {
		t.Run(body, func(t *testing.T) {
			batch := tasks(3)
			for i := range batch {
				batch[i].Script.Source = []byte(`return {api_version=1,action=function() return {verdict='not_vulnerable'} end}`)
			}
			batch[1].Target.Protocol = "udp"
			batch[1].Script.Source = []byte(`return {api_version=1,action=function() ` + body + ` end}`)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			seen := 0
			err := engine.Run(ctx, batch, func(r scribe.Result) error {
				seen++
				if r.ScriptID == "1" {
					if r.Status != scribe.Failed || r.Verdict != scribe.Unknown {
						t.Errorf("fault: %+v", r)
					}
				} else if r.Status != scribe.Completed || r.Verdict != scribe.NotVulnerable {
					t.Errorf("sibling: %+v", r)
				}
				return nil
			})
			if err == nil || seen != 3 {
				t.Fatalf("err=%v results=%d", err, seen)
			}
		})
	}
}

func TestLuaActiveCancellation(t *testing.T) {
	started := make(chan struct{})
	vm, err := lua54.NewNative(lua54.Options{Functions: map[string]scribe.Function{"wait": func(ctx context.Context, _ scribe.Target, _ []any) (any, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 1}, vm)
	if err != nil {
		t.Fatal(err)
	}
	batch := tasks(20)
	for i := range batch {
		batch[i].Script.Source = []byte(`return {api_version=1,action=function() sirius.call('wait') end}`)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	seen := 0
	go func() {
		done <- engine.Run(ctx, batch, func(r scribe.Result) error {
			seen++
			if r.Status == scribe.Completed || r.Verdict != scribe.Unknown {
				t.Errorf("cancelled result: %+v", r)
			}
			return nil
		})
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("capability did not start")
	}
	cancel()
	if err := await(t, done); err == nil {
		t.Fatal("missing cancellation error")
	}
	if seen != len(batch) {
		t.Fatalf("terminal records=%d want=%d", seen, len(batch))
	}
}

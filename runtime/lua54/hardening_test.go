package lua54

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/SiriusScan/scribe"
)

// FuzzParallelPlanner exercises shared caches, planning and isolated Lua states.
// Seed cases also run in the normal race suite.
func FuzzParallelPlanner(f *testing.F) {
	f.Add(uint8(4), uint8(8), true, false)
	f.Add(uint8(16), uint8(16), false, true)
	f.Fuzz(func(t *testing.T, modules, hosts uint8, selected, cancel bool) {
		r, err := NewNative(Options{})
		if err != nil {
			t.Fatal(err)
		}
		e, err := scribe.New(scribe.Options{Concurrency: 4}, r)
		if err != nil {
			t.Fatal(err)
		}
		n, m := 1+int(modules)%16, 1+int(hosts)%16
		scripts := make([]scribe.Script, n)
		targets := make([]scribe.Target, m)
		for i := range scripts {
			scripts[i] = scribe.Script{ID: fmt.Sprint(i), Dialect: scribe.Sirius, Source: []byte("-- scribe: {\"services\":[\"http\"]}\nreturn {api_version=1, action=function() return {data=42,verdict='unknown'} end}")}
		}
		for i := range targets {
			service := "http"
			if selected && i%2 == 0 {
				service = "ssh"
			}
			targets[i] = scribe.Target{Host: fmt.Sprintf("host-%d", i), Port: 80, Service: service}
		}
		idx, err := scribe.NewIndex(scripts)
		if err != nil {
			t.Fatal(err)
		}
		ctx, stop := context.WithCancel(context.Background())
		defer stop()
		if cancel {
			stop()
		}
		records := 0
		err = e.RunSelected(ctx, idx, targets, func(r scribe.Result) error {
			records++
			if r.Verdict != scribe.Unknown {
				t.Fatalf("unexpected verdict: %+v", r)
			}
			if r.Status == scribe.Completed && fmt.Sprint(r.Output.Data) != "42" {
				t.Fatalf("lost action: %+v", r)
			}
			if r.Status == scribe.Skipped && r.Output.SkipReason == "" {
				t.Fatal("missing skip reason")
			}
			return nil
		})
		if !cancel && (err != nil || records != n*m) {
			t.Fatalf("records=%d want=%d err=%v", records, n*m, err)
		}
		if cancel && err == nil {
			t.Fatal("lost cancellation")
		}
	})
}

func FuzzMixedFailures(f *testing.F) {
	f.Add(uint8(0), false)
	f.Add(uint8(3), true)
	f.Add(uint8(4), false)
	f.Fuzz(func(t *testing.T, mode uint8, sinkFails bool) {
		r, _ := NewNative(Options{Functions: map[string]scribe.Function{"read": func(context.Context, scribe.Target, []any) (any, error) {
			return 42, nil
		}}})
		input := task(scribe.Sirius, `return {api_version=1,action=function() return {data=sirius.call("read")} end}`)
		input.Capabilities = []string{"read"}
		switch mode % 4 {
		case 1:
			input.Capabilities = []string{}
		case 3:
			input.Capabilities = []string{"reader"}
		case 2:
			input.Script.Source = []byte(`return {api_version=1,action=function() error("mixed failure") end}`)
		}
		_, err := r.Execute(context.Background(), input)
		if (err != nil) != (mode%4 != 0) {
			t.Fatalf("mode=%d err=%v", mode, err)
		}
		e, _ := scribe.New(scribe.Options{Concurrency: 4}, r)
		tasks := make([]scribe.Task, 8)
		for i := range tasks {
			tasks[i] = input
			if i%2 == 0 {
				tasks[i].Capabilities = []string{"read"}
			}
		}

		sinkErr := errors.New("sink failure")
		calls := 0
		err = e.Run(context.Background(), tasks, func(result scribe.Result) error {
			calls++
			if result.Verdict != scribe.Unknown {
				t.Fatal("failure promoted to verdict")
			}
			if sinkFails {
				return sinkErr
			}
			return nil
		})
		if (!sinkFails && calls != len(tasks)) || (sinkFails && calls < 1) {
			t.Fatalf("calls=%d", calls)
		}
		if sinkFails && !errors.Is(err, sinkErr) {
			t.Fatalf("lost sink failure: %v", err)
		}
	})
}

func TestTableLibraryInvocationIsolation(t *testing.T) {
	r, _ := NewNative(Options{})
	for _, source := range []string{
		`return {api_version=1,action=function() math.abs=nil;math.extra=42;string.upper=nil;string.extra=42;table.insert=nil;table.extra=42;utf8.len=nil;utf8.extra=42; return {} end}`,
		`return {api_version=1,action=function() assert(math.abs(-2)==2);assert(math.extra==nil);assert(("abc"):upper()=="ABC");assert(string.extra==nil);assert("2"+3==5);assert(string.dump==nil and math.random==nil and math.randomseed==nil);assert(utf8.len("hello")==5);assert(utf8.extra==nil);assert(type(table.insert)=="function");assert(table.extra==nil);local x={};table.insert(x,42);return {data=x[1]} end}`,
	} {
		if _, err := r.Execute(context.Background(), task(scribe.Sirius, source)); err != nil {
			t.Fatal(err)
		}
	}
}

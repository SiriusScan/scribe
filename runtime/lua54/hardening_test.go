package lua54

import (
	"context"
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

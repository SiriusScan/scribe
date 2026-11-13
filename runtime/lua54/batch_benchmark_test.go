package lua54

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"

	"github.com/SiriusScan/scribe"
)

// This fixture uses only the pre-throughput SDK, so it can also run unchanged
// against 8bc7506 to measure the complete before/after batch path.
func BenchmarkLuaBatch(b *testing.B) {
	r, err := NewNative(Options{})
	if err != nil {
		b.Fatal(err)
	}
	e, err := scribe.New(scribe.Options{Concurrency: 4}, r)
	if err != nil {
		b.Fatal(err)
	}
	var scripts []scribe.Script
	for i := 0; i < 8; i++ {
		scripts = append(scripts, scribe.Script{ID: fmt.Sprint(i), Dialect: scribe.Sirius, Source: []byte(`return {api_version=1,action=function(t) return {data={host=t.host,value=42}} end}`)})
	}
	idx, err := scribe.NewIndex(scripts)
	if err != nil {
		b.Fatal(err)
	}
	targets := make([]scribe.Target, 16)
	for i := range targets {
		targets[i] = scribe.Target{Host: fmt.Sprintf("host-%d", i)}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		n := 0
		if err := e.RunSelected(context.Background(), idx, targets, func(scribe.Result) error { n++; return nil }); err != nil || n != 128 {
			b.Fatalf("n=%d err=%v", n, err)
		}
	}
}

// BenchmarkPlannerExecution checks actual Lua action output for every completed
// invocation; both paths emit the full matrix, including planner skips.
func BenchmarkPlannerExecution(b *testing.B) {
	benchmarkPlannerExecution(b, 100, false)
}

// BenchmarkPlannerLongExecution amortizes setup with longer Lua CPU work.
func BenchmarkPlannerLongExecution(b *testing.B) {
	benchmarkPlannerExecution(b, 100000, false)
}

// BenchmarkPlannerJSONLHandoff measures synchronous result encoding, including
// planner skips, through the same verified execution matrix. Discard isolates
// serialization cost; it does not model disk durability or a remote consumer.
func BenchmarkPlannerJSONLHandoff(b *testing.B) {
	benchmarkPlannerExecution(b, 100, true)
}

func benchmarkPlannerExecution(b *testing.B, iterations int, jsonl bool) {
	benchmarkPlannerWindow(b, iterations, jsonl, 0)
}

func BenchmarkPlannerWindow(b *testing.B) {
	for _, window := range []int{1, 8, 256} {
		b.Run(fmt.Sprintf("window=%d", window), func(b *testing.B) { benchmarkPlannerWindow(b, 100, true, window) })
	}
}

func benchmarkPlannerWindow(b *testing.B, iterations int, jsonl bool, window int) {
	for _, concurrency := range []int{1, 2, 4, 8} {
		for _, moduleLimit := range []int{0, 1} {
			for _, selected := range []bool{false, true} {
				b.Run(fmt.Sprintf("workers=%d/module_limit=%d/selected=%v", concurrency, moduleLimit, selected), func(b *testing.B) {
					r, err := NewNative(Options{})
					if err != nil {
						b.Fatal(err)
					}
					e, err := scribe.New(scribe.Options{Concurrency: concurrency, ModuleConcurrency: moduleLimit, Window: window}, r)
					if err != nil {
						b.Fatal(err)
					}
					var scripts []scribe.Script
					var tasks []scribe.Task
					var targets []scribe.Target
					for j := 0; j < 16; j++ {
						targets = append(targets, scribe.Target{Host: fmt.Sprintf("host-%d", j), Port: 80, Service: "http"})
					}
					for j := 0; j < 32; j++ {
						service := "ssh"
						if j%8 == 0 {
							service = "http"
						}
						hint := ""
						if selected {
							hint = fmt.Sprintf("-- scribe: {\"services\":[%q]}\n", service)
						}
						s := scribe.Script{ID: fmt.Sprint(j), Dialect: scribe.Sirius, Source: plannerWorkload(hint, iterations)}
						scripts = append(scripts, s)
						for _, t := range targets {
							tasks = append(tasks, scribe.Task{Script: s, Target: t})
						}
					}
					idx, err := scribe.NewIndex(scripts)
					if err != nil {
						b.Fatal(err)
					}
					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						completed, records := 0, 0
						encoder := json.NewEncoder(io.Discard)
						sink := func(r scribe.Result) error {
							records++
							if r.Verdict != scribe.Unknown {
								b.Fatalf("unexpected verdict: %+v", r)
							}
							if jsonl {
								if err := encoder.Encode(r); err != nil {
									return err
								}
							}
							if r.Status == scribe.Completed {
								completed++
								if fmt.Sprint(r.Output.Data) != fmt.Sprint(int64(iterations)*int64(iterations+1)/2) {
									b.Fatalf("action output: %#v", r.Output.Data)
								}
							} else if r.Status != scribe.Skipped {
								b.Fatalf("%+v", r)
							}
							return nil
						}
						if selected {
							err = e.RunSelected(context.Background(), idx, targets, sink)
						} else {
							err = e.Run(context.Background(), tasks, sink)
						}
						want := 512
						if selected {
							want = 64
						}
						if err != nil || completed != want || records != 512 {
							b.Fatalf("completed=%d records=%d err=%v", completed, records, err)
						}
					}
					actions := 512.0
					if selected {
						actions = 64
					}
					b.ReportMetric(actions*float64(b.N)/b.Elapsed().Seconds(), "actions/s")
					b.ReportMetric(512*float64(b.N)/b.Elapsed().Seconds(), "records/s")
				})
			}
		}

	}
}

func plannerWorkload(hint string, iterations int) []byte {
	return []byte(hint + fmt.Sprintf("return {api_version=1,action=function() local n=0; for i=1,%d do n=n+i end; return {data=n,verdict='unknown'} end}", iterations))
}

func TestPlannerLongWorkload(t *testing.T) {
	for _, workers := range []int{1, 8} {
		t.Run(fmt.Sprint(workers), func(t *testing.T) {
			r, err := NewNative(Options{})
			if err != nil {
				t.Fatal(err)
			}
			e, err := scribe.New(scribe.Options{Concurrency: workers}, r)
			if err != nil {
				t.Fatal(err)
			}
			tasks := make([]scribe.Task, 16)
			for i := range tasks {
				tasks[i] = scribe.Task{Script: scribe.Script{ID: "long", Dialect: scribe.Sirius, Source: plannerWorkload("", 100000)}, Target: scribe.Target{Host: fmt.Sprintf("host-%d", i)}}
			}
			count := 0
			err = e.Run(context.Background(), tasks, func(r scribe.Result) error {
				count++
				if r.Status != scribe.Completed || fmt.Sprint(r.Output.Data) != "5000050000" || r.Output.Verdict != scribe.Unknown {
					t.Errorf("unexpected result: %+v", r)
				}
				return nil
			})
			if err != nil || count != len(tasks) {
				t.Fatalf("records=%d err=%v", count, err)
			}
		})
	}
}

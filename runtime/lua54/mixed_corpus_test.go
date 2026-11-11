package lua54

import (
	"context"
	"fmt"
	"testing"

	"github.com/SiriusScan/scribe"
)

// One harness keeps benchmark execution subject to the regression assertions.
func mixedCorpus(b testing.TB, exhaustive bool) func() {
	b.Helper()
	runtime, err := NewNative(Options{})
	if err != nil {
		b.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 4, StrictIdentification: true, Exhaustive: exhaustive}, runtime)
	if err != nil {
		b.Fatal(err)
	}
	actions := []string{
		`return {verdict='vulnerable'}`,
		`return {verdict='not_vulnerable'}`,
		`return {verdict='unknown'}`,
		`return nil`,
		`error('mixed corpus failure')`,
		`return {verdict='not_vulnerable'}`,
	}
	var scripts []scribe.Script
	for i := 0; i < 32; i++ {
		rule := ""
		if i%6 == 5 {
			rule = "rule=function() return false end,"
		}
		scripts = append(scripts, scribe.Script{ID: fmt.Sprint(i), Dialect: scribe.Sirius, Source: []byte(`-- scribe: {"match":{"products":["Mixed fixture"],"on_unknown":"run"}}
return {api_version=1,` + rule + `action=function() ` + actions[i%6] + ` end}`)})
	}
	index, err := scribe.NewIndex(scripts)
	if err != nil {
		b.Fatal(err)
	}
	var targets []scribe.Target
	for i := 0; i < 16; i++ {
		product := "Mixed fixture"
		if i%3 == 1 {
			product = "Other fixture"
		}
		if i%3 == 2 {
			product = ""
		}
		targets = append(targets, scribe.Target{Host: fmt.Sprint(i), Product: product})
	}
	return func() {
		seen := map[string]bool{}
		reasons := map[string]int{}
		err := engine.RunSelected(context.Background(), index, targets, func(r scribe.Result) error {
			key := r.ScriptID + "/" + r.Target.Host
			if seen[key] {
				b.Fatalf("duplicate %s", key)
			}
			seen[key] = true
			var module int
			fmt.Sscan(r.ScriptID, &module)
			kind := module % 6
			excluded := r.Target.Product == "Other fixture"
			cleanDenied := kind == 1 && r.Target.Product != "Mixed fixture"
			switch {
			case excluded || cleanDenied || kind == 5:
				if r.Status != scribe.Skipped || r.Verdict != scribe.Unknown || r.Output.SkipReason == "" {
					b.Fatalf("skip: %+v", r)
				}
				reasons[r.Output.SkipReason]++
			case kind == 3 || kind == 4:
				if r.Status == scribe.Completed || r.Verdict != scribe.Unknown || r.Error == "" {
					b.Fatalf("error: %+v", r)
				}
			default:
				want := scribe.Unknown
				if kind == 0 {
					want = scribe.Vulnerable
				}
				if kind == 1 {
					want = scribe.NotVulnerable
				}
				if r.Status != scribe.Completed || r.Verdict != want {
					b.Fatalf("execution: %+v", r)
				}
			}
			return nil
		})
		if err == nil || len(seen) != 512 || len(reasons) == 0 {
			b.Fatalf("records=%d reasons=%v err=%v", len(seen), reasons, err)
		}
	}
}

func TestMixedCorpusPlanner(t *testing.T) {
	for _, exhaustive := range []bool{false, true} {
		t.Run(fmt.Sprint(exhaustive), func(t *testing.T) { mixedCorpus(t, exhaustive)() })
	}
}
func BenchmarkMixedCorpusPlanner(b *testing.B) {
	for _, exhaustive := range []bool{false, true} {
		b.Run(fmt.Sprint(exhaustive), func(b *testing.B) {
			run := mixedCorpus(b, exhaustive)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				run()
			}
		})
	}
}

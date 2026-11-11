package lua54

import (
	"context"
	"fmt"
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

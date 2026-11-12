package scribe_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/SiriusScan/scribe"
)

func TestDirectExclusionsBypassHostAdmission(t *testing.T) {
	for _, exhaustive := range []bool{false, true} {
		t.Run(fmt.Sprint(exhaustive), func(t *testing.T) {
			calls := 0
			e, err := scribe.New(scribe.Options{MaxHosts: 1, Window: 1, Exhaustive: exhaustive}, testRuntime{execute: func(context.Context, scribe.Task) (scribe.Output, error) { calls++; return scribe.Output{}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			batch := tasks(20)
			for i := range batch {
				batch[i].Target.Host = fmt.Sprintf("host-%d.internal", i)
				batch[i].Target.Product = "apache"
				batch[i].Script.Source = []byte("-- scribe: {\"match\":{\"products\":[\"nginx\"]}}")
			}
			batch[len(batch)-1].Target.Product = "nginx"
			count := 0
			err = e.Run(context.Background(), batch, func(r scribe.Result) error {
				count++
				if !exhaustive && count < len(batch) && (r.Status != scribe.Skipped || r.Verdict != scribe.Unknown || r.Output.SkipReason == "") {
					t.Errorf("excluded record: %+v", r)
				}
				return nil
			})
			if exhaustive {
				if err == nil {
					t.Fatal("exhaustive bypassed host bound")
				}
				return
			}
			if err != nil || count != len(batch) || calls != 1 {
				t.Fatalf("err=%v records=%d calls=%d", err, count, calls)
			}
		})
	}
}

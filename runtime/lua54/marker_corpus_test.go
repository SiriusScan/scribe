package lua54

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/SiriusScan/scribe"
	"os"
	"testing"
)

func TestMarkerCorpus(t *testing.T) {
	source, err := os.ReadFile("../../testdata/sirius/http-marker.lua")
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(source)); got != "233d593087b6b58ee84d6fe4cc2731c9b556da9c0b9b166648fd48c246803c6b" {
		t.Fatalf("fixture digest changed: %s", got)
	}
	for _, marker := range []string{"vulnerable", "clean", "unrecognized"} {
		for _, product := range []string{"Scribe fixture", "", "Other"} {
			for _, exhaustive := range []bool{false, true} {
				rt, err := NewNative(Options{Functions: map[string]scribe.Function{"http.get": func(context.Context, scribe.Target, []any) (any, error) {
					return map[string]any{"status": 200, "headers": map[string]any{"x-sirius-fixture": []any{marker}}}, nil
				}}})
				if err != nil {
					t.Fatal(err)
				}
				engine, err := scribe.New(scribe.Options{StrictIdentification: true, Exhaustive: exhaustive}, rt)
				if err != nil {
					t.Fatal(err)
				}
				idx, err := scribe.NewIndex([]scribe.Script{{ID: "http-marker", Dialect: scribe.Sirius, Source: source}})
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				err = engine.RunSelected(context.Background(), idx, []scribe.Target{{Host: "fixture", Service: "http", Product: product}}, func(r scribe.Result) error {
					count++
					want := scribe.Unknown
					if marker == "vulnerable" {
						want = scribe.Vulnerable
					}
					if marker == "clean" {
						want = scribe.NotVulnerable
					}
					if product != "Scribe fixture" {
						if r.Status != scribe.Skipped || r.Output.SkipReason == "" {
							t.Fatalf("missing skip: %+v", r)
						}
						reason := "script hints exclude supplied endpoint facts"
						if r.Output.SkipReason != reason {
							t.Fatalf("reason: %+v", r)
						}
						want = scribe.Unknown
					} else if r.Status != scribe.Completed {
						t.Fatalf("execution: %+v", r)
					}
					if r.Verdict != want {
						t.Fatalf("marker=%s product=%s: %+v", marker, product, r)
					}
					return nil
				})
				if err != nil || count != 1 {
					t.Fatalf("count=%d err=%v", count, err)
				}
			}
		}
	}
}

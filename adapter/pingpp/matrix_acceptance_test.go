package pingpp

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

// Exercise the public adapter, planner and real Lua engine as one bounded batch.
func TestRunManyModulesAcceptance(t *testing.T) {
	for _, workers := range []int{1, 8} {
		for _, exhaustive := range []bool{false, true} {
			t.Run(fmt.Sprintf("workers=%d/exhaustive=%v", workers, exhaustive), func(t *testing.T) {
				rt, err := lua54.NewNative(lua54.Options{})
				if err != nil {
					t.Fatal(err)
				}
				engine, err := scribe.New(scribe.Options{Concurrency: workers, Exhaustive: exhaustive}, rt)
				if err != nil {
					t.Fatal(err)
				}
				scripts := make([]scribe.Script, 32)
				for i := range scripts {
					scripts[i] = scribe.Script{ID: fmt.Sprintf("module-%d", i), Dialect: scribe.Sirius, Source: []byte(fmt.Sprintf(`-- scribe: {"match":{"products":["nginx"]}}
return {api_version=1, action=function() return {verdict="not_vulnerable", data="module-%d"} end}`, i))}
				}
				index, err := scribe.NewIndex(scripts)
				if err != nil {
					t.Fatal(err)
				}
				var endpoints, claims []string
				for i := 0; i < 16; i++ {
					host := fmt.Sprintf("192.0.2.%d", i+1)
					subject := host + "/tcp/443"
					endpoints = append(endpoints, fmt.Sprintf(`{"address":%q,"port":443,"transport":"tcp","state":"open","execution":"attempted"}`, host))
					confidence := "exact"
					if i%3 == 1 {
						confidence = "weak"
					}
					claims = append(claims, fmt.Sprintf(`{"subject":%q,"kind":"product","product":"nginx","confidence":%q}`, subject, confidence))
					if i%3 == 2 {
						claims = append(claims, fmt.Sprintf(`{"subject":%q,"kind":"product","product":"Apache","confidence":"exact"}`, subject))
					}
				}
				input := `{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[` + strings.Join(endpoints, ",") + `],"claims":[` + strings.Join(claims, ",") + `]}}` + "\n"
				seen := map[string]bool{}
				completed := 0
				err = Run(context.Background(), engine, index, strings.NewReader(input), func(r scribe.Result) error {
					key := r.Target.Host + "/" + r.ScriptID
					if seen[key] {
						t.Fatalf("duplicate %s", key)
					}
					seen[key] = true
					var n int
					fmt.Sscanf(r.Target.Host, "192.0.2.%d", &n)
					if (n-1)%3 == 0 {
						if r.Status != "completed" || r.Verdict != "not_vulnerable" || r.Output.Data != r.ScriptID {
							t.Fatalf("identified: %+v", r)
						}
						completed++
					} else if r.Status != "skipped" || r.Verdict != "unknown" || r.Target.Product != "" || r.PlannerMiss || r.Output.SkipReason == "" {
						t.Fatalf("false clean: %+v", r)
					}
					return nil
				})
				if err != nil || len(seen) != 512 || completed != 192 {
					t.Fatalf("records=%d completed=%d err=%v", len(seen), completed, err)
				}
			})
		}
	}
}

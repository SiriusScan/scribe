package pingpp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

func TestRunRejectsMissingDependencies(t *testing.T) {
	if err := Run(context.Background(), nil, nil, nil, nil); err == nil {
		t.Fatal("missing dependencies accepted")
	}
}

func TestRunStreamCompletion(t *testing.T) {
	runtime, err := lua54.NewNative(lua54.Options{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	index, err := scribe.NewIndex([]scribe.Script{{ID: "plan", Dialect: scribe.Sirius, Source: []byte(`-- scribe: {"match":{"protocols":["tcp"]}}
return {api_version=1, action=function() return {verdict="unknown", data="adapter executed"} end}`)}})
	if err != nil {
		t.Fatal(err)
	}
	wire := `{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"127.0.0.1","port":80,"transport":"tcp","state":"open","execution":"attempted"}]}}` + "\n"
	for _, tc := range []struct {
		name, input string
		fail        bool
	}{{"complete", wire, false}, {"late error", wire + "invalid\n", true}, {"empty", "", true}} {
		t.Run(tc.name, func(t *testing.T) {
			count := 0
			err := Run(context.Background(), engine, index, strings.NewReader(tc.input), func(r scribe.Result) error {
				count++
				if r.Status != "completed" || r.Verdict != "unknown" {
					t.Fatalf("result=%+v", r)
				}
				return nil
			})
			if (err != nil) != tc.fail {
				t.Fatalf("error=%v", err)
			}
			if !tc.fail && count != 1 {
				t.Fatalf("records=%d", count)
			}
		})
	}
	sentinel := errors.New("sink failed")
	if err := Run(context.Background(), engine, index, strings.NewReader(wire), func(scribe.Result) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("sink error=%v", err)
	}
}

type unreadableInput struct{ t *testing.T }

func (r unreadableInput) Read([]byte) (int, error) {
	r.t.Fatal("empty plan read upstream input")
	return 0, errors.New("unexpected read")
}

func TestRunEmptyPlanDoesNotRead(t *testing.T) {
	runtime, err := lua54.NewNative(lua54.Options{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), engine, &scribe.Index{}, unreadableInput{t}, func(scribe.Result) error {
		t.Fatal("empty plan emitted a result")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "index must contain scripts") {
		t.Fatalf("error=%v", err)
	}
}

func TestTargetsBoundsSDKDocuments(t *testing.T) {
	for _, claims := range []bool{false, true} {
		var d Document
		if err := json.Unmarshal([]byte(`{"schema_version":"pingpp.scan/v1","asset":{}}`), &d); err != nil {
			t.Fatal(err)
		}
		if claims {
			d.Asset.Claims = make([]Claim, 262145)
		} else {
			d.Asset.Endpoints = make([]Endpoint, 65537)
		}
		targets, err := Targets(d)
		if err == nil || len(targets) != 0 || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("targets=%d err=%v", len(targets), err)
		}
	}
}

// Pin identity reduction, selection and the exhaustive clean gate together.
func TestRunIdentitySelectionAcceptance(t *testing.T) { runSelectionAcceptance(t, false) }

func TestRunHTTPSSelectionAcceptance(t *testing.T) { runSelectionAcceptance(t, true) }

func runSelectionAcceptance(t *testing.T, https bool) {
	t.Helper()
	for _, workers := range []int{1, 8} {
		for _, exhaustive := range []bool{false, true} {
			runtime, err := lua54.NewNative(lua54.Options{})
			if err != nil {
				t.Fatal(err)
			}
			engine, err := scribe.New(scribe.Options{Concurrency: workers, Exhaustive: exhaustive}, runtime)
			if err != nil {
				t.Fatal(err)
			}
			serviceMatch := ""
			if https {
				serviceMatch = `,"services":["http"]`
			}
			index, err := scribe.NewIndex([]scribe.Script{{ID: "identity", Dialect: scribe.Sirius, Source: []byte(`-- scribe: {"match":{"products":["nginx"]` + serviceMatch + `}}
return {api_version=1, action=function() return {verdict="not_vulnerable"} end}`)}})
			if err != nil {
				t.Fatal(err)
			}
			input := `{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"192.0.2.1","port":443,"transport":"tcp","state":"open","execution":"attempted"},{"address":"192.0.2.2","port":443,"transport":"tcp","state":"open","execution":"attempted"}],"claims":[{"subject":"192.0.2.1/tcp/443","kind":"product","product":"nginx","confidence":"exact"},{"subject":"192.0.2.2/tcp/443","kind":"product","product":"nginx","confidence":"weak"}]}}` + "\n"
			if https {
				input = strings.Replace(input, `"claims":[`, `"claims":[{"subject":"192.0.2.1/tcp/443","kind":"service","value":"https","confidence":"exact"},{"subject":"192.0.2.2/tcp/443","kind":"service","value":"https","confidence":"weak"},`, 1)
			}
			seen := map[string]bool{}
			err = Run(context.Background(), engine, index, strings.NewReader(input), func(r scribe.Result) error {
				if https && r.Target.Host == "192.0.2.1" && (r.Target.Service != "http" || !r.Target.TLS) {
					t.Fatalf("secure facts: %+v", r)
				}
				if seen[r.Target.Host] {
					t.Fatalf("duplicate result: %+v", r)
				}
				seen[r.Target.Host] = true
				if r.Target.Host == "192.0.2.1" {
					if r.Status != "completed" || r.Verdict != "not_vulnerable" || r.Target.Product != "nginx" {
						t.Fatalf("identified: %+v", r)
					}
				} else {
					status := scribe.Status("skipped")

					if r.Status != status || r.Verdict != "unknown" || r.Target.Product != "" || r.PlannerMiss {
						t.Fatalf("unidentified: %+v", r)
					}
				}
				return nil
			})
			if err != nil || len(seen) != 2 {
				t.Fatalf("workers=%d exhaustive=%v records=%d error=%v", workers, exhaustive, len(seen), err)
			}
		}
	}
}

package pingpp

import (
	"context"
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

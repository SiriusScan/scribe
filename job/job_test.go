package job_test

import (
	"context"
	"errors"
	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/job"
	"github.com/SiriusScan/scribe/runtime/lua54"
	"testing"
)

func TestJobs(t *testing.T) {
	runtime, _ := lua54.NewNative(lua54.Options{Functions: map[string]scribe.Function{"tcp": func(context.Context, scribe.Target, []any) (any, error) { return true, nil }}})
	engine, _ := scribe.New(scribe.Options{}, runtime)
	request := job.Request{SchemaVersion: 1, ID: "job", ScriptID: "script", Dialect: scribe.Sirius, Target: scribe.Target{Host: "localhost"}, Source: `return {api_version=1, action=function() sirius.call("tcp"); return {verdict="not_vulnerable"} end}`}
	result, err := job.Run(context.Background(), engine, request, nil)
	if err == nil || result.Report.Assessment != "inconclusive" {
		t.Fatalf("denied: %+v %v", result, err)
	}
	_, err = runtime.Execute(context.Background(), scribe.Task{Script: scribe.Script{ID: "s", Dialect: scribe.Sirius, Source: []byte(request.Source)}, Target: request.Target, Capabilities: []string{}})
	var denied *scribe.CapabilityDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("missing typed denial: %v", err)
	}
	request.Capabilities = []string{"tcp"}
	if _, err := job.Run(context.Background(), engine, request, nil); err != nil {
		t.Fatal(err)
	}
	request.Limits.CPU = 1
	if _, err := job.Run(context.Background(), engine, request, nil); err == nil {
		t.Fatal("limit ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := job.Run(ctx, engine, request, nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

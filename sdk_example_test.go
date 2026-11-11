package scribe_test

import (
	"context"
	"fmt"
	"strings"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/adapter/pingpp"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

func exampleEngine() *scribe.Engine {
	runtime, err := lua54.NewNative(lua54.Options{})
	if err != nil {
		panic(err)
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 2}, runtime)
	if err != nil {
		panic(err)
	}
	return engine
}
func exampleScript() scribe.Script {
	return scribe.Script{ID: "check", Dialect: scribe.Sirius, Source: []byte(`-- scribe: {"services":["http"]}
return {api_version=1, action=function() return {verdict="unknown"} end}`)}
}
func ExampleEngine_Run() {
	err := exampleEngine().Run(context.Background(), []scribe.Task{{Script: exampleScript(), Target: scribe.Target{Host: "localhost"}}}, func(r scribe.Result) error {
		fmt.Println(r.Status, r.Verdict)
		return nil
	})
	if err != nil {
		panic(err)
	}
	// Output: completed unknown
}
func ExampleEngine_Batch() {
	reader := pingpp.NewReader(strings.NewReader(`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"127.0.0.1","port":80,"transport":"tcp","state":"open","execution":"attempted"}]}}`))
	var tasks []scribe.Task
	for {
		target, ok, err := reader.Next(context.Background())
		if err != nil {
			panic(err)
		}
		if !ok {
			break
		}
		tasks = append(tasks, scribe.Task{Script: exampleScript(), Target: target})
	}
	results, err := exampleEngine().Batch(context.Background(), tasks)
	if err != nil {
		panic(err)
	}
	fmt.Println(len(results), results[0].Verdict)
	// Output: 1 unknown
}
func ExampleEngine_Stream() {
	index, err := scribe.NewIndex([]scribe.Script{exampleScript()})
	if err != nil {
		panic(err)
	}
	reader := pingpp.NewReader(strings.NewReader(`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"127.0.0.1","port":22,"transport":"tcp","state":"open","execution":"attempted"}],"claims":[{"subject":"127.0.0.1/tcp/22","kind":"service","value":"ssh","confidence":"exact"}]}}`))
	err = exampleEngine().Stream(context.Background(), index, reader.Next, func(r scribe.Result) error {
		fmt.Println(r.Status, r.Verdict, r.Output.SkipReason)
		return nil
	})
	if err != nil {
		panic(err)
	}
	// Output: skipped unknown script hints exclude supplied endpoint facts
}

// ExampleEvents shows how transports derive observations without changing verdicts.
func ExampleEvents() {
	events := scribe.Events(scribe.Result{SchemaVersion: 1, Status: scribe.Skipped, Verdict: scribe.Unknown})
	for _, event := range events {
		fmt.Println(event.Type, event.Result.Verdict)
	}
	// Output:
	// planning unknown
	// timing unknown
	// verdict unknown
}

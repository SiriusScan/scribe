// This example embeds Scribe and registers a Go function without a subprocess.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

func main() {
	if err := execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute() error {
	runtime, err := lua54.NewNative(lua54.Options{
		Limits: lua54.Limits{CPU: 10_000_000, Memory: 32 << 20, Timeout: 5 * time.Second},
		Functions: map[string]scribe.Function{
			"asset.label": func(ctx context.Context, target scribe.Target, args []any) (any, error) {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if len(args) != 1 {
					return nil, fmt.Errorf("asset.label expects one label")
				}
				label, ok := args[0].(string)
				if !ok || len(label) > 128 {
					return nil, fmt.Errorf("asset.label expects a string of at most 128 bytes")
				}
				return map[string]any{"host": target.Host, "label": label}, nil
			},
		},
	})
	if err != nil {
		return err
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 4, HostConcurrency: 2, ModuleConcurrency: 1, GlobalInterval: time.Millisecond, ScriptTimeout: 5 * time.Second}, runtime)
	if err != nil {
		return err
	}
	task := scribe.Task{
		Target: scribe.Target{Host: "example.internal", Port: 443, Protocol: "tcp", Service: "https", TLS: true},
		Script: scribe.Script{
			ID:      "asset-label",
			Dialect: scribe.Sirius,
			Source: []byte(`return {
  api_version = 1,
  action = function(target, args)
    return {data = sirius.call("asset.label", "inventory")}
  end
}`),
		},
	}
	encoder := json.NewEncoder(os.Stdout)
	return engine.Run(context.Background(), []scribe.Task{task}, func(result scribe.Result) error {
		return encoder.Encode(result)
	})
}

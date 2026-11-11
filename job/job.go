// Package job defines the versioned embedding contract. Catalog ownership remains
// with callers; resolved scripts always pass through the SDK engine.
package job

import (
	"context"
	"fmt"
	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/report"
)

// Request is a schema-v1 invocation; absent capabilities deny all registered calls.
type Request struct {
	// SchemaVersion must be 1; zero is invalid.
	SchemaVersion int `json:"schema_version"`
	// ID is required caller correlation text; empty is invalid.
	ID string `json:"id"`
	// ScriptID identifies resolved source and execution; empty fails engine validation.
	ScriptID string `json:"script_id"`
	// Source is inline Lua text; empty invokes Resolver.
	Source string `json:"source,omitempty"`
	// Dialect must explicitly select sirius or nse; empty is invalid.
	Dialect scribe.Dialect `json:"dialect"`
	// Args contains invocation arguments; nil supplies none.
	Args map[string]any `json:"args,omitempty"`
	// Target contains required endpoint facts; zero is invalid.
	Target scribe.Target `json:"target"`
	// Limits only tightens runtime ceilings; zero inherits, negative timeout is invalid.
	Limits scribe.Limits `json:"limits"`
	// Capabilities lists exact allowed function names; nil and empty both deny all.
	Capabilities []string `json:"capabilities"`
}

// Result preserves job correlation and the conservative report envelope.
type Result struct {
	// SchemaVersion is 1 for Run results; zero is uninitialized.
	SchemaVersion int `json:"schema_version"`
	// ID echoes request correlation text; empty supplies none.
	ID string `json:"id"`
	// Report contains conservative execution evidence; zero is not a successful assessment.
	Report report.Envelope `json:"report"`
}

// Resolver loads caller-owned script source when inline source is absent.
type Resolver func(context.Context, string, scribe.Dialect) ([]byte, error)

// Run executes one job. Missing grants deny every capability. Limits can only
// tighten runtime ceilings. Resolver is only used when inline source is absent.
func Run(ctx context.Context, engine *scribe.Engine, request Request, resolve Resolver) (Result, error) {
	result := Result{SchemaVersion: 1, ID: request.ID}
	if ctx == nil || engine == nil || request.SchemaVersion != 1 || request.ID == "" || request.Limits.Timeout < 0 {
		return result, fmt.Errorf("invalid job request")
	}
	source := []byte(request.Source)
	if len(source) == 0 {
		if resolve == nil {
			return result, fmt.Errorf("script resolver required")
		}
		var err error
		source, err = resolve(ctx, request.ScriptID, request.Dialect)
		if err != nil {
			return result, err
		}
	}
	grants := append([]string{}, request.Capabilities...)
	task := scribe.Task{Script: scribe.Script{ID: request.ScriptID, Source: source, Dialect: request.Dialect, Args: request.Args}, Target: request.Target, Limits: request.Limits, Capabilities: grants}
	err := engine.Run(ctx, []scribe.Task{task}, func(r scribe.Result) error { result.Report = report.Map(r); return nil })
	return result, err
}

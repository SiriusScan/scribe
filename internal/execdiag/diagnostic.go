// Package execdiag carries trusted execution diagnostics across runtime boundaries.
package execdiag

import (
	"context"
	"errors"
)

const (
	Load       = "load"
	Initialize = "initialize"
	Rule       = "rule"
	Action     = "action"
	Output     = "output"
	Plan       = "plan"
	Execution  = "execution"

	Rejected          = "rejected"
	TimedOut          = "timed_out"
	Cancelled         = "cancelled"
	RuleFalse         = "rule_false"
	MissingTargetPort = "missing_target_port"
	ExcludedByHints   = "excluded_by_hints"
	UnsupportedAPI    = "unsupported_api"
	UnsupportedModule = "unsupported_module"
	UnsupportedPhase  = "unsupported_rule_phase"
	UnsupportedDep    = "unsupported_dependencies"
)

// Observation carries trusted metadata alongside a single fixture execution.
type Observation struct {
	Code  string
	Phase string
	Text  *string
}

type recorderKey struct{}

// WithRecorder attaches a private handler to a single execution.
func WithRecorder(ctx context.Context, record func(Observation)) context.Context {
	return context.WithValue(ctx, recorderKey{}, record)
}

// Record publishes metadata when the internal fixture harness is listening.
func Record(ctx context.Context, observation Observation) {
	if record, ok := ctx.Value(recorderKey{}).(func(Observation)); ok {
		record(observation)
	}
}

// Diagnostic is an error from a trusted Go boundary. Lua can see its message.
type Diagnostic struct {
	cause error
	code  string
	phase string
}

func (d *Diagnostic) Error() string { return d.cause.Error() }
func (d *Diagnostic) Unwrap() error { return d.cause }

// WithCode adds a bounded classification to an existing diagnostic.
func WithCode(cause error, code string) error {
	return &Diagnostic{cause: cause, code: code}
}

// At adds a phase while preserving a nested diagnostic's code.
func At(cause error, phase string) error {
	code, _ := Details(cause)
	return &Diagnostic{cause: cause, code: code, phase: phase}
}

// Details returns the diagnostic code and phase. Ordinary errors supply neither.
func Details(err error) (code, phase string) {
	var diagnostic *Diagnostic
	if errors.As(err, &diagnostic) {
		return diagnostic.code, diagnostic.phase
	}
	return "", ""
}

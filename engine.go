package scribe

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

const MaxSourceBytes = 1 << 20

// Options controls orchestration, independently of each runtime's limits.
type Options struct {
	Concurrency int
	// HostConcurrency defaults to Concurrency. Limits are per run and span ports.
	HostConcurrency int
	// HostInterval spaces invocation starts per host; zero disables pacing.
	HostInterval time.Duration
	// HostErrorBudget stops new invocations after this many execution errors.
	// Already running invocations finish; zero disables the budget.
	HostErrorBudget int
	Strategy        Strategy
	// Window bounds pending tasks and target lookahead; default 256.
	Window int
	// MaxHosts bounds retained per-run host accounting; default 65536.
	MaxHosts int
}

// Engine holds immutable runtime registrations. Callers may use Run concurrently
// if their registered runtimes support it, and must not mutate submitted tasks.
type Engine struct {
	options  Options
	workers  int
	runtimes map[Dialect]Runtime
}

func New(options Options, runtimes ...Runtime) (*Engine, error) {
	if options.Concurrency == 0 {
		options.Concurrency = 4
	}
	if options.Concurrency < 1 || options.Concurrency > 256 {
		return nil, errors.New("concurrency must be between 1 and 256")
	}
	if options.HostConcurrency == 0 {
		options.HostConcurrency = options.Concurrency
	}
	if options.HostConcurrency < 1 || options.HostConcurrency > options.Concurrency {
		return nil, errors.New("host concurrency must be between 1 and concurrency")
	}
	if options.HostInterval < 0 || options.HostErrorBudget < 0 {
		return nil, errors.New("host interval and error budget cannot be negative")
	}
	if options.Strategy == "" {
		options.Strategy = ScriptSpray
	}
	if options.Strategy != HostSpray && options.Strategy != ScriptSpray {
		return nil, errors.New("strategy must be host-spray or script-spray")
	}
	if options.Window == 0 {
		options.Window = 256
	}
	if options.Window < 1 || options.Window > 65536 {
		return nil, errors.New("window must be between 1 and 65536")
	}
	if options.MaxHosts == 0 {
		options.MaxHosts = 65536
	}
	if options.MaxHosts < 1 || options.MaxHosts > 1_000_000 {
		return nil, errors.New("max hosts must be between 1 and 1000000")
	}
	engine := &Engine{options: options, workers: options.Concurrency, runtimes: make(map[Dialect]Runtime)}
	for _, runtime := range runtimes {
		if runtime == nil {
			return nil, errors.New("nil runtime")
		}
		dialect := runtime.Dialect()
		if dialect != Sirius && dialect != NSE {
			return nil, fmt.Errorf("unsupported dialect %q", dialect)
		}
		if _, exists := engine.runtimes[dialect]; exists {
			return nil, fmt.Errorf("duplicate runtime for %q", dialect)
		}
		engine.runtimes[dialect] = runtime
	}
	if len(engine.runtimes) == 0 {
		return nil, errors.New("at least one runtime is required")
	}
	return engine, nil
}

// Run validates all tasks before execution and streams results serially. Host
// controls apply within this run. Every submitted task gets a terminal record
// after cancellation while the sink remains available.
func (e *Engine) Run(ctx context.Context, tasks []Task, onResult func(Result) error) error {
	if ctx == nil || onResult == nil {
		return errors.New("context and result callback are required")
	}
	for i, task := range tasks {
		if err := e.validate(task); err != nil {
			return fmt.Errorf("task %d: %w", i, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	n := 0
	return e.run(ctx, func(context.Context) (Task, bool, error) {
		if n == len(tasks) {
			return Task{}, false, nil
		}
		t := tasks[n]
		n++
		return t, true, nil
	}, onResult, true)
}
func (e *Engine) validate(task Task) error {
	if _, ok := e.runtimes[task.Script.Dialect]; !ok {
		return fmt.Errorf("no runtime for dialect %q", task.Script.Dialect)
	}
	if task.Script.ID == "" || len(task.Script.Source) == 0 || len(task.Script.Source) > MaxSourceBytes {
		return fmt.Errorf("script ID and source (at most %d bytes) are required", MaxSourceBytes)
	}
	return task.Target.Validate()
}
func (e *Engine) execute(ctx context.Context, task Task) Result {
	start := time.Now()
	var output Output
	err := ctx.Err()
	if err == nil && task.planSkip != "" {
		output = Output{Skipped: true, SkipReason: task.planSkip}
	} else if err == nil {
		output, err = e.runtimes[task.Script.Dialect].Execute(ctx, task)
	}
	result := Result{SchemaVersion: 1, ScriptID: task.Script.ID, ScriptSHA256: fmt.Sprintf("%x", sha256.Sum256(task.Script.Source)), Dialect: task.Script.Dialect, Target: task.Target, Output: output, Status: Completed, Verdict: Unknown, ElapsedMS: time.Since(start).Milliseconds()}
	if err != nil {
		result.Status, result.Error, result.Output = Failed, err.Error(), Output{Logs: output.Logs, LogsTruncated: output.LogsTruncated}
		if errors.Is(err, context.Canceled) {
			result.Status = Cancelled
		}
	} else if output.Skipped {
		result.Status = Skipped
		result.Output = Output{Skipped: true, SkipReason: output.SkipReason, Logs: output.Logs, LogsTruncated: output.LogsTruncated}
	}
	if result.Status == Completed && task.Script.Dialect == Sirius {
		switch output.Verdict {
		case Vulnerable, NotVulnerable:
			result.Verdict = output.Verdict
		}
	}
	return result
}

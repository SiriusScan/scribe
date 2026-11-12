package scribe

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// MaxSourceBytes bounds script source size to one MiB.
const MaxSourceBytes = 1 << 20

// Options controls orchestration, independently of each runtime's limits.
type Options struct {
	// OnEvent observes ordered per-module lifecycle records; see Event.
	// OnEvent is optional; nil disables observations.
	OnEvent func(Event) error
	// Plan defaults false; true returns planning skips without actions or probes.
	Plan bool
	// ScriptTimeout caps each invocation in nanoseconds (time.Duration); zero adds no engine deadline, negative is invalid.
	ScriptTimeout time.Duration
	// GlobalInterval spaces starts across a run in nanoseconds; zero disables pacing, negative is invalid.
	GlobalInterval time.Duration
	// SNMPCommunity enables v2c identification with exactly this community; empty disables it.
	// At most 255 bytes; it is never included in returned facts.
	SNMPCommunity string
	// PlannerProbes enables bounded passive identification; false disables general probes.
	PlannerProbes bool
	// StrictIdentification requires declared matching products for clean verdicts; false preserves legacy callers.
	StrictIdentification bool
	// Exhaustive executes excluded pairs while retaining clean gates; false skips them.
	Exhaustive bool
	// Concurrency is the worker count, 1–256; zero selects four, negative is invalid.
	Concurrency int
	// ModuleConcurrency caps active invocations sharing a dialect and script ID per run; zero uses Concurrency.
	ModuleConcurrency int
	// HostConcurrency counts active tasks per host across ports; zero uses Concurrency.
	// Values must be 1 through Concurrency; negative is invalid.
	HostConcurrency int
	// HostInterval spaces starts per host in nanoseconds; zero disables pacing, negative is invalid.
	HostInterval time.Duration
	// HostErrorBudget stops new invocations after this many execution errors.
	// Already running invocations finish; zero disables the budget, negative is invalid.
	HostErrorBudget int
	// Strategy selects host-spray or script-spray; empty selects script-spray.
	Strategy Strategy
	// Window counts pending plus active work, 1–65536; zero selects 256, negative is invalid.
	Window int
	// MaxHosts limits retained hosts, 1–1000000; zero selects 65536, negative is invalid.
	MaxHosts int
}

// The zero Engine is not usable; construct one with New.
// Engine holds immutable runtime registrations. Callers may use Run concurrently
// if their registered runtimes support it, and must not mutate submitted tasks.
type Engine struct {
	options  Options
	workers  int
	runtimes map[Dialect]Runtime
}

// New validates options and registers one runtime per explicit dialect.
func New(options Options, runtimes ...Runtime) (*Engine, error) {
	if options.ScriptTimeout < 0 || options.GlobalInterval < 0 {
		return nil, errors.New("timeout and global interval cannot be negative")
	}
	if len(options.SNMPCommunity) > 255 {
		return nil, fmt.Errorf("SNMP community exceeds 255 bytes")
	}
	if options.Concurrency == 0 {
		options.Concurrency = 4
	}
	if options.Concurrency < 1 || options.Concurrency > 256 {
		return nil, errors.New("concurrency must be between 1 and 256")
	}
	if options.ModuleConcurrency == 0 {
		options.ModuleConcurrency = options.Concurrency
	}
	if options.ModuleConcurrency < 1 || options.ModuleConcurrency > options.Concurrency {
		return nil, errors.New("module concurrency must be between 1 and concurrency")
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
// The callback runs synchronously, serially within this run, in completion order
// (not submission order). Slow callbacks apply backpressure. Return an error to
// stop delivery and cancel/drain active executions; Run returns the sink error.
// Callbacks must return promptly and must not wait for Run to finish. A nil Run
// error describes delivery, not a vulnerability verdict; inspect each Result.
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
	cache := make(probeCache)
	n := 0
	return e.run(ctx, func(context.Context) (Task, bool, error) {
		if n == len(tasks) {
			return Task{}, false, nil
		}
		t := tasks[n]
		if e.options.PlannerProbes && !e.options.Plan {
			t.Target = cache.enrich(ctx, t.Target, e.options.MaxHosts, e.options.SNMPCommunity)
		}
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
	if e.options.ScriptTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.options.ScriptTimeout)
		defer cancel()
	}
	start := time.Now()
	hints := task.preparedHints
	var planErr error
	if hints == nil {
		var idx *Index
		idx, planErr = NewIndex([]Script{task.Script})
		if planErr == nil {
			hints = &idx.entries[0].hints
		}
	}
	if planErr == nil && hints.Match != nil {
		ok, _ := hints.Match.evaluate(task.Target)
		if !ok && !e.options.Exhaustive {
			task.planSkip = hints.Match.skipReason(task.Target)
		}
	}
	var output Output
	err := ctx.Err()
	if err == nil {
		err = planErr
	}
	if err == nil && task.planSkip != "" {
		output = Output{Skipped: true, SkipReason: task.planSkip}
	} else if err == nil && e.options.Plan {
		output = Output{Skipped: true, SkipReason: "plan: would run (dynamic Lua rules not evaluated)"}
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
			if output.Verdict == NotVulnerable && (hints.Match != nil || e.options.StrictIdentification) {
				h := hints
				identified := task.Target.Product != "" && contains(h.Products, task.Target.Product)
				if h.Match != nil {
					_, identified = h.Match.evaluate(task.Target)
				}
				if !identified {
					result.Verdict = Unknown
					result.Status = Skipped
					result.Output = Output{Skipped: true, SkipReason: "clean verdict requires a matching declared product identification"}
				}
			}
		}
	}
	result.PlannerMiss = task.plannerExcluded && result.Status == Completed && result.Verdict != Unknown
	return result
}

package scribe

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

const MaxSourceBytes = 1 << 20

// Options controls orchestration, independently of each runtime's limits.
type Options struct {
	Concurrency int
}

// Engine holds immutable runtime registrations. Callers may use Run concurrently
// if their registered runtimes support it, and must not mutate submitted tasks.
type Engine struct {
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
	engine := &Engine{workers: options.Concurrency, runtimes: make(map[Dialect]Runtime)}
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

// Run validates all tasks before execution and streams results as they finish.
// The callback runs serially within this Run; returning an error cancels the run.
// Script errors appear in Results and also cause a non-nil summary error.
// Cancellation waits for active bounded runtimes to finish; it does not abandon
// goroutines or claim instantaneous interruption of CPU-only Lua execution.
func (e *Engine) Run(ctx context.Context, tasks []Task, onResult func(Result) error) error {
	if ctx == nil || onResult == nil {
		return errors.New("context and result callback are required")
	}
	for i, task := range tasks {
		if _, exists := e.runtimes[task.Script.Dialect]; !exists {
			return fmt.Errorf("task %d: no runtime for dialect %q", i, task.Script.Dialect)
		}
		if task.Script.ID == "" || len(task.Script.Source) == 0 || len(task.Script.Source) > MaxSourceBytes {
			return fmt.Errorf("task %d: script ID and source (at most %d bytes) are required", i, MaxSourceBytes)
		}
		if err := task.Target.Validate(); err != nil {
			return fmt.Errorf("task %d: %w", i, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan Task)
	results := make(chan Result, e.workers)
	var workers sync.WaitGroup
	workerCount := min(e.workers, len(tasks))
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for task := range jobs {
				start := time.Now()
				var output Output
				err := runCtx.Err()
				if err == nil {
					output, err = e.runtimes[task.Script.Dialect].Execute(runCtx, task)
				}
				result := Result{SchemaVersion: 1, ScriptID: task.Script.ID, ScriptSHA256: fmt.Sprintf("%x", sha256.Sum256(task.Script.Source)), Dialect: task.Script.Dialect, Target: task.Target, Output: output, Status: Completed, Verdict: Unknown, ElapsedMS: time.Since(start).Milliseconds()}
				if err != nil {
					result.Status, result.Error, result.Output = Failed, err.Error(), Output{Logs: output.Logs, LogsTruncated: output.LogsTruncated}
					if errors.Is(err, context.Canceled) {
						result.Status = Cancelled
					}
				} else if output.Skipped {
					result.Status = Skipped
					result.Output = Output{Skipped: true, Logs: output.Logs, LogsTruncated: output.LogsTruncated}
				}
				if result.Status == Completed && task.Script.Dialect == Sirius {
					switch output.Verdict {
					case Vulnerable, NotVulnerable:
						result.Verdict = output.Verdict
					}
				}
				results <- result
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, task := range tasks {
			jobs <- task
		}
	}()
	go func() { workers.Wait(); close(results) }()
	var callbackErr error
	failures := 0
	for result := range results {
		if result.Status == Failed {
			failures++
		}
		if callbackErr == nil {
			callbackErr = onResult(result)
			if callbackErr != nil {
				cancel()
			}
		}
	}
	if callbackErr != nil {
		return callbackErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if failures > 0 {
		return fmt.Errorf("%d script execution(s) failed", failures)
	}
	return nil
}

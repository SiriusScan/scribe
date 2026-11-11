package scribe

import "context"

// Batch collects terminal records in completion order. Execution errors remain
// in each Result; the returned error describes validation, cancellation or sink
// failure. Always inspect both status and verdict.
func (e *Engine) Batch(ctx context.Context, tasks []Task) ([]Result, error) {
	var results []Result
	err := e.Run(ctx, tasks, func(r Result) error { results = append(results, r); return nil })
	return results, err
}

// Stream consumes caller-supplied endpoint facts with bounded lookahead and
// serial result delivery. It includes selection skips and their reasons.
// The producer must honor cancellation, including interrupting blocking input.
func (e *Engine) Stream(ctx context.Context, index *Index, next func(context.Context) (Target, bool, error), sink func(Result) error) error {
	return e.RunTargetStream(ctx, index, next, sink)
}

Run `go run ./examples/embed` from the repository root. This compiling example registers a context-aware capability and executes a native script with JSON output.

Global and host intervals pace script admissions, not capability calls. ModuleConcurrency caps active tasks with the same dialect and script ID across hosts within one Run; use stable unique IDs. Its zero value uses global concurrency. Host and module caps apply together. Limits are per run; embedders coordinate independent runs themselves. ScriptTimeout adds a cooperative invocation deadline; registered Go functions must honor context.

Use StrictIdentification for product-specific checks and supply authoritative product/version/CPE facts. Match ports are advisory. Only completed explicit verdicts establish findings or clean assessments; errors, skips and missing verdicts remain inconclusive. A sink error stops delivery and cancels work, so require a complete stream. See examples/external for external-module and persistence acceptance.

Result streaming uses Engine.Run(ctx, tasks, callback); run this example with
`go run ./examples/embed`. The JSON encoder callback receives terminal results
serially in completion order and provides backpressure. Return a storage/write
error to cancel and drain execution; delivery stops when the sink fails. Keep
the sink available during cancellation to receive queued terminal records.
Callbacks must return promptly. A successful Run is not a clean assessment: inspect
execution status and explicit verdicts; absent verdicts remain unknown.

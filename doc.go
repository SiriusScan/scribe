// Package scribe executes scripts against caller-supplied endpoint facts.
//
// Select a dialect explicitly and use New to configure an Engine. Run executes
// one task; Batch and Stream provide bounded scheduling. Each invocation owns
// its interpreter. Callers own discovery, persistence, and capability policy.
// Execution status and verdict are independent: only completed explicit verdicts
// establish findings; unknown, skipped, failed, and missing results are inconclusive.
//
// Versioning follows semantic versions. The v1 public Go API is stable within major version 1; consumers should pin
// a tagged module version. The NSE dialect remains an experimental subset. Job and report envelopes
// have independent schema versions. Version reports Scribe module metadata.
package scribe

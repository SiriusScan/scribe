// Package scribe executes scripts against caller-supplied endpoint facts.
//
// Select a dialect explicitly and use New to configure an Engine. Run executes
// one task; Batch and Stream provide bounded scheduling. Each invocation owns
// its interpreter. Callers own discovery, persistence, and capability policy.
// Execution status and verdict are independent: only completed explicit verdicts
// establish findings; unknown, skipped, failed, and missing results are inconclusive.
//
// Versioning follows semantic versions. Before v1.0, minor releases may change
// APIs; consumers should pin a tagged module version. Job and report envelopes
// have independent schema versions. Version reports Scribe module metadata.
package scribe

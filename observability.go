package scribe

// Event is a schema v1 observation. Each terminal module record produces planning,
// timing and verdict events in that order. Planning is retrospective: callbacks
// run at result delivery, outside the Lua state. Concurrent runs may invoke the
// same callback concurrently. Callbacks must return promptly; an error cancels
// delivery just like a result sink error. Missing events are inconclusive.
type Event struct {
	// SchemaVersion is 1 for generated events; zero is uninitialized.
	SchemaVersion int `json:"schema_version"`
	// Type is planning, timing or verdict; empty is uninitialized.
	Type string `json:"type"`
	// Result preserves terminal evidence; zero supplies no completion or assessment.
	Result Result `json:"result"`
}

// Events derives transport-independent observations from a terminal result.
// Planning includes status and output.skip_reason; timing uses elapsed_ms;
// verdict preserves the independent execution status and explicit verdict.
func Events(result Result) []Event {
	return []Event{{1, "planning", result}, {1, "timing", result}, {1, "verdict", result}}
}

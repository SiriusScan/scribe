// Package acceptance is the Phase 0 external-import gate for Scribe.
//
// It is a separate Go module that imports github.com/SiriusScan/scribe the
// way an outside consumer would (a replace directive points at the repository
// root until a tagged release exists). Its tests run the same native script
// through the SDK and a freshly built scribe CLI against a controlled local
// HTTP service, compare the structured output, and cover cancellation,
// rules, limits, and error propagation.
package acceptance

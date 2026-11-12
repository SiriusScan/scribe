package pingpp

import (
	"context"
	"fmt"
	"io"

	"github.com/SiriusScan/scribe"
)

// Run consumes a bounded pingpp.scan/v1 JSONL stream through the engine planner.
// The caller owns input interruption and the engine's registered capabilities.
// Results retain execution status and explicit verdicts; a nil error is not a
// vulnerability assessment. Earlier documents may emit results before a later
// document fails, so callers must require successful stream completion.
func Run(ctx context.Context, engine *scribe.Engine, index *scribe.Index, input io.Reader, sink func(scribe.Result) error) error {
	if engine == nil || index == nil || input == nil || sink == nil {
		return fmt.Errorf("ping++ run requires engine, index, input and sink")
	}
	return engine.RunTargetStream(ctx, index, NewReader(input).Next, sink)
}

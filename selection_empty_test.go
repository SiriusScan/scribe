package scribe

import (
	"context"
	"strings"
	"testing"
)

func TestEmptyIndexRejectsBeforeProducer(t *testing.T) {
	// No runtime is needed: invalid plans must fail before scheduling.
	e := &Engine{}
	for _, drain := range []bool{false, true} {
		err := e.runTargets(context.Background(), &Index{}, func(context.Context) (Target, bool, error) {
			t.Fatal("empty index invoked producer")
			return Target{}, false, nil
		}, func(Result) error {
			t.Fatal("empty index emitted result")
			return nil
		}, drain)
		if err == nil || !strings.Contains(err.Error(), "index must contain scripts") {
			t.Fatalf("error=%v", err)
		}
	}
}

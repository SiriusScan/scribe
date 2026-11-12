package pingpp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestReaderReleasesTerminalInput(t *testing.T) {
	for _, wire := range []string{"", "invalid", `{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[]}}`} {
		r := NewReader(strings.NewReader(wire))
		_, ok, first := r.Next(context.Background())
		if ok || r.scan != nil || r.pending != nil {
			t.Fatalf("terminal reader retains input: %+v", r)
		}
		for i := 0; i < 3; i++ {
			_, ok, err := r.Next(context.Background())
			if ok || !errors.Is(err, first) {
				t.Fatalf("unstable terminal result: %v, %v", ok, err)
			}
		}
	}
}

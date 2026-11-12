package pingpp

import (
	"context"
	"strings"
	"testing"
)

func TestWireAmbiguity(t *testing.T) {
	for _, input := range []string{
		`{"schema_version":"bad","schema_version":"pingpp.scan/v1","asset":{"endpoints":[]}}`,
		`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[],"endpoints":[]}}`,
		`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[],"claims":[{"product":"a","product":"b"}]}}`,
		`{"a":1,"\u0061":2}`,
		strings.Repeat(`[`, 130) + strings.Repeat(`]`, 130),
	} {
		r := NewReader(strings.NewReader(input))
		for i := 0; i < 2; i++ {
			_, ok, err := r.Next(context.Background())
			if ok || err == nil {
				t.Fatalf("ambiguous document accepted: %s", input)
			}
		}
	}
	for _, input := range []string{`{"a":1,"b":{"a":2}}`, `[{"a":1},{"a":2}]`} {
		if err := validateWire([]byte(input)); err != nil {
			t.Fatal(err)
		}
	}
}

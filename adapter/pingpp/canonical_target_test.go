package pingpp

import (
	"context"
	"strings"
	"testing"
)

func TestReaderCanonicalHostAcrossDocuments(t *testing.T) {
	for _, addresses := range [][]string{{"2001:0db8:0:0:0:0:0:1", "2001:db8::1"}, {"::ffff:192.0.2.1", "192.0.2.1"}} {
		var input strings.Builder
		for _, address := range addresses {
			input.WriteString(`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"` + address + `","port":443,"transport":"tcp","state":"open","execution":"attempted"}]}}` + "\n")
		}
		r := NewReader(strings.NewReader(input.String()))
		first, ok, err := r.Next(context.Background())
		if err != nil || !ok {
			t.Fatalf("first: %v %v", ok, err)
		}
		second, ok, err := r.Next(context.Background())
		if err != nil || !ok {
			t.Fatalf("second: %v %v", ok, err)
		}
		if first.Host != second.Host || first.IP != second.IP || first.Host != addresses[1] {
			t.Fatalf("host keys differ: %+v %+v", first, second)
		}
		if _, ok, err := r.Next(context.Background()); ok || err != nil {
			t.Fatalf("EOF: %v %v", ok, err)
		}
	}
}

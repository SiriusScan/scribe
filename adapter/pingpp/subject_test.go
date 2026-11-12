package pingpp

import (
	"encoding/json"
	"testing"
)

func TestCanonicalClaimSubjects(t *testing.T) {
	for _, address := range []string{"2001:db8::1", "2001:0db8:0:0:0:0:0:1"} {
		var d Document
		err := json.Unmarshal([]byte(`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"`+address+`","port":443,"transport":"tcp","state":"open","execution":"attempted"}],"claims":[{"subject":"2001:0db8:0:0:0:0:0:1/tcp/443","kind":"product","product":"example","confidence":"strong"},{"subject":"2001:db8::1/tcp/443","kind":"product","product":"example","version":"2","confidence":"exact"},{"subject":"2001:db8::1/udp/443","kind":"product","product":"wrong","confidence":"exact"},{"subject":"2001:db8::1/tcp/80","kind":"product","product":"wrong","confidence":"exact"}]}}`), &d)
		if err != nil {
			t.Fatal(err)
		}
		targets, err := Targets(d)
		if err != nil || len(targets) != 1 {
			t.Fatalf("%v %v", targets, err)
		}
		if got := targets[0]; got.Product != "example" || got.Version != "2" || got.Confidence != 1 {
			t.Fatalf("%+v", got)
		}
	}
	for _, subject := range []string{"2001:db8::1", "2001:db8::1/tcp/0443", "2001:db8::1/tcp/0", "2001:db8::1/sctp/443"} {
		if _, ok := canonicalSubject(subject); ok {
			t.Fatalf("accepted %q", subject)
		}
	}
}

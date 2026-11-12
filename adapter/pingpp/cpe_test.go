package pingpp

import (
	"context"
	"strings"
	"testing"
)

func TestCPEEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, extra string
		want        bool
	}{
		{"accepted", "", true},
		{"version conflict", `,{"subject":"192.0.2.1/tcp/443","kind":"product","product":"nginx","version":"2","confidence":"exact"}`, false},
		{"product conflict", `,{"subject":"192.0.2.1/tcp/443","kind":"product","product":"other","confidence":"exact"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := `{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"192.0.2.1","port":443,"transport":"tcp","state":"open","execution":"attempted"}],"claims":[{"subject":"192.0.2.1/tcp/443","kind":"product","product":"nginx","version":"1","confidence":"strong","cpe":"cpe:/a:nginx:nginx:1"},{"subject":"192.0.2.1/tcp/443","kind":"service","confidence":"exact","cpe":"ignored"},{"subject":"other","kind":"product","product":"nginx","confidence":"exact","cpe":"ignored"},{"subject":"192.0.2.1/tcp/443","kind":"product","product":"nginx","confidence":"weak","cpe":"ignored"},{"subject":"192.0.2.1/tcp/443","kind":"product","product":"nginx","confidence":"exact","contradiction_ids":["x"],"cpe":"ignored"}` + tc.extra + `]}}`
			r := NewReader(strings.NewReader(wire))
			got, ok, err := r.Next(context.Background())
			if err != nil || !ok {
				t.Fatalf("%v %v", ok, err)
			}
			if tc.want {
				if len(got.CPE) != 1 || got.CPE[0] != "cpe:/a:nginx:nginx:1" {
					t.Fatalf("%+v", got)
				}
			} else if len(got.CPE) != 0 {
				t.Fatalf("conflicting identity supplied CPE: %+v", got)
			}
			if _, ok, err := r.Next(context.Background()); ok || err != nil {
				t.Fatalf("EOF: %v %v", ok, err)
			}
		})
	}
}

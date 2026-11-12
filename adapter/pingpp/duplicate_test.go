package pingpp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestDuplicateEndpoints(t *testing.T) {
	for _, tc := range []struct {
		name, address, transport, state string
		reject                          bool
	}{
		{"repeated", "::1", "tcp", "open", true},
		{"conflicting state", "::1", "tcp", "closed", true},
		{"equivalent IPv6", "0:0:0:0:0:0:0:1", "tcp", "open", true},
		{"other transport", "::1", "udp", "open", false},
		{"other address", "::2", "tcp", "open", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var d Document
			if err := json.Unmarshal([]byte(`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"::1","port":80,"transport":"tcp","state":"open","execution":"attempted"}]}}`), &d); err != nil {
				t.Fatal(err)
			}
			d.Asset.Endpoints = append(d.Asset.Endpoints, Endpoint{Address: tc.address, Port: 80, Transport: tc.transport, State: tc.state, Execution: "attempted"})
			targets, err := Targets(d)
			if tc.reject {
				if err == nil || len(targets) != 0 {
					t.Fatalf("targets=%v err=%v", targets, err)
				}
			} else if err != nil || len(targets) != 2 {
				t.Fatalf("targets=%v err=%v", targets, err)
			}
		})
	}
}

func TestDuplicateReaderTerminal(t *testing.T) {
	const endpoint = `{"address":"127.0.0.1","port":80,"transport":"tcp","state":"open","execution":"attempted"}`
	r := NewReader(strings.NewReader(`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[` + endpoint + `,` + endpoint + `]}}`))
	for i := 0; i < 2; i++ {
		target, ok, err := r.Next(context.Background())
		if err == nil || ok || target.Host != "" {
			t.Fatalf("target=%v ok=%v err=%v", target, ok, err)
		}
	}
}

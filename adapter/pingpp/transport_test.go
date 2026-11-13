package pingpp

import (
	"encoding/json"
	"testing"
)

func TestTransportClaims(t *testing.T) {
	for _, kind := range []string{"protocol", "service"} {
		t.Run(kind, func(t *testing.T) {
			for _, tc := range []struct {
				transport, confidence string
				conflict              bool
			}{
				{"tcp", "exact", false}, {"tcp", "strong", false},
				{"udp", "exact", true}, {"udp", "strong", true}, {"udp", "weak", false},
			} {
				t.Run(tc.transport+tc.confidence, func(t *testing.T) {
					var d Document
					if err := json.Unmarshal([]byte(`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"127.0.0.1","port":443,"transport":"tcp","state":"open","execution":"attempted"}],"claims":[]}}`), &d); err != nil {
						t.Fatal(err)
					}
					subject := "127.0.0.1/tcp/443"
					d.Asset.Claims = []Claim{
						{Subject: subject, Kind: kind, Value: tc.transport, Confidence: tc.confidence},
						{Subject: subject, Kind: "service", Value: "http", Confidence: "exact"},
						{Subject: subject, Kind: "protocol", Value: "tls", Confidence: "exact"},
						{Subject: subject, Kind: "product", Product: "nginx", Version: "1.2", Confidence: "exact"},
					}
					for i := 0; i < 2; i++ {
						targets, err := Targets(d)
						if err != nil || len(targets) != 1 {
							t.Fatalf("targets=%v err=%v", targets, err)
						}
						got := targets[0]
						if tc.conflict {
							if got.Service != "" || got.Product != "" || got.Version != "" || got.Confidence != 0 || got.TLS {
								t.Fatalf("contradictory identity: %+v", got)
							}
						} else if got.Service != "http" || got.Product != "nginx" || !got.TLS {
							t.Fatalf("lost identity: %+v", got)
						}
						for l, r := 0, len(d.Asset.Claims)-1; l < r; l, r = l+1, r-1 {
							d.Asset.Claims[l], d.Asset.Claims[r] = d.Asset.Claims[r], d.Asset.Claims[l]
						}
					}
				})
			}
		})
	}
}

func TestUDPWithTLSClaim(t *testing.T) {
	for _, confidence := range []string{"exact", "strong", "weak"} {
		for _, kind := range []string{"protocol", "service"} {
			var d Document
			if err := json.Unmarshal([]byte(`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"127.0.0.1","port":443,"transport":"udp","state":"open","execution":"attempted"}]}}`), &d); err != nil {
				t.Fatal(err)
			}
			subject := "127.0.0.1/udp/443"
			d.Asset.Claims = []Claim{
				{Subject: subject, Kind: kind, Value: "tls", Confidence: confidence},
				{Subject: subject, Kind: "service", Value: "dns", Confidence: "exact"},
				{Subject: subject, Kind: "product", Product: "example", Version: "1.0", CPE: "cpe:/a:example:example:1.0", Confidence: "exact"},
			}
			for order := 0; order < 2; order++ {
				targets, err := Targets(d)
				if err != nil || len(targets) != 1 {
					t.Fatalf("targets=%v err=%v", targets, err)
				}
				got := targets[0]
				if got.Protocol != "udp" || got.TLS {
					t.Fatalf("transport changed: %+v", got)
				}
				if confidence == "weak" {
					if got.Product != "example" || got.Service != "dns" {
						t.Fatalf("weak claim affected identity: %+v", got)
					}
				} else if got.Product != "" || got.Service != "" || got.Version != "" || got.Confidence != 0 || len(got.CPE) != 0 {
					t.Fatalf("unsupported TLS transport established identity: %+v", got)
				}
				d.Asset.Claims[0], d.Asset.Claims[2] = d.Asset.Claims[2], d.Asset.Claims[0]
			}
		}
	}
}

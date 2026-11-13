package pingpp

import (
	"encoding/json"
	"testing"
)

func TestImplicitTLSServiceClaims(t *testing.T) {
	for secure, base := range map[string]string{"https": "http", "imaps": "imap", "pop3s": "pop3", "smtps": "smtp", "ldaps": "ldap"} {
		for _, kind := range []string{"service", "protocol"} {
			for _, transport := range []string{"tcp", "udp"} {
				for _, confidence := range []string{"exact", "strong", "weak"} {
					for _, sibling := range []string{"", base, "unrelated"} {
						var d Document
						if err := json.Unmarshal([]byte(`{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"address":"127.0.0.1","port":443,"transport":"`+transport+`","state":"open","execution":"attempted"}]}}`), &d); err != nil {
							t.Fatal(err)
						}
						subject := "127.0.0.1/" + transport + "/443"
						d.Asset.Claims = []Claim{{Subject: subject, Kind: kind, Value: secure, Confidence: confidence}}
						if sibling != "" {
							d.Asset.Claims = append(d.Asset.Claims, Claim{Subject: subject, Kind: "service", Value: sibling, Confidence: "exact"})
						}
						for order := 0; order < 2; order++ {
							targets, err := Targets(d)
							if err != nil || len(targets) != 1 {
								t.Fatalf("%v %v", targets, err)
							}
							got := targets[0]
							wantService, wantTLS := sibling, false
							if confidence != "weak" {
								wantService, wantTLS = base, true
								if transport != "tcp" || sibling == "unrelated" {
									wantService, wantTLS = "", false
								}
							}
							if got.Service != wantService || got.TLS != wantTLS || got.Product != "" || got.Confidence != 0 {
								t.Fatalf("%s/%s/%s: %+v", transport, confidence, sibling, got)
							}
							if len(d.Asset.Claims) == 2 {
								d.Asset.Claims[0], d.Asset.Claims[1] = d.Asset.Claims[1], d.Asset.Claims[0]
							}
						}
					}
				}
			}
		}

	}
}

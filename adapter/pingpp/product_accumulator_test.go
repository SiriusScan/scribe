package pingpp

import "testing"

func TestProductConflictSurvivesLaterAgreement(t *testing.T) {
	for _, products := range [][]string{{"a", "b", "a"}, {"b", "a", "a"}, {"a", "a", "b"}} {
		d := Document{SchemaVersion: SchemaVersion}
		// Exercise the public adapter with repeated conflicting identity evidence.
		d.Asset = &struct {
			Endpoints []Endpoint `json:"endpoints"`
			Claims    []Claim    `json:"claims"`
		}{Endpoints: []Endpoint{{Address: "127.0.0.1", Port: 80, Transport: "tcp", State: "open", Execution: "attempted"}}}
		for _, p := range products {
			d.Asset.Claims = append(d.Asset.Claims, Claim{Subject: "127.0.0.1/tcp/80", Kind: "product", Product: p, Version: "1", Confidence: "exact", CPE: "cpe:/a:test"})
		}
		targets, err := Targets(d)
		if err != nil || len(targets) != 1 {
			t.Fatalf("targets=%v err=%v", targets, err)
		}
		got := targets[0]
		if got.Product != "" || got.Version != "" || got.Confidence != 0 || len(got.CPE) != 0 {
			t.Fatalf("conflicting products established identity: %+v", got)
		}
	}
}

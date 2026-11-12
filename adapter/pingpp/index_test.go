package pingpp

import (
	"encoding/json"
	"fmt"
	"testing"
)

func indexedDocument(t testing.TB) Document {
	t.Helper()
	var d Document
	if err := json.Unmarshal([]byte(`{"schema_version":"pingpp.scan/v1","asset":{}}`), &d); err != nil {
		t.Fatal(err)
	}
	for port := 1; port <= 128; port++ {
		d.Asset.Endpoints = append(d.Asset.Endpoints, Endpoint{Address: "127.0.0.1", Port: uint16(port), Transport: "tcp", State: "open", Execution: "attempted"})
	}
	for round := 0; round < 16; round++ {
		for port := 1; port <= 128; port++ {
			d.Asset.Claims = append(d.Asset.Claims, Claim{Subject: fmt.Sprintf("127.0.0.1/tcp/%d", port), Kind: "product", Product: fmt.Sprintf("product%d", port), Version: "1.2.3", Confidence: "exact"})
		}
	}
	return d
}

func TestInterleavedClaimIndex(t *testing.T) {
	d := indexedDocument(t)
	// A late conflict must affect only its endpoint, even across index growth.
	d.Asset.Claims = append(d.Asset.Claims, Claim{Subject: "127.0.0.1/tcp/64", Kind: "product", Product: "other", Confidence: "strong"})
	targets, err := Targets(d)
	if err != nil || len(targets) != 128 {
		t.Fatalf("targets=%d err=%v", len(targets), err)
	}
	for i, target := range targets {
		if target.Port != uint16(i+1) {
			t.Fatalf("order: %+v", target)
		}
		if i == 63 {
			if target.Product != "" || target.Version != "" || target.Confidence != 0 {
				t.Fatalf("conflict: %+v", target)
			}
		} else if target.Product != fmt.Sprintf("product%d", i+1) || target.Version != "1.2.3" || target.Confidence != 1 {
			t.Fatalf("identity: %+v", target)
		}
	}
}

func BenchmarkInterleavedClaimIndex(b *testing.B) {
	d := indexedDocument(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		targets, err := Targets(d)
		if err != nil || len(targets) != 128 {
			b.Fatal(err)
		}
	}
}

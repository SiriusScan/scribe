package pingpp

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestReader(t *testing.T) {
	f, err := os.Open("testdata/scan.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := NewReader(f)
	target, ok, err := r.Next(context.Background())
	if err != nil || !ok || target.Service != "http" || target.Product != "nginx" || target.Version != "1.24" || !target.TLS || target.Port != 443 {
		t.Fatalf("%+v %v %v", target, ok, err)
	}
	if _, ok, err := r.Next(context.Background()); ok || err != nil {
		t.Fatalf("end: %v %v", ok, err)
	}
}
func TestConservativeFacts(t *testing.T) {
	data, err := os.ReadFile("testdata/scan.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	d.Asset.Claims = append(d.Asset.Claims, Claim{Subject: "192.0.2.1/tcp/443", Kind: "product", Product: "other", Confidence: "strong"})
	ts, err := Targets(d)
	if err != nil || len(ts) != 1 || ts[0].Product != "" {
		t.Fatalf("%+v %v", ts, err)
	}
	d.Asset.Endpoints[0].Execution = "not_attempted_budget"
	ts, err = Targets(d)
	if err != nil || len(ts) != 0 {
		t.Fatalf("%+v %v", ts, err)
	}
}
func TestStreamErrors(t *testing.T) {
	for _, input := range []string{"", "{}", "{", `{"schema_version":"pingpp.scan/v1","error":{"message":"cancelled"}}`, strings.Repeat("x", 4<<20)} {
		r := NewReader(strings.NewReader(input))
		if _, _, err := r.Next(context.Background()); err == nil {
			t.Fatalf("accepted %.40s", input)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := NewReader(strings.NewReader("{}")).Next(ctx); err != context.Canceled {
		t.Fatal(err)
	}
}

// Arbitrary mixed documents must terminate without inventing invalid endpoints.
func FuzzReader(f *testing.F) {
	data, err := os.ReadFile("testdata/scan.jsonl")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(data))
	f.Add(`{"schema_version":"pingpp.scan/v1","error":"failed"}`)
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 65536 {
			t.Skip()
		}
		r := NewReader(strings.NewReader(data))
		for i := 0; i < 1024; i++ {
			target, ok, err := r.Next(context.Background())
			if err != nil || !ok {
				return
			}
			if target.Host == "" || target.Port == 0 {
				t.Fatalf("invalid endpoint: %+v", target)
			}
		}
	})
}

// Conflicting versions must not depend on the order of wire claims.
func TestConflictingVersionOrder(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		data, err := os.ReadFile("testdata/scan.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		var d Document
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatal(err)
		}
		d.Asset.Claims = append(d.Asset.Claims, Claim{Subject: "192.0.2.1/tcp/443", Kind: "product", Product: "nginx", Version: "other", Confidence: "strong"})
		if reverse {
			for i, j := 0, len(d.Asset.Claims)-1; i < j; i, j = i+1, j-1 {
				d.Asset.Claims[i], d.Asset.Claims[j] = d.Asset.Claims[j], d.Asset.Claims[i]
			}
		}
		targets, err := Targets(d)
		if err != nil || len(targets) != 1 {
			t.Fatalf("targets=%+v err=%v", targets, err)
		}
		got := targets[0]
		if got.Product != "" || got.Version != "" || got.Service != "http" || !got.TLS {
			t.Fatalf("conflicting identity: %+v", got)
		}
	}
}

func TestEndpointClaimIsolation(t *testing.T) {
	data, err := os.ReadFile("testdata/scan.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var d Document
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatal(err)
	}
	original, err := Targets(d)
	if err != nil || len(original) != 1 {
		t.Fatalf("fixture: %v %v", original, err)
	}
	second := d.Asset.Endpoints[0]
	second.Port = 8443
	d.Asset.Endpoints = append(d.Asset.Endpoints, second)
	d.Asset.Claims = append(d.Asset.Claims, Claim{Subject: "192.0.2.1/tcp/8443", Kind: "product", Product: "isolated", Version: "2", Confidence: "exact"})
	got, err := Targets(d)
	if err != nil || len(got) != 2 {
		t.Fatalf("targets: %v %v", got, err)
	}
	if !reflect.DeepEqual(got[0], original[0]) || got[1].Product != "isolated" || got[1].Version != "2" || got[1].Service != "" || got[1].TLS {
		t.Fatalf("claims crossed endpoints: %+v", got)
	}
}

package pingpp

import (
	"context"
	"encoding/json"
	"os"
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

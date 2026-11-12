package pingpp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/SiriusScan/scribe"
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
		if got.Product != "nginx" || got.Version != "" || got.Service != "http" || !got.TLS {
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

func TestReaderReleasesConsumedTargets(t *testing.T) {
	first := scribe.Target{Host: "192.0.2.1", Port: 80}
	second := scribe.Target{Host: "192.0.2.2", Port: 443}
	backing := []scribe.Target{first, second}
	r := NewReader(strings.NewReader(""))
	r.pending = backing
	for i, want := range []scribe.Target{first, second} {
		got, ok, err := r.Next(context.Background())
		if err != nil || !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("target %d: %+v %v %v", i, got, ok, err)
		}
		if !reflect.DeepEqual(backing[i], scribe.Target{}) {
			t.Fatalf("consumed slot %d retained target", i)
		}
	}
	if r.pending != nil {
		t.Fatal("drained queue retains backing array")
	}
}

func TestUpstreamErrorDiagnosticBound(t *testing.T) {
	for _, size := range []int{16, 1024, 1025, 4 << 20} {
		raw := json.RawMessage(strings.Repeat("x", size))
		targets, err := Targets(Document{SchemaVersion: SchemaVersion, Error: raw})
		if err == nil || len(targets) != 0 {
			t.Fatalf("size %d: targets=%v error=%v", size, targets, err)
		}
		if len(err.Error()) > 1100 {
			t.Fatalf("unbounded diagnostic: %d", len(err.Error()))
		}
		if strings.Contains(err.Error(), "(truncated)") != (size > 1024) {
			t.Fatalf("size %d: incorrect truncation marker", size)
		}
	}
	r := NewReader(strings.NewReader(`{"schema_version":"pingpp.scan/v1","error":"` + strings.Repeat("x", 4096) + `"}`))
	_, ok, err := r.Next(context.Background())
	if ok || err == nil || len(err.Error()) > 1150 {
		t.Fatalf("reader: ok=%v error=%v", ok, err)
	}
	_, ok, again := r.Next(context.Background())
	if ok || again != err {
		t.Fatalf("reader must retain terminal error: %v %v", ok, again)
	}
}

func TestSchemaDiagnosticBound(t *testing.T) {
	for _, size := range []int{16, 1024, 1025, 4 << 20} {
		// Quoted control bytes expand during formatting; bound the input first.
		schema := strings.Repeat("\x01", size)
		targets, err := Targets(Document{SchemaVersion: schema})
		if err == nil || len(targets) != 0 || len(err.Error()) > 4200 {
			t.Fatalf("size %d: targets=%d diagnostic length=%d", size, len(targets), len(fmt.Sprint(err)))
		}
		if strings.Contains(err.Error(), "(truncated)") != (size > 1024) {
			t.Fatalf("size %d: incorrect truncation", size)
		}
	}
	data, err := json.Marshal(Document{SchemaVersion: strings.Repeat("x", 8192)})
	if err != nil {
		t.Fatal(err)
	}
	r := NewReader(strings.NewReader(string(data)))
	_, ok, first := r.Next(context.Background())
	if ok || first == nil || len(first.Error()) > 1200 {
		t.Fatalf("reader: %v %v", ok, first)
	}
	_, ok, again := r.Next(context.Background())
	if ok || again != first {
		t.Fatal("schema failure must remain terminal")
	}
}

func TestInvalidEndpointDiagnosticsBounded(t *testing.T) {
	for _, field := range []string{"address", "transport", "state"} {
		t.Run(field, func(t *testing.T) {
			endpoint := map[string]any{"address": "127.0.0.1", "port": 80, "transport": "tcp", "state": "open", "execution": "attempted"}
			endpoint[field] = strings.Repeat("\"", 100000)
			wire, err := json.Marshal(map[string]any{"schema_version": SchemaVersion, "asset": map[string]any{"endpoints": []any{endpoint}}})
			if err != nil {
				t.Fatal(err)
			}
			r := NewReader(strings.NewReader(string(wire) + "\n"))
			_, ok, first := r.Next(context.Background())
			if ok || first == nil || len(first.Error()) > 5000 || !strings.Contains(first.Error(), "... (truncated)") {
				t.Fatalf("ok=%v error length/content: %v", ok, first)
			}
			_, ok, next := r.Next(context.Background())
			if ok || next != first {
				t.Fatalf("reader failure not terminal: %v %v", ok, next)
			}
		})
	}
}

func TestReaderBoundsDecoderDiagnostics(t *testing.T) {
	// Overflow diagnostics include the complete untrusted numeric token.
	input := `{"schema_version":"pingpp.scan/v1","asset":{"endpoints":[{"port":` + strings.Repeat("9", 16384) + `}]}}`
	r := NewReader(strings.NewReader(input))
	_, ok, err := r.Next(context.Background())
	if ok || err == nil || len(err.Error()) > 1100 || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("ok=%v error=%v", ok, err)
	}
	_, ok, again := r.Next(context.Background())
	if ok || again != err {
		t.Fatalf("terminal error changed: %v", again)
	}
}

func TestProductAgreementWithVersionConflict(t *testing.T) {
	data, err := os.ReadFile("testdata/scan.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	for _, reverse := range []bool{false, true} {
		var d Document
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatal(err)
		}
		d.Asset.Claims = []Claim{
			{Subject: "192.0.2.1/tcp/443", Kind: "product", Product: "nginx", Version: "1.24", Confidence: "strong"},
			{Subject: "192.0.2.1/tcp/443", Kind: "product", Product: "nginx", Version: "1.25", Confidence: "exact"},
			{Subject: "192.0.2.1/tcp/443", Kind: "product", Product: "nginx", Version: "1.25", Confidence: "strong"},
		}
		if reverse {
			d.Asset.Claims[0], d.Asset.Claims[2] = d.Asset.Claims[2], d.Asset.Claims[0]
		}
		targets, err := Targets(d)
		if err != nil || len(targets) != 1 || targets[0].Product != "nginx" || targets[0].Version != "" {
			t.Fatalf("reverse=%v: %+v %v", reverse, targets, err)
		}
	}
}

package scribe

import (
	"net/http"
	"testing"

	"github.com/SiriusScan/scribe/fingerprint"
)

func TestHTTPProductCPESelection(t *testing.T) {
	for _, tc := range []struct{ header, product, cpe string }{
		{"Caddy/2.8.4", "Caddy", "cpe:/a:caddyserver:caddy:2.8.4"},
		{"openresty/1.27.1.1", "OpenResty", "cpe:/a:openresty:openresty:1.27.1.1"},
		{"Caddy", "Caddy", "cpe:/a:caddyserver:caddy:*"},
	} {
		t.Run(tc.header, func(t *testing.T) {
			f := fingerprint.Default().Match("", http.Header{"Server": {tc.header}})
			observed := Target{Product: f.Product, Version: f.Version, CPE: inferredCPE(f.Product, f.Version)}
			if len(observed.CPE) != 1 || observed.CPE[0] != tc.cpe {
				t.Fatalf("facts: %+v", observed)
			}
			m := Match{Products: []string{tc.product}, CPE: []string{tc.cpe}}
			if ok, id := m.evaluate(observed); !ok || !id {
				t.Fatalf("selection: %v %v", ok, id)
			}
			conflict := mergeProbe(Target{Product: "other"}, observed)
			if len(conflict.CPE) != 0 {
				t.Fatal("conflicting product acquired CPE")
			}
			if reason := m.skipReason(conflict); reason != "declarative match: product identification mismatched" {
				t.Fatal(reason)
			}
			observed.Product = ""
			if reason := m.skipReason(observed); reason != "declarative match: product identification missing" {
				t.Fatal(reason)
			}
			m.Products = nil
			if _, id := m.evaluate(observed); id {
				t.Fatal("CPE established clean gate")
			}
		})
	}
	if got := inferredCPE("Caddy", "2.8:injected"); len(got) != 0 {
		t.Fatal(got)
	}
}

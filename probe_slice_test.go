package scribe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestConfidenceCPE(t *testing.T) {
	m := Match{CPE: []string{"cpe:/a:test"}, Confidence: .8, OnUnknown: "run"}
	target := Target{CPE: []string{"cpe:/a:test"}, Confidence: .7}
	if ok, _ := m.evaluate(target); ok {
		t.Fatal("low confidence accepted")
	}
	target.Confidence = .9
	if ok, _ := m.evaluate(target); !ok {
		t.Fatal("matching facts rejected")
	}
	target.CPE = nil
	if ok, _ := m.evaluate(target); ok {
		t.Fatal("missing CPE accepted")
	}
}
func TestHTTPAndTLSProbeCache(t *testing.T) {
	for _, secure := range []bool{false, true} {
		calls := 0
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.Header().Set("Server", "nginx/1.2") })
		var server *httptest.Server
		if secure {
			server = httptest.NewTLSServer(handler)
		} else {
			server = httptest.NewServer(handler)
		}
		host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
		n, _ := strconv.Atoi(port)
		target := Target{Host: host, Port: uint16(n), Protocol: "tcp", TLS: secure}
		cache := make(probeCache)
		got := cache.enrich(context.Background(), target, 1)
		again := cache.enrich(context.Background(), target, 1)
		server.Close()
		if got.Product != "nginx" || again.Product != got.Product || calls != 1 {
			t.Fatalf("%+v calls %d", got, calls)
		}
		if secure && (got.TLSVersion == "" || got.CertSubject == "") {
			t.Fatalf("missing TLS facts: %+v", got)
		}
	}
}

func TestDirectSDKProbeOption(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Server", "nginx/1.2") }))
	defer server.Close()
	host, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	n, _ := strconv.Atoi(port)
	script := Script{ID: "probe", Dialect: Sirius, Source: []byte("-- scribe: {\"match\":{\"products\":[\"nginx\"],\"confidence\":0.8}}")}
	for _, enabled := range []bool{false, true} {
		engine, err := New(Options{PlannerProbes: enabled}, cleanMatchRuntime{})
		if err != nil {
			t.Fatal(err)
		}
		err = engine.Run(context.Background(), []Task{{Script: script, Target: Target{Host: host, Port: uint16(n), Protocol: "tcp"}}}, func(r Result) error {
			if enabled && r.Target.Product != "nginx" {
				t.Fatal(r)
			}
			if !enabled && r.Status != Skipped {
				t.Fatal(r)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

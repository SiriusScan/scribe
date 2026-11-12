package scribe

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
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
		target := Target{Host: host, Port: uint16(n), Protocol: "tcp", TLS: false}
		cache := make(probeCache)
		got := cache.enrich(context.Background(), target, 1)
		again := cache.enrich(context.Background(), target, 1)
		server.Close()
		if got.Product != "nginx" || again.Product != got.Product || calls != 1 {
			t.Fatalf("%+v calls %d", got, calls)
		}
		if len(got.CPE) == 0 {
			t.Fatal("missing CPE", got)
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

func TestManyTargetSelectionReduction(t *testing.T) {
	var scripts []Script
	for i := 1; i <= 100; i++ {
		scripts = append(scripts, Script{ID: strconv.Itoa(i), Dialect: Sirius, Source: []byte("-- scribe: {\"ports\":[" + strconv.Itoa(i) + "]}")})
	}
	idx, err := NewIndex(scripts)
	if err != nil {
		t.Fatal(err)
	}
	selected := 0
	for i := 1; i <= 100; i++ {
		selected += len(idx.Select(Target{Host: "localhost", Port: uint16(i)}))
	}
	if selected != 100 || selected >= len(scripts)*100 {
		t.Fatalf("selected %d versus unfiltered %d", selected, len(scripts)*100)
	}
}

// A real loopback listener exercises the bounded SSH identification path.
func TestSSHListenerAcceptance(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("SSH-2.0-OpenSSH_9.0\r\n"))
	}()
	addr := listener.Addr().(*net.TCPAddr)
	got := make(probeCache).enrich(context.Background(), Target{Host: "127.0.0.1", Port: uint16(addr.Port), Protocol: "tcp"}, 1)
	<-done
	if got.Service != "ssh" || got.Product != "OpenSSH" || got.Version != "9.0" {
		t.Fatalf("SSH facts: %+v", got)
	}
}

func TestDirectSDKProbeDemand(t *testing.T) {
	for _, match := range []string{
		`{"products":["nginx"]}`,
		`{"products":["Apache"],"services":["ssh"]}`,
		`{"any_of":[{"products":["nginx"]},{"products":["Apache"],"services":["ssh"]}]}`,
	} {
		t.Run(match, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			engine, err := New(Options{PlannerProbes: true}, cleanMatchRuntime{})
			if err != nil {
				t.Fatal(err)
			}
			script := Script{ID: "demand", Dialect: Sirius, Source: []byte("-- scribe: {\"match\":" + match + "}")}
			target := Target{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Protocol: "tcp", Product: "nginx", Service: "http"}
			count := 0
			err = engine.Run(context.Background(), []Task{{Script: script, Target: target}}, func(r Result) error { count++; return nil })
			if err != nil || count != 1 {
				t.Fatalf("count=%d error=%v", count, err)
			}
			listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
			conn, err := listener.Accept()
			if err == nil {
				conn.Close()
				t.Fatal("unnecessary identification connection")
			}
		})
	}
}

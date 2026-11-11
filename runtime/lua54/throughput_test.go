package lua54

import (
	"context"
	"fmt"
	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/capability/httpcap"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
)

// Real interpreter execution, including initialization, rules and conversion.
func BenchmarkLuaThroughput(b *testing.B) {
	for _, fixture := range []struct{ name, source string }{
		{"action", `return {api_version=1, action=function(t) return {verdict="unknown", data={host=t.host, value=42}} end}`},
		{"rule_skip", `return {api_version=1, rule=function(t) return false end, action=function() error("unexpected") end}`},
		{"hint_skip", "-- scribe: {\"services\":[\"ssh\"]}\nreturn {api_version=1, rule=function(t) return t.service == 'ssh' end, action=function() return {} end}"},
	} {
		b.Run(fixture.name, func(b *testing.B) {
			r, err := NewNative(Options{})
			if err != nil {
				b.Fatal(err)
			}
			input := task(scribe.Sirius, fixture.source)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := r.Execute(context.Background(), input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// The disabled path executes the same real Lua action over fresh HTTP sockets.
func BenchmarkLuaHTTPReuse(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fixture")) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())
	for _, disabled := range []bool{true, false} {
		b.Run(fmt.Sprintf("disabled=%t", disabled), func(b *testing.B) {
			client, err := httpcap.New(httpcap.Options{DisableReuse: disabled})
			if err != nil {
				b.Fatal(err)
			}
			defer client.Close()
			r, _ := NewNative(Options{Functions: map[string]scribe.Function{"http.get": client.Function}})
			input := task(scribe.Sirius, `return {api_version=1,action=function() local r=sirius.call("http.get","/"); assert(r.status==200);return {data=r.body} end}`)
			input.Target = scribe.Target{Host: u.Hostname(), Port: uint16(port), Protocol: "tcp"}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := r.Execute(context.Background(), input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLuaCacheModes(b *testing.B) {
	for _, entries := range []int{-1, 128} {
		b.Run(fmt.Sprintf("entries=%d", entries), func(b *testing.B) {
			r, _ := NewNative(Options{CacheEntries: entries})
			input := task(scribe.Sirius, `return {api_version=1,action=function(t) return {data={host=t.host,value=42}} end}`)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := r.Execute(context.Background(), input); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkLuaEngineMatrix(b *testing.B) {
	for _, strategy := range []scribe.Strategy{scribe.ScriptSpray, scribe.HostSpray} {
		b.Run(string(strategy), func(b *testing.B) {
			r, _ := NewNative(Options{})
			e, _ := scribe.New(scribe.Options{Concurrency: 4, HostConcurrency: 2, Strategy: strategy}, r)
			var scripts []scribe.Script
			for i := 0; i < 8; i++ {
				scripts = append(scripts, scribe.Script{ID: fmt.Sprint(i), Dialect: scribe.Sirius, Source: []byte(`return {api_version=1,action=function(t) return {data={host=t.host,value=42}} end}`)})
			}
			idx, _ := scribe.NewIndex(scripts)
			targets := make([]scribe.Target, 16)
			for i := range targets {
				targets[i] = scribe.Target{Host: fmt.Sprintf("host-%d", i)}
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n := 0
				if err := e.RunSelected(context.Background(), idx, targets, func(scribe.Result) error { n++; return nil }); err != nil || n != 128 {
					b.Fatalf("n=%d err=%v", n, err)
				}
			}
		})
	}
}

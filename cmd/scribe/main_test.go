package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/SiriusScan/scribe"
)

func scriptFile(t *testing.T, source string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "check.lua")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCLIEmitsStructuredResultsWithoutDiagnosticsOnSuccess(t *testing.T) {
	path := scriptFile(t, `return {
  api_version = 1,
  action = function(target, args)
    return {data = {host = target.host, label = args.label, large = args.large}, findings = {
      {id = "fixture", title = "Observed fixture", severity = "info", evidence = "local script"}
    }}
  end
}`)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--script", path, "--dialect", "sirius", "--host", "example.internal", "--port", "443", "--tls", "--args", `{"label":"example","large":9007199254740993}`}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, stderr.String(), stdout.String())
	}
	var result scribe.Result
	decoder := json.NewDecoder(&stdout)
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("stdout must contain one JSON result: %v: %s", err, stdout.String())
	}
	if result.Status != scribe.Completed || result.ScriptID != "check.lua" || len(result.Output.Findings) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	data, ok := result.Output.Data.(map[string]any)
	if !ok || data["host"] != "example.internal" || data["label"] != "example" || data["large"] != json.Number("9007199254740993") {
		t.Fatalf("target and arguments did not reach the script: %#v", result.Output.Data)
	}
}

func TestCLIRejectsInvalidInputsBeforeProducingResults(t *testing.T) {
	path := scriptFile(t, `error("must not execute")`)
	base := []string{"--script", path, "--dialect", "sirius", "--host", "example.internal"}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing explicit dialect", []string{"--script", path, "--host", "example.internal"}},
		{"unknown dialect", append(append([]string{}, base...), "--dialect", "lua")},
		{"negative port", append(append([]string{}, base...), "--port", "-1")},
		{"overflow port", append(append([]string{}, base...), "--port", "65536")},
		{"scheme in host", append(append([]string{}, base...), "--host", "https://example.internal")},
		{"invalid IP", append(append([]string{}, base...), "--ip", "invalid")},
		{"array arguments", append(append([]string{}, base...), "--args", "[]")},
		{"null arguments", append(append([]string{}, base...), "--args", "null")},
		{"trailing JSON", append(append([]string{}, base...), "--args", "{} {}")},
		{"oversized arguments", append(append([]string{}, base...), "--args", strings.Repeat(" ", 64<<10)+"{}")},
		{"zero timeout", append(append([]string{}, base...), "--timeout", "0s")},
		{"zero CPU", append(append([]string{}, base...), "--cpu", "0")},
		{"zero memory", append(append([]string{}, base...), "--memory", "0")},
		{"invalid concurrency", append(append([]string{}, base...), "--concurrency", "257")},
		{"positional argument", append(append([]string{}, base...), "extra")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(context.Background(), tc.args, &stdout, &stderr); code == 0 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCLIReportsScriptFailureAsExecutionError(t *testing.T) {
	path := scriptFile(t, `return {api_version = 1, action = function() error("probe failed") end}`)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--script", path, "--dialect", "sirius", "--host", "example.internal"}, &stdout, &stderr)
	var result scribe.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("missing structured failure: %v; stderr=%s", err, stderr.String())
	}
	if code == 0 || result.Status != scribe.Failed || len(result.Output.Findings) != 0 || !strings.Contains(result.Error, "probe failed") || stderr.Len() == 0 {
		t.Fatalf("code=%d result=%+v stderr=%s", code, result, stderr.String())
	}
}

func TestCLIRegistersHTTPForTheKnownEndpoint(t *testing.T) {
	var requests atomic.Int32
	var receivedHost atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		receivedHost.Store(r.Host)
		fmt.Fprint(w, "local fixture")
	}))
	defer server.Close()
	ip, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	path := scriptFile(t, `return {
  api_version = 1,
  action = function()
    local response = sirius.call("http.get", "/fixture")
    return {data = {status = response.status, body = response.body}}
  end
}`)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--script", path, "--dialect", "sirius", "--host", "virtual.internal", "--ip", ip, "--port", port}, &stdout, &stderr)
	var result scribe.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("missing result: %v; stderr=%s", err, stderr.String())
	}
	data, ok := result.Output.Data.(map[string]any)
	if code != 0 || result.Status != scribe.Completed || !ok || data["status"] != float64(200) || data["body"] != "local fixture" {
		t.Fatalf("code=%d result=%+v stderr=%s", code, result, stderr.String())
	}
	if requests.Load() != 1 || receivedHost.Load() != net.JoinHostPort("virtual.internal", port) {
		t.Fatalf("requests=%d host=%v", requests.Load(), receivedHost.Load())
	}
}

func TestCLIReportsUnsupportedNSEModuleWithoutFallback(t *testing.T) {
	path := scriptFile(t, `local nmap = require "nmap"
hostrule = function() return true end
action = function() return "must not run" end`)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--script", path, "--dialect", "nse", "--host", "example.internal"}, &stdout, &stderr)
	var result scribe.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("missing structured failure: %v; stderr=%s", err, stderr.String())
	}
	if code == 0 || result.Dialect != scribe.NSE || result.Status != scribe.Failed || !strings.Contains(result.Error, "unsupported Lua module") || len(result.Output.Findings) != 0 {
		t.Fatalf("code=%d result=%+v", code, result)
	}
}

func TestCLIBoundsScriptSourceReads(t *testing.T) {
	for _, source := range []string{"", strings.Repeat("x", scribe.MaxSourceBytes+1)} {
		path := scriptFile(t, source)
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{"--script", path, "--dialect", "sirius", "--host", "example.internal"}, &stdout, &stderr); code == 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "bytes") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	}
}

func TestVersionWithoutTarget(t *testing.T) {
	var out, errs bytes.Buffer
	if code := run(context.Background(), []string{"--version"}, &out, &errs); code != 0 || !strings.Contains(out.String(), "scribe ") {
		t.Fatalf("version: %d %s %s", code, out.String(), errs.String())
	}
}

func TestCheckWithoutTarget(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   int
	}{
		{`return {api_version=1,action=function() error("not executed") end}`, 0},
		{`local x=require "unsupported"`, 1},
	} {
		path := scriptFile(t, tc.source)
		var out, errs bytes.Buffer
		if code := run(context.Background(), []string{"--check", "--dialect", "sirius", "--script", path}, &out, &errs); code != tc.want {
			t.Fatalf("check: %d %s %s", code, out.String(), errs.String())
		}
	}
}

func TestCLIRegistersHEADForTheKnownEndpoint(t *testing.T) {
	var requests atomic.Int32
	var receivedHost atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("X-Probe") != "marker" {
			t.Error("missing Lua request header")
		}
		receivedHost.Store(r.Host)
		fmt.Fprint(w, "local fixture")
	}))
	defer server.Close()
	ip, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	path := scriptFile(t, `return {
  api_version = 1,
  action = function()
    local response = sirius.call("http.head", "/fixture", {["X-Probe"] = "marker"})
    return {data = {status = response.status, body = response.body}}
  end
}`)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--script", path, "--dialect", "sirius", "--host", "virtual.internal", "--ip", ip, "--port", port}, &stdout, &stderr)
	var result scribe.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("missing result: %v; stderr=%s", err, stderr.String())
	}
	data, ok := result.Output.Data.(map[string]any)
	if code != 0 || result.Status != scribe.Completed || !ok || data["status"] != float64(200) || data["body"] != "" {
		t.Fatalf("code=%d result=%+v stderr=%s", code, result, stderr.String())
	}
	if requests.Load() != 1 || receivedHost.Load() != net.JoinHostPort("virtual.internal", port) {
		t.Fatalf("requests=%d host=%v", requests.Load(), receivedHost.Load())
	}
}

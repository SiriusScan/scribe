package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestHTTPMatchesCLI(t *testing.T) {
	for _, source := range []string{`return {api_version=1,action=function() return {data="ok"} end}`, `return {api_version=1,action=function() error("failed") end}`} {
		path := scriptFile(t, source)
		args := []string{"--script", path, "--dialect", "sirius", "--host", "example.internal"}
		var out, diag bytes.Buffer
		run(context.Background(), args, &out, &diag)
		body, _ := json.Marshal(map[string]any{"args": args})
		rec := httptest.NewRecorder()
		runHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/run", bytes.NewReader(body)))
		var cli, httpResult map[string]any
		if err := json.Unmarshal(out.Bytes(), &cli); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &httpResult); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"status", "verdict", "script_id", "error"} {
			if cli[key] != httpResult[key] {
				t.Fatalf("%s: CLI %v HTTP %v", key, cli, httpResult)
			}
		}
		if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/x-ndjson" {
			t.Fatal(rec)
		}
	}
}
func TestHTTPRejectsBadRequests(t *testing.T) {
	for _, body := range []string{`{}`, `null`, `{"args":[]}`, `{"unknown":1}`, `{} {}`, `{"args":["serve"]}`, `{"args":["--host","invalid"]}`} {
		rec := httptest.NewRecorder()
		runHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/run", bytes.NewBufferString(body)))
		if rec.Code != 400 {
			t.Fatalf("%s: %d", body, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	runHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/run", nil))
	if rec.Code != 405 {
		t.Fatal(rec.Code)
	}
}

func TestHTTPInline(t *testing.T) {
	for _, verdict := range []string{"vulnerable", "not_vulnerable", "unknown", "invalid"} {
		t.Run(verdict, func(t *testing.T) {
			source := "return {api_version=1,action=function() return {verdict='" + verdict + "'} end}"
			if verdict == "invalid" {
				source = "return {"
			}
			body, _ := json.Marshal(map[string]any{"args": []string{"--dialect", "sirius", "--host", "example.internal"}, "scripts": []inlineScript{{ID: "check.lua", Source: source}}})
			rec := httptest.NewRecorder()
			runHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/run", bytes.NewReader(body)))
			var result map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err, rec.Body.String())
			}
			if rec.Code != 200 || result["script_id"] != "check.lua" {
				t.Fatal(rec.Body.String())
			}
			if verdict == "invalid" {
				if result["error"] == nil {
					t.Fatal(result)
				}
			} else if result["verdict"] != verdict {
				t.Fatal(result)
			}
		})
	}
}

func TestHTTPInlineMixedAndOversize(t *testing.T) {
	source := "return {api_version=1,action=function() return {verdict='unknown'} end}"
	body, _ := json.Marshal(map[string]any{"args": []string{"--dialect", "sirius", "--host", "example.internal", "--script", scriptFile(t, source)}, "scripts": []inlineScript{{ID: "inline.lua", Source: source}}})
	rec := httptest.NewRecorder()
	runHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/run", bytes.NewReader(body)))
	if rec.Code != 200 || bytes.Count(rec.Body.Bytes(), []byte("\n")) != 2 {
		t.Fatal(rec.Body.String())
	}
	rec = httptest.NewRecorder()
	runHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/run", bytes.NewReader(bytes.Repeat([]byte(" "), 129<<10))))
	if rec.Code != 400 {
		t.Fatal(rec.Code)
	}
}

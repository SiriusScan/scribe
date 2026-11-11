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

package main

import (
	"bytes"
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFactsBatch(t *testing.T) {
	body := `{"args":["--dialect","sirius"],"facts":[{"host":"localhost","port":80,"protocol":"tcp","state":"open","service":"http","product":"fixture","version":"1"},{"host":"localhost","port":81}],"scripts":[{"id":"a","source":"return {api_version=1,rule=function(t) return t.product=='fixture' and t.version=='1' end,action=function(t) return {verdict='not_vulnerable',data=t.service} end}"},{"id":"b","source":"return {api_version=1,action=function() return {} end}"}]}`
	w := httptest.NewRecorder()
	runHandler().ServeHTTP(w, httptest.NewRequest("POST", "/run", strings.NewReader(body)))
	if w.Code != 200 || len(strings.Split(strings.TrimSpace(w.Body.String()), "\n")) != 4 || !strings.Contains(w.Body.String(), `"verdict":"not_vulnerable"`) || !strings.Contains(w.Body.String(), `"status":"skipped"`) {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestStreamingFactsAndHintRecords(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fixture.lua")
	facts := filepath.Join(dir, "facts.jsonl")
	if err := os.WriteFile(script, []byte("-- scribe: {\"services\":[\"ssh\"]}\nreturn {api_version=1,action=function() return {data='ok'} end}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(facts, []byte("{\"host\":\"one\",\"service\":\"http\"}\n{\"host\":\"two\",\"service\":\"ssh\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	code := run(context.Background(), []string{"--dialect", "sirius", "--script", script, "--facts-jsonl", facts, "--host-concurrency", "1", "--host-interval", "1ms", "--strategy", "host-spray"}, &out, &diagnostics)
	if code != 0 || strings.Count(out.String(), "\n") != 2 || !strings.Contains(out.String(), `"skip_reason"`) {
		t.Fatalf("code=%d out=%s errors=%s", code, &out, &diagnostics)
	}
	if err := os.WriteFile(facts, []byte("{invalid}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	diagnostics.Reset()
	if code := run(context.Background(), []string{"--dialect", "sirius", "--script", script, "--facts-jsonl", facts}, &out, &diagnostics); code == 0 {
		t.Fatal("invalid input succeeded")
	}
}

func TestPingppSelection(t *testing.T) {
	script := filepath.Join(t.TempDir(), "fixture.lua")
	if err := os.WriteFile(script, []byte("-- scribe: {\"services\":[\"ssh\"]}\nreturn {api_version=1,action=function() return {data='ok'} end}"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	args := []string{"--dialect", "sirius", "--script", script, "--pingpp-jsonl", "../../adapter/pingpp/testdata/scan.jsonl"}
	if code := run(context.Background(), args, &out, &diagnostics); code != 0 || strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), `"skip_reason"`) {
		t.Fatalf("%d %s %s", code, &out, &diagnostics)
	}
	args = append(args, "--facts-jsonl", "unused")
	if code := run(context.Background(), args, &out, &diagnostics); code == 0 {
		t.Fatal("mixed input accepted")
	}
}

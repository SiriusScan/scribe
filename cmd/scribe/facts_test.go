package main

import (
	"bytes"
	"context"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
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

func TestRealEmitterExecution(t *testing.T) {
	repo := os.Getenv("PINGPP_REPO")
	if repo == "" {
		repo = "/home/agi/Projects/sirius-workspace/minor-projects/ping++"
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cmd := exec.Command("go", "run", "./cmd/pingpp-scan", listener.Addr().String())
	cmd.Dir = repo
	wire, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	facts := filepath.Join(dir, "scan.jsonl")
	script := filepath.Join(dir, "check.lua")
	if err := os.WriteFile(facts, wire, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(script, []byte("return {api_version=1,action=function(t) return {verdict='vulnerable',data='emitter-executed'} end}"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	code := run(context.Background(), []string{"--dialect", "sirius", "--script", script, "--pingpp-jsonl", facts}, &out, &diagnostics)
	if code != 0 || strings.Count(out.String(), "\n") != 1 || !strings.Contains(out.String(), `"status":"completed"`) || !strings.Contains(out.String(), "emitter-executed") || !strings.Contains(out.String(), `"verdict":"vulnerable"`) {
		t.Fatalf("%d %s %s", code, &out, &diagnostics)
	}
}

func TestPingppStdin(t *testing.T) {
	script := filepath.Join(t.TempDir(), "check.lua")
	if err := os.WriteFile(script, []byte("return {api_version=1,action=function() return {data='pipe-executed'} end}"), 0600); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile("../../adapter/pingpp/testdata/scan.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	args := []string{"--dialect", "sirius", "--script", script, "--pingpp-jsonl", "-"}
	for _, broken := range []bool{false, true} {
		input := string(wire)
		if broken {
			input += "\ninvalid\n"
		}
		var out, diag bytes.Buffer
		code := runScriptsInput(context.Background(), args, nil, strings.NewReader(input), &out, &diag)
		if (code != 0) != broken {
			t.Fatalf("code=%d diagnostics=%s", code, &diag)
		}
		if !broken && (!strings.Contains(out.String(), "pipe-executed") || !strings.Contains(out.String(), `"verdict":"unknown"`)) {
			t.Fatal(out.String())
		}
	}
	var out, diag bytes.Buffer
	if runScripts(context.Background(), args, nil, &out, &diag) == 0 {
		t.Fatal("HTTP accepted process stdin")
	}
}

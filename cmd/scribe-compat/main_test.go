package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunRepositoryManifest(t *testing.T) {
	manifest := filepath.Join("..", "..", "compat", "manifest.json")
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"--manifest", manifest}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var report struct {
		Summary struct {
			Total       int `json:"total"`
			Fail        int `json:"fail"`
			Unsupported int `json:"unsupported"`
		} `json:"summary"`
		Results []struct {
			SHA256 string `json:"sha256"`
			Status string `json:"status"`
			Reason string `json:"reason"`
		} `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	if report.Summary.Fail != 0 || report.Summary.Unsupported != 2 || report.Summary.Total != len(report.Results) {
		t.Fatalf("summary: %+v", report.Summary)
	}
	for _, entry := range report.Results {
		if len(entry.SHA256) != 64 || entry.Status == "" || entry.Reason == "" {
			t.Errorf("incomplete entry: %+v", entry)
		}
	}
	var out bytes.Buffer
	if code := run(context.Background(), nil, &out, &stderr); code != 2 {
		t.Fatalf("missing manifest should exit 2, got %d", code)
	}
}

func TestRepositorySnapshotCurrentAndDeterministic(t *testing.T) {
	root := filepath.Join("..", "..", "compat")
	args := []string{"--manifest", filepath.Join(root, "manifest.json"), "--check", filepath.Join(root, "report.json")}
	var first, second, stderr bytes.Buffer
	for _, dst := range []*bytes.Buffer{&first, &second} {
		if code := run(context.Background(), args, dst, &stderr); code != 0 {
			t.Fatalf("exit %d: %s", code, &stderr)
		}
	}
	if !bytes.Equal(first.Bytes(), second.Bytes()) {
		t.Fatal("fixed manifest and build produced different report bytes")
	}
	stale := filepath.Join(t.TempDir(), "stale.json")
	if err := os.WriteFile(stale, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = stale
	if code := run(context.Background(), args, &second, &stderr); code != 1 ||
		!strings.Contains(stderr.String(), "is stale") {
		t.Fatalf("stale snapshot exit %d: %s", code, &stderr)
	}
}

func TestCancelledRunPublishesIncompleteEvidence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	manifest := filepath.Join("..", "..", "compat", "manifest.json")
	var stdout, stderr bytes.Buffer
	if code := run(ctx, []string{"--manifest", manifest}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d: %s", code, &stderr)
	}
	var report struct {
		Complete bool              `json:"complete"`
		Planned  int               `json:"planned"`
		Results  []json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || report.Complete ||
		report.Planned == 0 || report.Planned != len(report.Results) {
		t.Fatalf("interrupted report: %s, %v", &stdout, err)
	}
}

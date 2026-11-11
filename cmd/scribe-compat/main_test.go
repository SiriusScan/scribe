package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
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

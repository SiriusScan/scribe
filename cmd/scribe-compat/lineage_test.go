package main

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/SiriusScan/scribe/internal/compatlineage"
)

func TestLineageCommand(t *testing.T) {
	fixtures := filepath.Join("..", "..", "internal", "compatlineage", "testdata")
	args := []string{"lineage",
		"--scope", filepath.Join(fixtures, "scope.json"),
		"--candidate", filepath.Join(fixtures, "candidate.json"),
		"--reference", filepath.Join(fixtures, "reference.json"),
		"--review", filepath.Join(fixtures, "review.json"),
	}
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), args, &stdout, &stderr); code != 0 {
		t.Fatalf("lineage exit code = %d: %s", code, stderr.String())
	}
	var receipt compatlineage.Report
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.SchemaVersion != 1 || receipt.ReleaseQualified || len(receipt.Scopes) != 2 ||
		receipt.Scopes[0].Affirmative != 1 || receipt.Scopes[1].Negative != 1 {
		t.Fatalf("unexpected synthetic receipt: %s", stdout.String())
	}

	want := bytes.Clone(stdout.Bytes())
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), append(args, "--require-qualified"), &stdout, &stderr); code != 1 {
		t.Fatalf("qualification gate exit code = %d: %s", code, stderr.String())
	}
	if !bytes.Equal(stdout.Bytes(), want) || !bytes.Contains(stderr.Bytes(), []byte("release is unqualified")) {
		t.Fatalf("qualification gate changed the receipt or omitted the error: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(), args[:3], &stdout, &stderr); code != 0 {
		t.Fatalf("lineage with missing files exit code = %d: %s", code, stderr.String())
	}
	receipt = compatlineage.Report{}
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.ReleaseQualified || len(receipt.Scopes) != 2 || receipt.Scopes[0].Unknown != 1 ||
		receipt.Scopes[1].Unknown != 1 {
		t.Fatalf("unexpected receipt for missing evidence: %s", stdout.String())
	}
}

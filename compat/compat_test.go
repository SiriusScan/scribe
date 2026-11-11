package compat

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SiriusScan/scribe"
)

func TestRepositoryManifestMeasuresAsExpected(t *testing.T) {
	manifest, err := LoadManifest("manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	report, err := Run(context.Background(), manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !report.OK() {
		for _, entry := range report.Results {
			t.Errorf("%s: %s (%s)", entry.ID, entry.Status, entry.Reason)
		}
		t.Fatalf("summary: %+v", report.Summary)
	}
	if report.Summary.Total != len(manifest.Cases) || report.Summary.Unsupported != 2 {
		t.Fatalf("summary: %+v", report.Summary)
	}
	for _, entry := range report.Results {
		if entry.SHA256 == "" || entry.SHA256 != entry.ExpectedSHA256 {
			t.Errorf("%s: digest %q != pin %q", entry.ID, entry.SHA256, entry.ExpectedSHA256)
		}
		if entry.Reason == "" {
			t.Errorf("%s: empty reason", entry.ID)
		}
	}
}

const loadOnlyScript = `local stdnse = require "stdnse"
hostrule = function() return true end
action = function() return "loaded" end
`

func writeCase(t *testing.T, dir, name, source string) (script, digest string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return name, fmt.Sprintf("%x", sha256.Sum256([]byte(source)))
}

func syntheticManifest(dir string, cases ...Case) Manifest {
	return Manifest{
		SchemaVersion: 1,
		Corpus:        Corpus{Name: "synthetic-test"},
		Cases:         cases,
		BaseDir:       dir,
	}
}

func baseCase(id, script, digest, expectStatus string) Case {
	return Case{
		ID: id, Script: script, SHA256: digest,
		Target: scribe.Target{Host: "192.0.2.1"},
		Expect: Expect{Status: expectStatus},
	}
}

func TestCompletedWithoutAssertionCannotPass(t *testing.T) {
	dir := t.TempDir()
	script, digest := writeCase(t, dir, "load.nse", loadOnlyScript)
	// A completed expectation with no exact output assertion is rejected
	// at validation time: loading a module is not a pass.
	manifest := syntheticManifest(dir, baseCase("load-only", script, digest, "completed"))
	if _, err := Run(context.Background(), manifest); err == nil || !strings.Contains(err.Error(), "not a pass") {
		t.Fatalf("expected validation rejection, got %v", err)
	}
	// With an assertion for different output, the same script fails.
	c := baseCase("load-only", script, digest, "completed")
	c.Expect.Data = []byte(`"something else"`)
	report, err := Run(context.Background(), syntheticManifest(dir, c))
	if err != nil {
		t.Fatal(err)
	}
	if report.Results[0].Status != Fail || !strings.Contains(report.Results[0].Reason, "output mismatch") {
		t.Fatalf("mismatched output: %+v", report.Results[0])
	}
	// Only the exact asserted output passes.
	c.Expect.Data = []byte(`"loaded"`)
	report, err = Run(context.Background(), syntheticManifest(dir, c))
	if err != nil || report.Results[0].Status != Pass {
		t.Fatalf("asserted output: %+v %v", report.Results[0], err)
	}
}

func TestDigestMismatchFailsWithoutExecution(t *testing.T) {
	dir := t.TempDir()
	script, _ := writeCase(t, dir, "boom.nse", `error("must never run")`)
	c := baseCase("wrong-pin", script, strings.Repeat("0", 64), "error")
	c.Expect.ErrorContains = "must never run"
	report, err := Run(context.Background(), syntheticManifest(dir, c))
	if err != nil {
		t.Fatal(err)
	}
	entry := report.Results[0]
	if entry.Status != Fail || !strings.Contains(entry.Reason, "digest") || entry.ExecutionStatus != "" {
		t.Fatalf("digest mismatch: %+v", entry)
	}
}

func TestUnexpectedUnsupportedFailsTheRun(t *testing.T) {
	dir := t.TempDir()
	script, digest := writeCase(t, dir, "net.nse", `local nmap = require "nmap"
hostrule = function() return true end
action = function() return "x" end
`)
	c := baseCase("surprise", script, digest, "completed")
	c.Expect.Data = []byte(`"x"`)
	report, err := Run(context.Background(), syntheticManifest(dir, c))
	if err != nil {
		t.Fatal(err)
	}
	entry := report.Results[0]
	if entry.Status != Unsupported || !entry.Unexpected || report.OK() {
		t.Fatalf("unexpected unsupported: %+v ok=%v", entry, report.OK())
	}
	// The same outcome, predicted by the manifest, is a measured gap and
	// does not fail the run.
	c.Expect = Expect{Status: "unsupported", ErrorContains: "unsupported Lua module"}
	report, err = Run(context.Background(), syntheticManifest(dir, c))
	if err != nil || !report.OK() || report.Results[0].Status != Unsupported {
		t.Fatalf("expected unsupported: %+v %v", report.Results[0], err)
	}
}

func TestManifestValidation(t *testing.T) {
	dir := t.TempDir()
	script, digest := writeCase(t, dir, "ok.nse", loadOnlyScript)
	good := baseCase("a", script, digest, "skipped")
	for name, manifest := range map[string]Manifest{
		"duplicate ids":    syntheticManifest(dir, good, good),
		"escaping script":  syntheticManifest(dir, func() Case { c := good; c.Script = "../outside.nse"; return c }()),
		"absolute script":  syntheticManifest(dir, func() Case { c := good; c.Script = "/etc/passwd"; return c }()),
		"missing pin":      syntheticManifest(dir, func() Case { c := good; c.SHA256 = ""; return c }()),
		"unknown expect":   syntheticManifest(dir, func() Case { c := good; c.Expect.Status = "green"; return c }()),
		"unsupported bare": syntheticManifest(dir, func() Case { c := good; c.Expect.Status = "unsupported"; return c }()),
	} {
		if err := manifest.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

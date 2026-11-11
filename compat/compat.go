// Package compat measures the experimental NSE profile against a pinned
// fixture manifest and emits a machine-readable report.
//
// A case passes only when its script digest matches the manifest pin and
// the observed execution matches the manifest expectation, including an
// exact output assertion for completed scripts. A script that merely
// loads, or completes with unasserted output, is a failure, never a pass.
// Scripts that hit an explicitly unsupported API are reported as
// unsupported, separately from passes and failures.
package compat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

// Status is the measured compatibility outcome for one case.
type Status string

const (
	// Pass indicates a pinned fixture matched its expected output.
	Pass Status = "pass"
	// Fail indicates fixture validation or execution failed.
	Fail Status = "fail"
	// Unsupported indicates execution encountered an unsupported API.
	Unsupported Status = "unsupported"
)

// Corpus identifies the script collection a manifest pins. The reference
// Nmap fields record the differential oracle once selected; until the
// Phase 1 pin decision is made they stay empty and PinStatus says so.
type Corpus struct {
	Name                    string `json:"name"`
	Revision                string `json:"revision,omitempty"`
	ReferenceNmapVersion    string `json:"reference_nmap_version,omitempty"`
	ReferenceNmapRevision   string `json:"reference_nmap_revision,omitempty"`
	ReferenceCorpusRevision string `json:"reference_corpus_revision,omitempty"`
	PinStatus               string `json:"pin_status,omitempty"`
}

// Expect is one case's asserted outcome. Status is the expected scribe
// execution status ("completed", "skipped", "error") or "unsupported" for
// a script expected to hit an explicitly unsupported API. Data is the
// exact expected action output as JSON and is required for "completed".
type Expect struct {
	Status        string          `json:"status"`
	Data          json.RawMessage `json:"data,omitempty"`
	ErrorContains string          `json:"error_contains,omitempty"`
}

// Case is one pinned script invocation against supplied target facts.
type Case struct {
	ID     string         `json:"id"`
	Script string         `json:"script"`
	SHA256 string         `json:"sha256"`
	Target scribe.Target  `json:"target"`
	Args   map[string]any `json:"args,omitempty"`
	Expect Expect         `json:"expect"`
}

// Manifest is the pinned input to a compatibility run.
type Manifest struct {
	SchemaVersion int    `json:"schema_version"`
	Corpus        Corpus `json:"corpus"`
	Cases         []Case `json:"cases"`
	BaseDir       string `json:"-"`
}

// Entry is one case's measured outcome. Unexpected marks an unsupported
// outcome the manifest did not predict (or predicted with a different
// reason); it fails the run even though the status stays "unsupported".
type Entry struct {
	ID              string `json:"id"`
	Script          string `json:"script"`
	SHA256          string `json:"sha256,omitempty"`
	ExpectedSHA256  string `json:"expected_sha256,omitempty"`
	Status          Status `json:"status"`
	Reason          string `json:"reason"`
	ExecutionStatus string `json:"execution_status,omitempty"`
	Error           string `json:"error,omitempty"`
	Unexpected      bool   `json:"unexpected,omitempty"`
}

// Summary counts outcomes. It conveys no compatibility percentage claim
// beyond the manifest's own selected cases.
type Summary struct {
	Total       int `json:"total"`
	Pass        int `json:"pass"`
	Fail        int `json:"fail"`
	Unsupported int `json:"unsupported"`
	Unexpected  int `json:"unexpected"`
}

// Report is the deterministic machine-readable result of a run. It holds
// no timestamps or durations so identical inputs produce identical bytes.
type Report struct {
	SchemaVersion int     `json:"schema_version"`
	Corpus        Corpus  `json:"corpus"`
	Summary       Summary `json:"summary"`
	Results       []Entry `json:"results"`
}

// OK reports whether the run matched every manifest expectation: no
// failures and no unexpected unsupported outcomes. Expected unsupported
// cases are measured gaps, not run failures.
func (r Report) OK() bool { return r.Summary.Fail == 0 && r.Summary.Unexpected == 0 }

const maxManifestBytes = 8 << 20

// LoadManifest reads and validates a manifest file. Case script paths are
// resolved relative to the manifest's directory.
func LoadManifest(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest: %w", err)
	}
	if len(data) > maxManifestBytes {
		return Manifest{}, errors.New("manifest exceeds 8 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("manifest must contain exactly one JSON object")
	}
	manifest.BaseDir = filepath.Dir(path)
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Validate rejects manifests whose expectations could pass vacuously or
// whose script paths escape the manifest directory.
func (m Manifest) Validate() error {
	if m.SchemaVersion != 1 {
		return fmt.Errorf("manifest schema_version must be 1, got %d", m.SchemaVersion)
	}
	if m.Corpus.Name == "" {
		return errors.New("manifest corpus.name is required")
	}
	if len(m.Cases) == 0 || len(m.Cases) > 4096 {
		return errors.New("manifest must contain 1 to 4096 cases")
	}
	seen := make(map[string]bool, len(m.Cases))
	for i, c := range m.Cases {
		if c.ID == "" {
			return fmt.Errorf("case %d: id is required", i)
		}
		if seen[c.ID] {
			return fmt.Errorf("case %d: duplicate id %q", i, c.ID)
		}
		seen[c.ID] = true
		if c.Script == "" || filepath.IsAbs(c.Script) || filepath.Clean(c.Script) != c.Script ||
			c.Script == ".." || strings.HasPrefix(c.Script, ".."+string(filepath.Separator)) {
			return fmt.Errorf("case %q: script must be a clean relative path inside the manifest directory", c.ID)
		}
		if len(c.SHA256) != 64 {
			return fmt.Errorf("case %q: sha256 pin is required (64 hex digits)", c.ID)
		}
		if _, err := hex.DecodeString(c.SHA256); err != nil || strings.ToLower(c.SHA256) != c.SHA256 {
			return fmt.Errorf("case %q: sha256 must be lowercase hex", c.ID)
		}
		switch c.Expect.Status {
		case "completed":
			if len(c.Expect.Data) == 0 {
				return fmt.Errorf("case %q: completed expectation requires an exact data assertion; loading or completing alone is not a pass", c.ID)
			}
			if !json.Valid(c.Expect.Data) {
				return fmt.Errorf("case %q: expect.data is not valid JSON", c.ID)
			}
		case "skipped":
		case "error", "unsupported":
			if c.Expect.ErrorContains == "" {
				return fmt.Errorf("case %q: %s expectation requires error_contains", c.ID, c.Expect.Status)
			}
		default:
			return fmt.Errorf("case %q: expect.status must be completed, skipped, error, or unsupported", c.ID)
		}
		if err := c.Target.Validate(); err != nil {
			return fmt.Errorf("case %q: %w", c.ID, err)
		}
	}
	return nil
}

// Run executes every manifest case once, in manifest order, through the
// experimental NSE profile and classifies the outcomes.
func Run(ctx context.Context, manifest Manifest) (Report, error) {
	if err := manifest.Validate(); err != nil {
		return Report{}, err
	}
	runtime, err := lua54.NewNSE(lua54.Options{})
	if err != nil {
		return Report{}, err
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 1}, runtime)
	if err != nil {
		return Report{}, err
	}
	report := Report{SchemaVersion: 1, Corpus: manifest.Corpus}
	for _, c := range manifest.Cases {
		entry := runCase(ctx, engine, manifest.BaseDir, c)
		report.Results = append(report.Results, entry)
		report.Summary.Total++
		switch entry.Status {
		case Pass:
			report.Summary.Pass++
		case Fail:
			report.Summary.Fail++
		case Unsupported:
			report.Summary.Unsupported++
		}
		if entry.Unexpected {
			report.Summary.Unexpected++
		}
	}
	return report, ctx.Err()
}

func runCase(ctx context.Context, engine *scribe.Engine, baseDir string, c Case) Entry {
	entry := Entry{ID: c.ID, Script: c.Script, ExpectedSHA256: c.SHA256}
	path := filepath.Join(baseDir, c.Script)
	file, err := os.Open(path)
	if err != nil {
		entry.Status, entry.Reason = Fail, fmt.Sprintf("read script: %v", err)
		return entry
	}
	source, err := io.ReadAll(io.LimitReader(file, scribe.MaxSourceBytes+1))
	file.Close()
	if err != nil {
		entry.Status, entry.Reason = Fail, fmt.Sprintf("read script: %v", err)
		return entry
	}
	if len(source) == 0 || len(source) > scribe.MaxSourceBytes {
		entry.Status, entry.Reason = Fail, fmt.Sprintf("script must contain 1-%d bytes", scribe.MaxSourceBytes)
		return entry
	}
	entry.SHA256 = fmt.Sprintf("%x", sha256.Sum256(source))
	if entry.SHA256 != c.SHA256 {
		entry.Status = Fail
		entry.Reason = "script digest does not match the manifest pin; not executed"
		return entry
	}
	var result *scribe.Result
	task := scribe.Task{
		Script: scribe.Script{ID: filepath.Base(c.Script), Dialect: scribe.NSE, Source: source, Args: c.Args},
		Target: c.Target,
	}
	runErr := engine.Run(ctx, []scribe.Task{task}, func(r scribe.Result) error {
		got := r
		result = &got
		return nil
	})
	if result == nil {
		entry.Status, entry.Reason = Fail, fmt.Sprintf("execution produced no result: %v", runErr)
		return entry
	}
	entry.ExecutionStatus = string(result.Status)
	entry.Error = result.Error
	classify(&entry, c, *result)
	return entry
}

func classify(entry *Entry, c Case, result scribe.Result) {
	if result.Status == scribe.Failed {
		if isUnsupported(result.Error) {
			entry.Status = Unsupported
			entry.Reason = "explicitly unsupported: " + result.Error
			if c.Expect.Status != "unsupported" {
				entry.Unexpected = true
				entry.Reason = "unexpected unsupported outcome (manifest expected " + c.Expect.Status + "): " + result.Error
			} else if !strings.Contains(result.Error, c.Expect.ErrorContains) {
				entry.Unexpected = true
				entry.Reason = fmt.Sprintf("unsupported for an unexpected reason (manifest expected error containing %q): %s", c.Expect.ErrorContains, result.Error)
			}
			return
		}
		if c.Expect.Status == "error" && strings.Contains(result.Error, c.Expect.ErrorContains) {
			entry.Status, entry.Reason = Pass, "failed as expected: "+result.Error
			return
		}
		entry.Status, entry.Reason = Fail, "execution failed: "+result.Error
		return
	}
	if string(result.Status) != c.Expect.Status {
		entry.Status = Fail
		entry.Reason = fmt.Sprintf("execution status %q does not match expected %q", result.Status, c.Expect.Status)
		return
	}
	if result.Status == scribe.Skipped {
		entry.Status, entry.Reason = Pass, "rule did not match the supplied facts, as expected"
		return
	}
	// Completed: require the exact output assertion (Validate enforces its
	// presence, so completion without asserted output can never pass).
	actual, err := canonicalJSON(result.Output.Data)
	if err != nil {
		entry.Status, entry.Reason = Fail, "encode actual output: "+err.Error()
		return
	}
	var expected any
	decoder := json.NewDecoder(bytes.NewReader(c.Expect.Data))
	decoder.UseNumber()
	if err := decoder.Decode(&expected); err != nil {
		entry.Status, entry.Reason = Fail, "decode expected output: "+err.Error()
		return
	}
	want, err := canonicalJSON(expected)
	if err != nil {
		entry.Status, entry.Reason = Fail, "encode expected output: "+err.Error()
		return
	}
	if !bytes.Equal(actual, want) {
		entry.Status = Fail
		entry.Reason = fmt.Sprintf("output mismatch: got %s, want %s", actual, want)
		return
	}
	entry.Status, entry.Reason = Pass, "completed with the asserted output"
}

// isUnsupported recognizes Scribe's explicit unsupported-surface errors.
// Any other execution error is a failure, never silently reclassified.
func isUnsupported(message string) bool {
	return strings.Contains(strings.ToLower(message), "unsupported")
}

func canonicalJSON(value any) ([]byte, error) {
	if value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(value)
}

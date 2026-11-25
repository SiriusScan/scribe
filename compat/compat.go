// Package compat measures the experimental NSE profile against a pinned
// offline fixture manifest and emits a versioned evidence report.
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
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/internal/execdiag"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

var caseIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// Corpus identifies the script collection a manifest pins. The reference
// Nmap fields record the differential oracle once selected; until the
// Phase 1 pin decision is made they stay empty and PinStatus says so.
type Corpus struct {
	// Name names the pinned collection; empty supplies no corpus identity.
	Name string `json:"name"`
	// Revision identifies the collection revision; empty means unpinned.
	Revision string `json:"revision,omitempty"`
	// ReferenceNmapVersion records oracle version text; empty means no oracle selected.
	ReferenceNmapVersion string `json:"reference_nmap_version,omitempty"`
	// ReferenceNmapRevision records oracle source revision; empty means unavailable.
	ReferenceNmapRevision string `json:"reference_nmap_revision,omitempty"`
	// ReferenceCorpusRevision records upstream corpus revision; empty means unavailable.
	ReferenceCorpusRevision string `json:"reference_corpus_revision,omitempty"`
	// PinStatus describes pin selection; empty supplies no pin status.
	PinStatus string `json:"pin_status,omitempty"`
}

// Expect is one case's asserted outcome. Status is the expected scribe
// execution status ("completed", "skipped", "error") or "unsupported" for
// a script expected to hit an explicitly unsupported API. Data is the
// exact expected action output as JSON and is required for "completed".
type Expect struct {
	// Status is required expected execution status or unsupported; empty is invalid.
	Status string `json:"status"`
	// Data is exact expected JSON output, required for completed; nil supplies no assertion.
	Data json.RawMessage `json:"data,omitempty"`
	// ErrorContains optionally asserts an exact diagnostic substring.
	ErrorContains string `json:"error_contains,omitempty"`
	// Code asserts the bounded runtime reason. Required for v2 skips and failures.
	Code string `json:"code,omitempty"`
	// Phase asserts the runtime boundary. Required for v2 skips and failures.
	Phase string `json:"phase,omitempty"`
	// Text, when set, asserts the exact separate NSE textual return.
	Text *string `json:"text,omitempty"`
	// Verdict, when set, asserts the independent modeled assessment.
	Verdict scribe.Verdict `json:"verdict,omitempty"`
}

// Case is one pinned script invocation against supplied target facts.
type Case struct {
	// ID is required case identity; empty is invalid.
	ID string `json:"id"`
	// Script is a source path relative to BaseDir; empty is invalid.
	Script string `json:"script"`
	// SHA256 is the required hexadecimal source digest; empty is invalid.
	SHA256 string `json:"sha256"`
	// Target supplies endpoint facts; zero fails execution validation.
	Target scribe.Target `json:"target"`
	// Args supplies script arguments; nil supplies none.
	Args map[string]any `json:"args,omitempty"`
	// Expect contains required outcome assertions; zero is invalid.
	Expect Expect `json:"expect"`
}

// Manifest is the pinned input to a compatibility run.
type Manifest struct {
	// SchemaVersion accepts 1 for legacy fixtures or 2 for strict evidence.
	SchemaVersion int `json:"schema_version"`
	// Corpus describes the selected corpus; zero establishes no upstream compatibility.
	Corpus Corpus `json:"corpus"`
	// Cases contains measured cases; empty is rejected by validation.
	Cases []Case `json:"cases"`
	// BaseDir resolves script paths; empty uses the current directory for relative paths.
	BaseDir string `json:"-"`
}

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
	if m.SchemaVersion != 1 && m.SchemaVersion != 2 {
		return fmt.Errorf("manifest schema_version must be 1 or 2, got %d", m.SchemaVersion)
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
		if m.SchemaVersion == 2 && !caseIDPattern.MatchString(c.ID) {
			return fmt.Errorf("case %q: id must use lowercase ASCII letters, digits, dots, dashes or underscores", c.ID)
		}
		if seen[c.ID] {
			return fmt.Errorf("case %d: duplicate id %q", i, c.ID)
		}
		seen[c.ID] = true
		if c.Script == "" || filepath.IsAbs(c.Script) || path.IsAbs(c.Script) || path.Clean(c.Script) != c.Script ||
			strings.ContainsAny(c.Script, `\:`) || c.Script == ".." || strings.HasPrefix(c.Script, "../") {
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
			if m.SchemaVersion == 1 && c.Expect.ErrorContains == "" {
				return fmt.Errorf("case %q: %s expectation requires error_contains", c.ID, c.Expect.Status)
			}
		default:
			return fmt.Errorf("case %q: expect.status must be completed, skipped, error, or unsupported", c.ID)
		}
		if m.SchemaVersion == 2 && c.Expect.Status != "completed" && (c.Expect.Code == "" || c.Expect.Phase == "") {
			return fmt.Errorf("case %q: %s expectation requires code and phase", c.ID, c.Expect.Status)
		}
		switch c.Expect.Verdict {
		case "", scribe.Unknown, scribe.Vulnerable, scribe.NotVulnerable:
		default:
			return fmt.Errorf("case %q: invalid expect.verdict %q", c.ID, c.Expect.Verdict)
		}
		if err := c.Target.Validate(); err != nil {
			return fmt.Errorf("case %q: %w", c.ID, err)
		}
	}
	return nil
}

// Run measures the pinned cases using the offline NSE profile.
func Run(ctx context.Context, manifest Manifest) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("context is required")
	}
	if err := manifest.Validate(); err != nil {
		return Report{}, err
	}
	inputDigest, err := digestJSON(manifest)
	if err != nil {
		return Report{}, fmt.Errorf("digest manifest: %w", err)
	}
	inputDigests := make([]string, len(manifest.Cases))
	for i, c := range manifest.Cases {
		inputDigests[i], err = digestJSON(c)
		if err != nil {
			return Report{}, fmt.Errorf("case %q: digest input: %w", c.ID, err)
		}
	}

	vm, err := lua54.NewNSE(lua54.Options{})
	if err != nil {
		return Report{}, err
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 1}, vm)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		SchemaVersion: EvidenceSchemaVersion, Corpus: manifest.Corpus, Source: buildSource(),
		ManifestSHA256: inputDigest, Complete: true, Planned: len(manifest.Cases),
		Results: make([]Entry, 0, len(manifest.Cases)),
	}
	for i, c := range manifest.Cases {
		entry := Entry{
			ID: c.ID, Script: c.Script, ExpectedSHA256: c.SHA256, InputSHA256: inputDigests[i], Expected: c.Expect,
		}
		if err := ctx.Err(); err != nil {
			markUnmeasured(&entry, interruptDisposition(err), "case was not started: "+err.Error())
		} else {
			runCase(ctx, engine, manifest.BaseDir, c, &entry)
		}
		report.add(entry)
	}
	if err := ctx.Err(); err != nil {
		report.Complete = false
		return report, err
	}
	return report, nil
}

func runCase(ctx context.Context, engine *scribe.Engine, baseDir string, c Case, entry *Entry) {
	file, err := os.Open(filepath.Join(baseDir, filepath.FromSlash(c.Script)))
	if err != nil {
		markUnmeasured(entry, Unmeasured, fmt.Sprintf("read script: %v", err))
		return
	}
	defer file.Close()
	source, err := io.ReadAll(io.LimitReader(file, scribe.MaxSourceBytes+1))
	if err != nil {
		markUnmeasured(entry, Unmeasured, fmt.Sprintf("read script: %v", err))
		return
	}
	if len(source) == 0 || len(source) > scribe.MaxSourceBytes {
		markUnmeasured(entry, Unmeasured, fmt.Sprintf("script must contain 1-%d bytes", scribe.MaxSourceBytes))
		return
	}
	entry.SHA256 = fmt.Sprintf("%x", sha256.Sum256(source))
	if entry.SHA256 != c.SHA256 {
		markUnmeasured(entry, Unmeasured, "script digest does not match the manifest pin")
		return
	}

	var result *scribe.Result
	var observation execdiag.Observation
	ctx = execdiag.WithRecorder(ctx, func(o execdiag.Observation) { observation = o })
	task := scribe.Task{
		Script: scribe.Script{ID: path.Base(c.Script), Dialect: scribe.NSE, Source: source, Args: c.Args},
		Target: c.Target,
	}
	runErr := engine.Run(ctx, []scribe.Task{task}, func(r scribe.Result) error {
		got := r
		result = &got
		return nil
	})
	if result == nil {
		markUnmeasured(entry, interruptDisposition(runErr), fmt.Sprintf("execution produced no result: %v", runErr))
		return
	}
	entry.ExecutionStatus = string(result.Status)
	entry.Error = result.Error
	entry.Code = observation.Code
	entry.Phase = observation.Phase
	entry.SkipReason = result.Output.SkipReason
	entry.Verdict = result.Verdict
	entry.Text = observation.Text
	switch result.Status {
	case scribe.Completed:
		entry.Disposition = Completion
		entry.Data, err = json.Marshal(result.Output.Data)
		if err != nil {
			markUnmeasured(entry, Unmeasured, "encode actual output: "+err.Error())
			return
		}
	case scribe.Skipped:
		entry.Disposition = RuleIneligible
		if entry.Code == execdiag.MissingTargetPort {
			entry.Disposition = MissingFacts
		}
	case scribe.Cancelled:
		markUnmeasured(entry, Cancellation, result.Error)
		return
	case scribe.Failed:
		switch entry.Code {
		case execdiag.TimedOut:
			markUnmeasured(entry, Timeout, result.Error)
			return
		case execdiag.UnsupportedAPI, execdiag.UnsupportedModule, execdiag.UnsupportedPhase, execdiag.UnsupportedDep:
			entry.Disposition = KnownUnsupported
		default:
			entry.Disposition = Rejection
		}
	default:
		markUnmeasured(entry, Unmeasured, "execution returned an unknown status")
		return
	}

	entry.Eligible = entry.Disposition == Completion ||
		(entry.Disposition != RuleIneligible && entry.Disposition != MissingFacts &&
			(entry.Phase == execdiag.Action || entry.Phase == execdiag.Output))
	classify(entry)
}

func interruptDisposition(err error) Disposition {
	switch {
	case errors.Is(err, context.Canceled):
		return Cancellation
	case errors.Is(err, context.DeadlineExceeded):
		return Timeout
	default:
		return Unmeasured
	}
}

package compat

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/internal/execdiag"
)

// EvidenceSchemaVersion is the generated report format. Reports from schema 1
// still decode, and OK retains its original fixture regression meaning.
const EvidenceSchemaVersion = 2

// Status summarizes regression and measured coverage for a row.
type Status string

const (
	Pass            Status = "pass"
	Fail            Status = "fail"
	Unsupported     Status = "unsupported"
	ExpectedOutcome Status = "expected_outcome"
)

// Disposition records the observed outcome independently of fixture matching.
type Disposition string

const (
	Completion       Disposition = "completed"
	Rejection        Disposition = "explicit_rejection"
	RuleIneligible   Disposition = "rule_ineligible"
	MissingFacts     Disposition = "missing_required_fact"
	KnownUnsupported Disposition = "unsupported"
	Timeout          Disposition = "timeout"
	Cancellation     Disposition = "cancelled"
	Unmeasured       Disposition = "unmeasured"
)

// FixtureResult records whether the observed result matched its expectation.
type FixtureResult string

const (
	FixtureMatch      FixtureResult = "match"
	FixtureMismatch   FixtureResult = "mismatch"
	FixtureUnmeasured FixtureResult = "unmeasured"
)

// Entry holds a planned fixture's expectation and the exact observed evidence.
type Entry struct {
	ID              string          `json:"id"`
	Script          string          `json:"script"`
	SHA256          string          `json:"sha256,omitempty"`
	ExpectedSHA256  string          `json:"expected_sha256"`
	InputSHA256     string          `json:"input_sha256"`
	Expected        Expect          `json:"expected"`
	Status          Status          `json:"status"`
	FixtureResult   FixtureResult   `json:"fixture_result"`
	Disposition     Disposition     `json:"disposition"`
	Eligible        bool            `json:"eligible"`
	Reason          string          `json:"reason"`
	ExecutionStatus string          `json:"execution_status,omitempty"`
	Code            string          `json:"code,omitempty"`
	Phase           string          `json:"phase,omitempty"`
	Data            json.RawMessage `json:"data,omitempty"`
	Text            *string         `json:"text,omitempty"`
	Verdict         scribe.Verdict  `json:"verdict,omitempty"`
	SkipReason      string          `json:"skip_reason,omitempty"`
	Error           string          `json:"error,omitempty"`
	Unexpected      bool            `json:"unexpected,omitempty"`
}

// Summary counts planned rows, matched expectations, eligible action phases,
// completed rows with nonempty data (Measured), and matching ones (Pass).
type Summary struct {
	Total       int `json:"total"`
	Pass        int `json:"pass"`
	Fail        int `json:"fail"`
	Unsupported int `json:"unsupported"`
	Unexpected  int `json:"unexpected"`
	Matched     int `json:"matched"`
	Eligible    int `json:"eligible"`
	Measured    int `json:"measured"`
}

// Source identifies the Scribe build that produced a report. Commit and version
// can be absent in an embedded or unpackaged build.
type Source struct {
	Module   string `json:"module"`
	Version  string `json:"version,omitempty"`
	Commit   string `json:"commit,omitempty"`
	Modified bool   `json:"modified"`
	Go       string `json:"go"`
	GOOS     string `json:"goos"`
	GOARCH   string `json:"goarch"`
}

func buildSource() *Source {
	v := scribe.Version()
	return &Source{
		Module: v.Module, Version: v.Version, Commit: v.Commit, Modified: v.Modified,
		Go: runtime.Version(), GOOS: runtime.GOOS, GOARCH: runtime.GOARCH,
	}
}

// Report contains the deterministic result of one measured fixture run.
type Report struct {
	SchemaVersion  int     `json:"schema_version"`
	Corpus         Corpus  `json:"corpus"`
	Source         *Source `json:"source,omitempty"`
	ManifestSHA256 string  `json:"manifest_sha256"`
	Complete       bool    `json:"complete"`
	Planned        int     `json:"planned"`
	Summary        Summary `json:"summary"`
	Results        []Entry `json:"results"`
}

// OK reports whether the fixture expectations matched. As in schema 1, the
// zero report and runs with only expected gaps may satisfy this legacy API.
func (r Report) OK() bool { return r.Summary.Fail == 0 && r.Summary.Unexpected == 0 }

// CoveredCases returns positive offline evidence for matching completed rows
// only after checking complete results against the supplied strict manifest.
func (r Report) CoveredCases(manifest Manifest) []string {
	if r.SchemaVersion != EvidenceSchemaVersion || !r.Complete || manifest.SchemaVersion != 2 ||
		manifest.Validate() != nil || r.Planned != len(manifest.Cases) || r.Planned != len(r.Results) {
		return nil
	}
	digest, err := digestJSON(manifest)
	if err != nil || digest != r.ManifestSHA256 {
		return nil
	}
	var covered []string
	for i, c := range manifest.Cases {
		e := r.Results[i]
		digest, err := digestJSON(c)
		if err != nil || e.InputSHA256 != digest || e.ID != c.ID || e.Script != c.Script ||
			e.ExpectedSHA256 != c.SHA256 || e.SHA256 != c.SHA256 || e.FixtureResult != FixtureMatch {
			return nil
		}
		e.Expected = c.Expect
		if assertionError(e) != "" {
			return nil
		}
		if e.Disposition == Completion && e.ExecutionStatus == string(scribe.Completed) &&
			e.Eligible && e.Phase == execdiag.Action && e.Status == Pass && e.hasData() {
			covered = append(covered, e.ID)
		}
	}
	return covered
}

func digestJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

func (r *Report) add(e Entry) {
	r.Results = append(r.Results, e)
	r.Summary.Total++
	if e.Eligible {
		r.Summary.Eligible++
	}
	if e.Disposition == Completion && e.hasData() {
		r.Summary.Measured++
	}
	if e.FixtureResult == FixtureMatch {
		r.Summary.Matched++
	}
	switch e.Status {
	case Pass:
		r.Summary.Pass++
	case Fail:
		r.Summary.Fail++
	case Unsupported:
		r.Summary.Unsupported++
	}
	if e.Unexpected {
		r.Summary.Unexpected++
	}
	if e.FixtureResult == FixtureUnmeasured {
		r.Complete = false
	}
}

func markUnmeasured(e *Entry, disposition Disposition, reason string) {
	e.Status, e.FixtureResult, e.Disposition, e.Reason = Fail, FixtureUnmeasured, disposition, reason
	if e.Code == "" {
		switch disposition {
		case Cancellation:
			e.Code = execdiag.Cancelled
		case Timeout:
			e.Code = execdiag.TimedOut
		default:
			e.Code = "no_observation"
		}
	}
}

func classify(e *Entry) {
	if message := assertionError(*e); message != "" {
		e.Status, e.FixtureResult, e.Reason = Fail, FixtureMismatch, message
		if e.Disposition == KnownUnsupported {
			e.Status, e.Unexpected = Unsupported, true
		}
		return
	}
	e.FixtureResult = FixtureMatch
	switch {
	case e.Disposition == KnownUnsupported:
		e.Status, e.Reason = Unsupported, "encountered the asserted unsupported surface"
	case e.Disposition == Completion && e.hasData():
		e.Status, e.Reason = Pass, "completed with the asserted output"
	case e.Disposition == Completion:
		e.Status, e.Reason = ExpectedOutcome, "completed with the asserted empty output"
	case e.Disposition == Rejection:
		e.Status, e.Reason = ExpectedOutcome, "rejected as expected"
	default:
		e.Status, e.Reason = ExpectedOutcome, "skipped as expected"
	}
}

func assertionError(e Entry) string {
	actualStatus := e.ExecutionStatus
	if e.Disposition == KnownUnsupported {
		actualStatus = string(Unsupported)
	}
	want := e.Expected
	if actualStatus != want.Status {
		return fmt.Sprintf("execution status %q does not match expected %q", actualStatus, want.Status)
	}
	if want.Code != "" && e.Code != want.Code {
		return fmt.Sprintf("reason code %q does not match expected %q", e.Code, want.Code)
	}
	if want.Phase != "" && e.Phase != want.Phase {
		return fmt.Sprintf("phase %q does not match expected %q", e.Phase, want.Phase)
	}
	if want.ErrorContains != "" && !strings.Contains(e.Error, want.ErrorContains) {
		return fmt.Sprintf("diagnostic does not contain %q", want.ErrorContains)
	}
	if want.Verdict != "" && e.Verdict != want.Verdict {
		return fmt.Sprintf("verdict %q does not match expected %q", e.Verdict, want.Verdict)
	}
	if want.Text != nil && (e.Text == nil || *e.Text != *want.Text) {
		return fmt.Sprintf("text does not match expected %q", *want.Text)
	}
	if len(want.Data) != 0 {
		actual, err := canonicalJSON(e.Data)
		if err != nil {
			return "encode actual output: " + err.Error()
		}
		expected, err := canonicalJSON(want.Data)
		if err != nil {
			return "encode expected output: " + err.Error()
		}
		if !bytes.Equal(actual, expected) {
			return fmt.Sprintf("output mismatch: got %s, want %s", actual, expected)
		}
	}
	return ""
}

func (e Entry) hasData() bool {
	data := bytes.TrimSpace(e.Data)
	return len(data) != 0 && string(data) != "null" && string(data) != `""`
}

func canonicalJSON(data json.RawMessage) ([]byte, error) {
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

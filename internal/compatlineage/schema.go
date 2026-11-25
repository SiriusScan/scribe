// Package compatlineage verifies supplied compatibility evidence without executing it.
package compatlineage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"unicode/utf8"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/compat"
)

const (
	SchemaVersion = 1
	Policy        = "scribe-json-v1"
	maxInputBytes = 8 << 20
)

type Producer struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

type Release struct {
	ScribeVersion         string   `json:"scribe_version"`
	ScribeCommit          string   `json:"scribe_commit"`
	ScribeProducer        Producer `json:"scribe_producer"`
	ReferenceVersion      string   `json:"reference_version"`
	ReferenceRevision     string   `json:"reference_revision"`
	ReferenceProducer     Producer `json:"reference_producer"`
	SiriusCommit          string   `json:"sirius_commit"`
	ScannerCommit         string   `json:"scanner_commit"`
	CatalogRevision       string   `json:"catalog_revision"`
	CatalogSHA256         string   `json:"catalog_sha256"`
	FixtureManifestSHA256 string   `json:"fixture_manifest_sha256"`
}

func (r Release) complete() bool {
	return r.ScribeVersion != "" && validHex(r.ScribeCommit, 40) && r.ScribeProducer.valid() &&
		r.ReferenceVersion != "" && validHex(r.ReferenceRevision, 40) && r.ReferenceProducer.valid() &&
		validHex(r.SiriusCommit, 40) && validHex(r.ScannerCommit, 40) &&
		validHex(r.CatalogRevision, 40) && validHex(r.CatalogSHA256, 64) &&
		validHex(r.FixtureManifestSHA256, 64)
}

type Key struct {
	Workflow string `json:"workflow"`
	CaseID   string `json:"case_id"`
}

type Record struct {
	Key
	InputSHA256  string          `json:"input_sha256"`
	Policy       string          `json:"policy"`
	Producer     Producer        `json:"producer"`
	ResultSHA256 string          `json:"result_sha256"`
	Result       json.RawMessage `json:"result"`
}

type Records struct {
	SchemaVersion int      `json:"schema_version"`
	Records       []Record `json:"records"`
}

type Result struct {
	Disposition compat.Disposition `json:"disposition"`
	Complete    *bool              `json:"complete"`
	Verdict     scribe.Verdict     `json:"verdict"`
	Data        json.RawMessage    `json:"data"`
}

type Review struct {
	Key
	ScopeSHA256  string   `json:"scope_sha256"`
	InputSHA256  string   `json:"input_sha256"`
	Policy       string   `json:"policy"`
	Kind         string   `json:"kind"`
	Producer     Producer `json:"producer"`
	ResultSHA256 string   `json:"result_sha256"`
	Decision     string   `json:"decision"`
	Reviewer     string   `json:"reviewer"`
}

type Reviews struct {
	SchemaVersion int      `json:"schema_version"`
	Reviews       []Review `json:"reviews"`
}

type Case struct {
	ID           string          `json:"id"`
	Input        json.RawMessage `json:"input"`
	ReviewSHA256 string          `json:"review_sha256"`
}

type Workflow struct {
	ID                string   `json:"id"`
	ReferenceKind     string   `json:"reference_kind"`
	ReferenceProducer Producer `json:"reference_producer"`
	Cases             []Case   `json:"cases"`
}

type Plan struct {
	SchemaVersion int        `json:"schema_version"`
	Policy        string     `json:"policy"`
	Release       Release    `json:"release"`
	Workflows     []Workflow `json:"workflows"`
}

type Finding struct {
	Reason string `json:"reason"`
	Source string `json:"source"`
}

type Observation struct {
	Producer     Producer           `json:"producer"`
	ResultSHA256 string             `json:"result_sha256"`
	Disposition  compat.Disposition `json:"disposition,omitempty"`
	Complete     *bool              `json:"complete,omitempty"`
	Verdict      scribe.Verdict     `json:"verdict,omitempty"`
}

type CaseReport struct {
	ID           string         `json:"id"`
	InputSHA256  string         `json:"input_sha256"`
	ReviewSHA256 string         `json:"review_sha256"`
	Candidate    *Observation   `json:"candidate,omitempty"`
	Reference    *Observation   `json:"reference,omitempty"`
	State        string         `json:"state"`
	Verdict      scribe.Verdict `json:"verdict"`
	Findings     []Finding      `json:"findings"`
}

func (c *CaseReport) reject(reason, source string) {
	c.Findings = append(c.Findings, Finding{Reason: reason, Source: source})
	if c.State != "invalid" {
		c.State = "invalid"
		if reason == "missing_record" || reason == "missing_review" || reason == "incomplete_result" || reason == "unknown_verdict" {
			c.State = "unknown"
		}
	}
}

type ScopeReport struct {
	ID                string       `json:"id"`
	ScopeSHA256       string       `json:"scope_sha256"`
	ReferenceKind     string       `json:"reference_kind"`
	ReferenceProducer Producer     `json:"reference_producer"`
	Required          int          `json:"required"`
	Affirmative       int          `json:"affirmative"`
	Negative          int          `json:"negative"`
	Unknown           int          `json:"unknown"`
	Invalid           int          `json:"invalid"`
	VerifiedLegacy    int          `json:"verified_legacy"`
	Qualified         bool         `json:"qualified"`
	Findings          []Finding    `json:"findings"`
	Cases             []CaseReport `json:"cases"`
}

type Unconfigured struct {
	Key
	Source string `json:"source"`
}

type Report struct {
	SchemaVersion    int            `json:"schema_version"`
	Policy           string         `json:"policy"`
	Release          Release        `json:"release"`
	ReleaseQualified bool           `json:"release_qualified"`
	ResultsSHA256    string         `json:"results_sha256"`
	Scopes           []ScopeReport  `json:"scopes"`
	Unconfigured     []Unconfigured `json:"unconfigured_records"`
}

type casePin struct {
	ID          string `json:"id"`
	InputSHA256 string `json:"input_sha256"`
}

type scopePin struct {
	SchemaVersion     int       `json:"schema_version"`
	Policy            string    `json:"policy"`
	Release           Release   `json:"release"`
	ID                string    `json:"id"`
	ReferenceKind     string    `json:"reference_kind"`
	ReferenceProducer Producer  `json:"reference_producer"`
	Cases             []casePin `json:"cases"`
}

func newScopePin(plan Plan, workflow Workflow, cases []casePin) scopePin {
	return scopePin{
		SchemaVersion: plan.SchemaVersion, Policy: plan.Policy, Release: plan.Release, ID: workflow.ID,
		ReferenceKind: workflow.ReferenceKind, ReferenceProducer: workflow.ReferenceProducer, Cases: cases,
	}
}

func SHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func digest(value any) string {
	// Callers pass validated structs containing only concrete JSON types.
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return SHA256(data)
}

func validHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, r := range value {
		if !(r >= '0' && r <= '9') && !(r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}

func validID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, r := range value {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && !(i > 0 && (r == '.' || r == '-' || r == '_')) {
			return false
		}
	}
	return true
}

func (p Producer) valid() bool {
	return validID(p.ID) && validHex(p.SHA256, 64)
}

func shareProducer(left, right Producer) bool {
	return (left.ID != "" && left.ID == right.ID) || (left.SHA256 != "" && left.SHA256 == right.SHA256)
}

func sortedKeys[T any](index map[string]T) []string {
	keys := make([]string, 0, len(index))
	for key := range index {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

type evidence struct {
	candidates map[Key][]Record
	references map[Key][]Record
	reviews    map[Key][]Review
}

func indexByKey[T any](rows []T, key func(T) Key) map[Key][]T {
	index := make(map[Key][]T, len(rows))
	for _, row := range rows {
		id := key(row)
		index[id] = append(index[id], row)
	}
	return index
}

func Load(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("evidence must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxInputBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxInputBytes {
		return errors.New("evidence file exceeds 8 MiB")
	}
	if err := decode(data, value); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func decode(data []byte, value any) error {
	if trimmed := bytes.TrimSpace(data); len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("expected a JSON object")
	}
	if err := validateJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func normalize(data []byte) ([]byte, error) {
	if err := validateJSON(data); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func validateJSON(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("expected one JSON value")
	}
	return nil
}

func walkJSON(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := token.(string)
			if !ok || seen[name] {
				return fmt.Errorf("invalid or duplicate JSON field %q", token)
			}
			seen[name] = true
			if err := walkJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	case json.Delim('['):
		for decoder.More() {
			if err := walkJSON(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return nil
	}
	_, err = decoder.Token()
	return err
}

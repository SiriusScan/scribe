package compatlineage

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/compat"
)

func sample(t *testing.T) (Plan, Records, Records, Reviews) {
	t.Helper()
	var plan Plan
	var candidate, reference Records
	var review Reviews
	for _, file := range []struct {
		name  string
		value any
	}{{"scope.json", &plan}, {"candidate.json", &candidate}, {"reference.json", &reference}, {"review.json", &review}} {
		if err := Load(filepath.Join("testdata", file.name), file.value); err != nil {
			t.Fatal(err)
		}
	}
	return plan, candidate, reference, review
}

func TestReviewedSyntheticLineage(t *testing.T) {
	plan, candidate, reference, review := sample(t)
	got, err := Evaluate(plan, candidate, reference, review)
	if err != nil {
		t.Fatal(err)
	}
	if got.ReleaseQualified || len(got.Scopes) != 2 {
		t.Fatalf("unexpected report: %+v", got)
	}
	alpha, beta := got.Scopes[0], got.Scopes[1]
	if alpha.Required != 1 || alpha.Affirmative != 1 || alpha.Negative != 0 ||
		beta.Required != 1 || beta.Affirmative != 0 || beta.Negative != 1 {
		t.Fatalf("unexpected coverage: %+v", got.Scopes)
	}
	for _, scope := range got.Scopes {
		row := scope.Cases[0]
		if scope.Qualified || scope.VerifiedLegacy != 0 || row.State != "match" ||
			row.Candidate.Producer == row.Reference.Producer || row.Candidate.ResultSHA256 == row.Reference.ResultSHA256 {
			t.Fatalf("unexpected synthetic evidence: %+v", scope)
		}
	}
	asJSON := func(x Report) []byte {
		data, err := json.MarshalIndent(x, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	slices.Reverse(plan.Workflows)
	slices.Reverse(candidate.Records)
	slices.Reverse(reference.Records)
	slices.Reverse(review.Reviews)
	reordered, err := Evaluate(plan, candidate, reference, review)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(asJSON(got), asJSON(reordered)) {
		t.Fatal("row order changed normalized receipt bytes")
	}
}

func TestLineageFailuresAreScoped(t *testing.T) {
	type edit func(*Plan, *Records, *Records, *Reviews)
	tests := []struct {
		name, reason, source, state string
		edit                        edit
	}{
		{"missing reference", "missing_record", "reference", "unknown", func(_ *Plan, _, r *Records, _ *Reviews) {
			r.Records = r.Records[1:]
		}},
		{"missing review", "missing_review", "review", "unknown", func(_ *Plan, _, _ *Records, r *Reviews) {
			r.Reviews = r.Reviews[1:]
		}},
		{"unpinned receipt", "unpinned_review", "review", "invalid", func(p *Plan, _, _ *Records, _ *Reviews) {
			p.Workflows[0].Cases[0].ReviewSHA256 = ""
		}},
		{"unapproved review", "unreviewed_reference", "review", "invalid", func(_ *Plan, _, _ *Records, r *Reviews) {
			r.Reviews[0].Decision = "pending"
		}},
		{"reviewer is producer", "self_referential_review", "review", "invalid", func(p *Plan, _, _ *Records, r *Reviews) {
			r.Reviews[0].Reviewer = p.Release.ScribeProducer.ID
		}},
		{"candidate relabelled", "self_referential_reference", "reference", "invalid", func(_ *Plan, c, r *Records, _ *Reviews) {
			r.Records[0] = c.Records[0]
		}},
		{"producer alias", "self_referential_reference", "reference", "invalid", func(_ *Plan, c, r *Records, _ *Reviews) {
			r.Records[0].Producer.SHA256 = c.Records[0].Producer.SHA256
		}},
		{"unknown artifact", "producer_mismatch", "reference", "invalid", func(_ *Plan, _, r *Records, _ *Reviews) {
			r.Records[0].Producer.SHA256 = strings.Repeat("f", 64)
		}},
		{"stale input", "input_digest_mismatch", "reference", "invalid", func(_ *Plan, _, r *Records, _ *Reviews) {
			r.Records[0].InputSHA256 = strings.Repeat("0", 64)
		}},
		{"stale policy", "normalization_policy_mismatch", "reference", "invalid", func(_ *Plan, _, r *Records, _ *Reviews) {
			r.Records[0].Policy = "other-v1"
		}},
		{"duplicate record", "duplicate_case", "candidate", "invalid", func(_ *Plan, c, _ *Records, _ *Reviews) {
			c.Records = append(c.Records, c.Records[0])
		}},
		{"duplicate required case", "duplicate_case", "scope", "invalid", func(p *Plan, _, _ *Records, _ *Reviews) {
			p.Workflows[0].Cases = append(p.Workflows[0].Cases, p.Workflows[0].Cases[0])
		}},
		{"changed body", "result_digest_mismatch", "reference", "invalid", func(_ *Plan, _, r *Records, _ *Reviews) {
			r.Records[0].Result = []byte(`{"disposition":"completed","complete":true,"verdict":"vulnerable","data":null}`)
		}},
		{"changed body and submitted digest", "review_subject_mismatch", "review", "invalid", func(_ *Plan, _, r *Records, _ *Reviews) {
			replaceResult(&r.Records[0], "completed", "vulnerable", true, `{"changed":true}`)
		}},
		{"stale workflow case set", "review_scope_mismatch", "review", "invalid", func(p *Plan, _, _ *Records, _ *Reviews) {
			p.Workflows[0].Cases = append(p.Workflows[0].Cases, Case{ID: "new-case", Input: []byte(`{}`)})
		}},
		{"mismatched normalized output", "semantic_mismatch", "comparison", "invalid", func(_ *Plan, c, _ *Records, _ *Reviews) {
			replaceResult(&c.Records[0], "completed", "vulnerable", true, `{"changed":true}`)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			plan, candidate, reference, review := sample(t)
			tc.edit(&plan, &candidate, &reference, &review)
			got, err := Evaluate(plan, candidate, reference, review)
			if err != nil {
				t.Fatal(err)
			}
			row := got.Scopes[0].Cases[0]
			if row.State != tc.state || row.Verdict != scribe.Unknown ||
				!slices.Contains(row.Findings, Finding{Reason: tc.reason, Source: tc.source}) {
				t.Fatalf("unexpected row state and findings: %+v", row)
			}
			if got.Scopes[1].Negative != 1 || got.Scopes[1].Cases[0].State != "match" || got.ReleaseQualified {
				t.Fatalf("failure changed independent scope coverage: %+v", got.Scopes)
			}
		})
	}
}

func replaceResult(row *Record, disposition compat.Disposition, verdict scribe.Verdict, complete bool, data string) {
	result, _ := json.Marshal(Result{Disposition: disposition, Complete: &complete, Verdict: verdict, Data: []byte(data)})
	row.Result, row.ResultSHA256 = result, SHA256(result)
}

func TestNegativeNeedsExplicitCompletedTerminalVerdict(t *testing.T) {
	for _, tc := range []struct {
		disposition compat.Disposition
		verdict     scribe.Verdict
		complete    bool
		state       string
	}{
		{compat.Completion, scribe.Unknown, true, "unknown"},
		{compat.Completion, "", true, "unknown"},
		{compat.Completion, scribe.NotVulnerable, false, "unknown"},
		{compat.KnownUnsupported, scribe.NotVulnerable, true, "unknown"},
		{compat.RuleIneligible, scribe.NotVulnerable, true, "unknown"},
		{compat.Rejection, scribe.NotVulnerable, true, "unknown"},
		{compat.MissingFacts, scribe.NotVulnerable, true, "unknown"},
		{compat.Timeout, scribe.NotVulnerable, true, "unknown"},
		{compat.Cancellation, scribe.NotVulnerable, false, "unknown"},
		{compat.Completion, scribe.Vulnerable, true, "invalid"},
		{compat.Completion, "unspecified", true, "invalid"},
	} {
		plan, candidate, reference, review := sample(t)
		replaceResult(&candidate.Records[1], tc.disposition, tc.verdict, tc.complete, `{"observation":"absent"}`)
		got, err := Evaluate(plan, candidate, reference, review)
		if err != nil {
			t.Fatal(err)
		}
		row := got.Scopes[1].Cases[0]
		if row.State != tc.state || row.Verdict != scribe.Unknown || got.Scopes[1].Negative != 0 || got.ReleaseQualified {
			t.Fatalf("candidate %+v produced unexpected case: %+v", tc, row)
		}
	}
}

func TestPinnedLegacyReleaseScope(t *testing.T) {
	// All digests and results in this test stand in for hypothetical artifacts.
	plan, candidate, reference, review := sample(t)
	plan.Workflows, candidate.Records, reference.Records, review.Reviews =
		plan.Workflows[:1], candidate.Records[:1], reference.Records[:1], review.Reviews[:1]
	workflow := &plan.Workflows[0]
	workflow.ReferenceKind = legacyReference
	plan.Release.ReferenceVersion = "7.95"
	plan.Release.ReferenceRevision = strings.Repeat("a", 40)
	plan.Release.ReferenceProducer = workflow.ReferenceProducer
	plan.Release.SiriusCommit = strings.Repeat("b", 40)
	plan.Release.ScannerCommit = strings.Repeat("c", 40)
	plan.Release.CatalogRevision = strings.Repeat("d", 40)
	plan.Release.CatalogSHA256 = strings.Repeat("e", 64)
	plan.Release.FixtureManifestSHA256 = strings.Repeat("f", 64)
	receipt := &review.Reviews[0]
	receipt.Kind = legacyReference
	receipt.ScopeSHA256 = digest(newScopePin(plan, *workflow, []casePin{{ID: workflow.Cases[0].ID, InputSHA256: receipt.InputSHA256}}))
	workflow.Cases[0].ReviewSHA256 = digest(*receipt)

	report, err := Evaluate(plan, candidate, reference, review)
	if err != nil || !report.ReleaseQualified || !report.Scopes[0].Qualified || report.Scopes[0].VerifiedLegacy != 1 {
		t.Fatalf("hypothetical complete legacy scope failed: %+v, %v", report, err)
	}
	plan.Release.ScannerCommit = strings.Repeat("e", 40)
	report, err = Evaluate(plan, candidate, reference, review)
	if err != nil || report.ReleaseQualified || report.Scopes[0].VerifiedLegacy != 0 ||
		!slices.Contains(report.Scopes[0].Cases[0].Findings, Finding{Reason: "review_scope_mismatch", Source: "review"}) {
		t.Fatalf("stale release qualified: %+v, %v", report, err)
	}
}

func TestCurrentFixtureReportDoesNotEstablishLineage(t *testing.T) {
	manifest, err := compat.LoadManifest("../../compat/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtureReport compat.Report
	if err := Load("../../compat/report.json", &fixtureReport); err != nil {
		t.Fatal(err)
	}
	var cases []Case
	for _, row := range manifest.Cases {
		input, err := json.Marshal(map[string]any{"target": row.Target, "args": row.Args})
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, Case{ID: row.ID, Input: input})
	}
	plan := Plan{
		SchemaVersion: SchemaVersion, Policy: Policy,
		Release: Release{FixtureManifestSHA256: fixtureReport.ManifestSHA256},
		Workflows: []Workflow{{ID: "original-fixtures", ReferenceKind: legacyReference, Cases: cases}},
	}
	rows := Records{SchemaVersion: SchemaVersion}
	got, err := Evaluate(plan, rows, rows, Reviews{SchemaVersion: SchemaVersion})
	if err != nil {
		t.Fatal(err)
	}
	scope := got.Scopes[0]
	if len(fixtureReport.CoveredCases(manifest)) != 5 || scope.Required != 10 ||
		scope.Unknown != 10 || scope.VerifiedLegacy != 0 || scope.Qualified || got.ReleaseQualified {
		t.Fatalf("unexpected legacy coverage: %+v", scope)
	}
}

func TestMalformedJSON(t *testing.T) {
	for _, input := range []string{`{}` + `{}`, `{"schema_version":1,"schema_version":1}`, "   ", `{"unexpected":1}`} {
		var plan Plan
		if decode([]byte(input), &plan) == nil {
			t.Errorf("accepted malformed plan: %q", input)
		}
	}
}

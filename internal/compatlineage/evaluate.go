package compatlineage

import (
	"bytes"
	"errors"
	"fmt"
	"sort"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/compat"
)

const (
	legacyReference    = "legacy"
	syntheticReference = "synthetic"
)

func Evaluate(plan Plan, candidate, reference Records, reviewed Reviews) (Report, error) {
	if plan.SchemaVersion != SchemaVersion || candidate.SchemaVersion != SchemaVersion ||
		reference.SchemaVersion != SchemaVersion || reviewed.SchemaVersion != SchemaVersion {
		return Report{}, errors.New("all lineage inputs require schema_version 1")
	}
	if plan.Policy != Policy {
		return Report{}, fmt.Errorf("unsupported normalization policy %q", plan.Policy)
	}
	workflows := make(map[string]Workflow, len(plan.Workflows))
	configured := make(map[Key]bool)
	for _, workflow := range plan.Workflows {
		if !validID(workflow.ID) {
			return Report{}, fmt.Errorf("invalid workflow ID %q", workflow.ID)
		}
		if _, exists := workflows[workflow.ID]; exists {
			return Report{}, fmt.Errorf("duplicate workflow ID %q", workflow.ID)
		}
		workflows[workflow.ID] = workflow
		for _, c := range workflow.Cases {
			configured[Key{Workflow: workflow.ID, CaseID: c.ID}] = true
		}
	}
	observed := evidence{
		candidates: indexByKey(candidate.Records, func(row Record) Key { return row.Key }),
		references: indexByKey(reference.Records, func(row Record) Key { return row.Key }),
		reviews:    indexByKey(reviewed.Reviews, func(row Review) Key { return row.Key }),
	}
	report := Report{
		SchemaVersion: SchemaVersion, Policy: plan.Policy, Release: plan.Release,
		Scopes: make([]ScopeReport, 0, len(workflows)), Unconfigured: []Unconfigured{},
		ReleaseQualified: len(workflows) > 0,
	}
	report.Unconfigured = appendUnconfigured(report.Unconfigured, observed.candidates, configured, "candidate")
	report.Unconfigured = appendUnconfigured(report.Unconfigured, observed.references, configured, "reference")
	report.Unconfigured = appendUnconfigured(report.Unconfigured, observed.reviews, configured, "review")
	sort.Slice(report.Unconfigured, func(i, j int) bool {
		a, b := report.Unconfigured[i], report.Unconfigured[j]
		if a.Workflow != b.Workflow {
			return a.Workflow < b.Workflow
		}
		if a.CaseID != b.CaseID {
			return a.CaseID < b.CaseID
		}
		return a.Source < b.Source
	})
	unconfiguredScopes := make(map[string]bool)
	for _, row := range report.Unconfigured {
		unconfiguredScopes[row.Workflow] = true
	}
	report.ReleaseQualified = report.ReleaseQualified && len(report.Unconfigured) == 0
	for _, id := range sortedKeys(workflows) {
		scope := evaluateScope(plan, workflows[id], observed, unconfiguredScopes[id])
		report.Scopes = append(report.Scopes, scope)
		report.ReleaseQualified = report.ReleaseQualified && scope.Qualified
	}
	report.ResultsSHA256 = digest(report.Scopes)
	return report, nil
}

func appendUnconfigured[T any](rows []Unconfigured, supplied map[Key][]T, configured map[Key]bool, source string) []Unconfigured {
	for key := range supplied {
		if !configured[key] {
			rows = append(rows, Unconfigured{Key: key, Source: source})
		}
	}
	return rows
}

func evaluateScope(plan Plan, workflow Workflow, observed evidence, unconfigured bool) ScopeReport {
	scope := ScopeReport{ID: workflow.ID, ReferenceKind: workflow.ReferenceKind, ReferenceProducer: workflow.ReferenceProducer,
		Findings: []Finding{}, Cases: []CaseReport{}}
	addFinding := func(reason string) {
		scope.Findings = append(scope.Findings, Finding{Reason: reason, Source: "scope"})
	}
	switch workflow.ReferenceKind {
	case legacyReference:
		if !plan.Release.complete() {
			addFinding("incomplete_release_tuple")
		}
		if workflow.ReferenceProducer != plan.Release.ReferenceProducer {
			addFinding("legacy_artifact_mismatch")
		}
	case syntheticReference:
		addFinding("synthetic_reference")
	default:
		addFinding("invalid_reference_kind")
	}
	if !plan.Release.ScribeProducer.valid() {
		addFinding("candidate_producer_unpinned")
	}
	if !workflow.ReferenceProducer.valid() {
		addFinding("reference_producer_unpinned")
	}
	if shareProducer(plan.Release.ScribeProducer, workflow.ReferenceProducer) {
		addFinding("self_referential_reference")
	}
	if unconfigured {
		addFinding("unconfigured_case")
	}

	cases := make(map[string][]Case, len(workflow.Cases))
	for _, c := range workflow.Cases {
		cases[c.ID] = append(cases[c.ID], c)
	}
	if len(cases) == 0 {
		addFinding("empty_scope")
	}

	pins := make([]casePin, 0, len(cases))
	for _, id := range sortedKeys(cases) {
		row := CaseReport{ID: id, Verdict: scribe.Unknown, Findings: []Finding{}}
		switch {
		case len(cases[id]) != 1:
			row.reject("duplicate_case", "scope")
		case !validID(id):
			row.reject("invalid_case_id", "scope")
		default:
			config := cases[id][0]
			row.ReviewSHA256 = config.ReviewSHA256
			input, err := normalize(config.Input)
			if err != nil || bytes.Equal(input, []byte("null")) {
				row.reject("invalid_supplied_input", "scope")
			} else {
				row.InputSHA256 = SHA256(input)
			}
		}
		pins = append(pins, casePin{ID: row.ID, InputSHA256: row.InputSHA256})
		scope.Cases = append(scope.Cases, row)
	}
	scope.ScopeSHA256 = digest(newScopePin(plan, workflow, pins))
	scope.Required = len(scope.Cases)
	for i := range scope.Cases {
		row := &scope.Cases[i]
		if len(row.Findings) == 0 {
			key := Key{Workflow: workflow.ID, CaseID: row.ID}
			evaluateCase(row, plan, workflow, scope.ScopeSHA256, key, observed)
		}
		switch row.State {
		case "match":
			if row.Verdict == scribe.Vulnerable {
				scope.Affirmative++
			} else {
				scope.Negative++
			}
		case "unknown":
			scope.Unknown++
		case "invalid":
			scope.Invalid++
		}
	}
	if workflow.ReferenceKind == legacyReference && len(scope.Findings) == 0 {
		scope.VerifiedLegacy = scope.Affirmative + scope.Negative
		scope.Qualified = scope.VerifiedLegacy == scope.Required
	}
	return scope
}

func evaluateCase(row *CaseReport, plan Plan, workflow Workflow, scopeDigest string, key Key, supplied evidence) {
	candidateRows, referenceRows, reviews := supplied.candidates[key], supplied.references[key], supplied.reviews[key]
	candidate, candidateData := checkRecord(row, candidateRows, plan.Release.ScribeProducer, "candidate")
	reference, referenceData := checkRecord(row, referenceRows, workflow.ReferenceProducer, "reference")
	row.Candidate, row.Reference = candidate, reference
	if reference != nil && (shareProducer(reference.Producer, plan.Release.ScribeProducer) ||
		(candidate != nil && shareProducer(reference.Producer, candidate.Producer))) {
		row.reject("self_referential_reference", "reference")
	}
	checkReview(row, reviews, scopeDigest, plan.Release.ScribeProducer, workflow, reference)
	if len(row.Findings) != 0 {
		return
	}
	if candidate.Verdict != reference.Verdict || !bytes.Equal(candidateData, referenceData) {
		row.reject("semantic_mismatch", "comparison")
		return
	}
	row.State, row.Verdict = "match", candidate.Verdict
}

func checkRecord(row *CaseReport, supplied []Record, producer Producer, source string) (*Observation, []byte) {
	switch len(supplied) {
	case 0:
		row.reject("missing_record", source)
		return nil, nil
	case 1:
	default:
		row.reject("duplicate_case", source)
		return nil, nil
	}
	record := supplied[0]
	observation := &Observation{Producer: record.Producer, ResultSHA256: record.ResultSHA256}
	if !producer.valid() || record.Producer != producer {
		row.reject("producer_mismatch", source)
	}
	if record.InputSHA256 != row.InputSHA256 {
		row.reject("input_digest_mismatch", source)
	}
	if record.Policy != Policy {
		row.reject("normalization_policy_mismatch", source)
	}
	if record.ResultSHA256 != SHA256(record.Result) {
		row.reject("result_digest_mismatch", source)
		return observation, nil
	}
	var result Result
	if err := decode(record.Result, &result); err != nil {
		row.reject("invalid_result", source)
		return observation, nil
	}
	observation.Disposition, observation.Complete, observation.Verdict = result.Disposition, result.Complete, result.Verdict
	switch result.Disposition {
	case compat.Completion:
		if result.Complete == nil || !*result.Complete {
			row.reject("incomplete_result", source)
		}
	case compat.Rejection, compat.RuleIneligible, compat.MissingFacts, compat.KnownUnsupported, compat.Timeout, compat.Cancellation, compat.Unmeasured:
		row.reject("incomplete_result", source)
	default:
		row.reject("invalid_disposition", source)
	}
	switch result.Verdict {
	case scribe.Vulnerable, scribe.NotVulnerable:
	case "", scribe.Unknown:
		row.reject("unknown_verdict", source)
	default:
		row.reject("invalid_verdict", source)
	}
	data, err := normalize(result.Data)
	if err != nil {
		row.reject("invalid_result_data", source)
	}
	return observation, data
}

func checkReview(row *CaseReport, reviews []Review, scopeDigest string, candidateProducer Producer, workflow Workflow, reference *Observation) {
	switch len(reviews) {
	case 0:
		row.reject("missing_review", "review")
		return
	case 1:
	default:
		row.reject("duplicate_case", "review")
		return
	}
	review := reviews[0]
	if !validHex(row.ReviewSHA256, 64) {
		row.reject("unpinned_review", "review")
	} else if row.ReviewSHA256 != digest(review) {
		row.reject("review_digest_mismatch", "review")
	}
	if review.Decision != "approved" || !validID(review.Reviewer) {
		row.reject("unreviewed_reference", "review")
	}
	if review.Reviewer == candidateProducer.ID || review.Reviewer == workflow.ReferenceProducer.ID {
		row.reject("self_referential_review", "review")
	}
	if review.ScopeSHA256 != scopeDigest {
		row.reject("review_scope_mismatch", "review")
	}
	if review.InputSHA256 != row.InputSHA256 {
		row.reject("review_input_digest_mismatch", "review")
	}
	if review.Policy != Policy {
		row.reject("review_policy_mismatch", "review")
	}
	if review.Kind != workflow.ReferenceKind || review.Producer != workflow.ReferenceProducer {
		row.reject("review_producer_mismatch", "review")
	}
	if reference != nil && review.ResultSHA256 != reference.ResultSHA256 {
		row.reject("review_subject_mismatch", "review")
	}
}

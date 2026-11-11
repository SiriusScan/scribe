// Package report maps execution evidence into a versioned Sirius adapter envelope.
package report

import "github.com/SiriusScan/scribe"

// Source identifies the engine and script configuration that produced evidence.
type Source struct {
	// Name identifies the evidence producer; Map uses scribe, empty is unspecified.
	Name string `json:"name"`
	// Config contains script_id, script_sha256 and dialect from Map; nil supplies no provenance.
	Config map[string]string `json:"config"`
}

// Envelope is the schema-v1 report with raw evidence and a conservative assessment.
type Envelope struct {
	// SchemaVersion is 1 for mapped reports; zero is uninitialized.
	SchemaVersion int `json:"schema_version"`
	// Source contains execution provenance; zero supplies none.
	Source Source `json:"source"`
	// Assessment is inconclusive unless completed native explicit evidence establishes a verdict; empty is uninitialized.
	Assessment string `json:"assessment"`
	// Verdict is unknown unless completed native evidence establishes an explicit verdict; empty is uninitialized.
	Verdict scribe.Verdict `json:"verdict"`
	// Evidence preserves the original result; zero establishes no execution or verdict.
	Evidence scribe.Result `json:"evidence"`
}

// Map preserves original evidence. Only completed explicit native verdicts establish assessments.
func Map(r scribe.Result) Envelope {
	e := Envelope{SchemaVersion: 1, Source: Source{Name: "scribe", Config: map[string]string{"script_id": r.ScriptID, "script_sha256": r.ScriptSHA256, "dialect": string(r.Dialect)}}, Assessment: "inconclusive", Verdict: scribe.Unknown, Evidence: r}
	if r.Status == scribe.Completed && r.Dialect == scribe.Sirius {
		switch r.Verdict {
		case scribe.Vulnerable, scribe.NotVulnerable:
			e.Verdict = r.Verdict
			e.Assessment = string(r.Verdict)
		}
	}
	return e
}

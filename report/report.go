// Package report maps execution evidence into a versioned Sirius adapter envelope.
package report

import "github.com/SiriusScan/scribe"

type Source struct {
	Name   string            `json:"name"`
	Config map[string]string `json:"config"`
}
type Envelope struct {
	SchemaVersion int            `json:"schema_version"`
	Source        Source         `json:"source"`
	Assessment    string         `json:"assessment"`
	Verdict       scribe.Verdict `json:"verdict"`
	Evidence      scribe.Result  `json:"evidence"`
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

package report

import (
	"github.com/SiriusScan/scribe"
	"testing"
)

func TestAssessments(t *testing.T) {
	for _, status := range []scribe.Status{scribe.Completed, scribe.Failed, scribe.Skipped, scribe.Cancelled} {
		for _, verdict := range []scribe.Verdict{scribe.Unknown, scribe.Vulnerable, scribe.NotVulnerable} {
			r := scribe.Result{Status: status, Verdict: verdict, Dialect: scribe.Sirius, ScriptID: "fixture", ScriptSHA256: "digest", Output: scribe.Output{Data: "raw"}}
			e := Map(r)
			if e.Evidence.Output.Data != "raw" || e.Source.Config["script_sha256"] != "digest" {
				t.Fatal(e)
			}
			if status != scribe.Completed && (e.Assessment != "inconclusive" || e.Verdict != scribe.Unknown) {
				t.Fatal(e)
			}
		}
	}
}

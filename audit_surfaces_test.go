package scribe_test

import (
	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/compat"
	"github.com/SiriusScan/scribe/fingerprint"
	"github.com/SiriusScan/scribe/report"
	"testing"
)

func TestAuditedEmptySurfaces(t *testing.T) {
	var matcher fingerprint.Matcher
	if got := matcher.Match("unrecognized", nil); got != (fingerprint.Facts{}) {
		t.Fatalf("empty matcher inferred facts: %+v", got)
	}
	// OK describes failure counters, not proof of coverage.
	if !(compat.Report{}).OK() {
		t.Fatal("zero report counter semantics changed")
	}
	if err := (compat.Manifest{}).Validate(); err == nil {
		t.Fatal("empty manifest accepted")
	}
	for _, status := range []scribe.Status{"", scribe.Failed, scribe.Skipped, scribe.Cancelled} {
		got := report.Map(scribe.Result{Dialect: scribe.Sirius, Status: status, Verdict: scribe.NotVulnerable})
		if got.Assessment != "inconclusive" || got.Verdict != scribe.Unknown {
			t.Fatalf("promoted incomplete evidence: %+v", got)
		}
	}
}

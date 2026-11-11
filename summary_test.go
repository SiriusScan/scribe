package scribe

import "testing"

func TestSummaryConservativeAndDedupe(t *testing.T) {
	records := []Result{
		{Status: Completed, Verdict: Vulnerable},
		{Status: Skipped, Verdict: NotVulnerable, Output: Output{SkipReason: "identity"}},
		{Status: Completed, Verdict: Unknown},
	}
	records = append(records, records[0])
	s := Summarize(records)
	if s.Total != 4 || s.ByVerdict[Vulnerable] != 2 || s.ByVerdict[Unknown] != 2 || s.BySkipReason["identity"] != 1 {
		t.Fatalf("%+v", s)
	}
	records[3].ElapsedMS = 123
	if got := Deduplicate(records); len(got) != 3 {
		t.Fatal(got)
	}
	if Summarize(nil).Total != 0 {
		t.Fatal("empty summary")
	}
}

func ExampleSummarize() {
	results := []Result{{Status: Completed, Verdict: Unknown}}
	summary := Summarize(Deduplicate(results))
	_ = summary.ByVerdict[Unknown]
}

// Uninitialized records must remain inconclusive, including forged clean verdicts.
func TestSummaryUninitializedResult(t *testing.T) {
	for _, r := range []Result{{}, {Verdict: NotVulnerable}, {Status: Failed, Verdict: Vulnerable}, {Status: Cancelled, Verdict: NotVulnerable}} {
		s := Summarize([]Result{r})
		if s.SchemaVersion != 1 || s.Type != "summary" || s.Total != 1 || s.ByStatus[r.Status] != 1 || s.ByVerdict[Unknown] != 1 || s.ByVerdict[NotVulnerable] != 0 || s.ByVerdict[Vulnerable] != 0 {
			t.Fatalf("uninitialized or unsuccessful record promoted: %+v", s)
		}
	}
}

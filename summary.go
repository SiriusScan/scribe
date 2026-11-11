package scribe

import "encoding/json"

// Summary counts execution evidence without promoting failed or skipped verdicts.
type Summary struct {
	SchemaVersion int             `json:"schema_version"`
	Type          string          `json:"type"`
	Total         int             `json:"total"`
	ByVerdict     map[Verdict]int `json:"by_verdict"`
	ByStatus      map[Status]int  `json:"by_status"`
	BySkipReason  map[string]int  `json:"by_skip_reason"`
}

// Add includes every delivered record. Only completed explicit verdicts count.
func (s *Summary) Add(r Result) {
	if s.ByVerdict == nil {
		*s = Summary{SchemaVersion: 1, Type: "summary", ByVerdict: map[Verdict]int{}, ByStatus: map[Status]int{}, BySkipReason: map[string]int{}}
	}
	s.Total++
	s.ByStatus[r.Status]++
	v := Unknown
	if r.Status == Completed && (r.Verdict == Vulnerable || r.Verdict == NotVulnerable) {
		v = r.Verdict
	}
	s.ByVerdict[v]++
	if r.Status == Skipped {
		s.BySkipReason[r.Output.SkipReason]++
	}
}

// Summarize counts all records, including duplicates.
func Summarize(results []Result) Summary {
	s := Summary{}
	s.Add(Result{})
	s.Total = 0
	clear(s.ByStatus)
	clear(s.ByVerdict)
	for _, r := range results {
		s.Add(r)
	}
	return s
}

// Deduplicate removes identical evidence records, ignoring elapsed timing.
// Conflicting verdicts and different target facts remain separate evidence.
// Memory use is proportional to caller-supplied results.
func Deduplicate(results []Result) []Result {
	seen := map[string]bool{}
	out := make([]Result, 0, len(results))
	for _, r := range results {
		key := r
		key.ElapsedMS = 0
		data, err := json.Marshal(key)
		if err != nil {
			out = append(out, r)
			continue
		}
		if !seen[string(data)] {
			seen[string(data)] = true
			out = append(out, r)
		}
	}
	return out
}

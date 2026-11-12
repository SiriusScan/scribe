package scribe

import "testing"

func TestPartialMatchKnownContradictions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		match  Match
		target Target
		want   bool
	}{
		{"missing", Match{Products: []string{"nginx"}, MinVersion: "1.0.0"}, Target{}, true},
		{"product conflict", Match{Products: []string{"nginx"}, MinVersion: "1.0.0"}, Target{Product: "Apache"}, false},
		{"version conflict", Match{Products: []string{"nginx"}, MinVersion: "2.0.0"}, Target{Version: "1.0.0"}, false},
		{"required conflict", Match{AllOf: []Match{{Products: []string{"nginx"}}, {Services: []string{"http"}}}}, Target{Service: "ssh"}, false},
		{"alternative", Match{AnyOf: []Match{{Products: []string{"nginx"}}, {Services: []string{"http"}}}}, Target{Service: "ssh"}, true},
		{"all alternatives conflict", Match{BannerRegex: "marker", AnyOf: []Match{{Products: []string{"nginx"}}, {Services: []string{"http"}}}}, Target{Product: "Apache", Service: "ssh"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.match.OnUnknown = "run"
			ok, id := tc.match.evaluate(tc.target)
			if ok != tc.want || id {
				t.Fatalf("got %v/%v want %v/false", ok, id, tc.want)
			}
		})
	}
}

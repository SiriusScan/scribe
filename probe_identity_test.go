package scribe

import "testing"

func TestProbeMergeIdentityEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, product, version string
		compatible             bool
	}{
		{"agree", "nginx", "1.2", true},
		{"missing version", "nginx", "", true},
		{"version conflict", "nginx", "9.9", false},
		{"product conflict", "Apache", "1.2", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			caller := Target{Product: tc.product, Version: tc.version}
			observed := Target{Product: "nginx", Version: "1.2", Confidence: 0.8, CPE: []string{"cpe:/a:nginx:nginx:1.2"}, Banner: "observed", TLS: true}
			got := mergeProbe(caller, observed)
			if got.Product != caller.Product || got.Version != caller.Version {
				t.Fatalf("caller identity replaced: %+v", got)
			}
			if (got.Confidence > 0) != tc.compatible || (len(got.CPE) > 0) != tc.compatible {
				t.Fatalf("incompatible identity evidence: %+v", got)
			}
			if !got.TLS || got.Banner != "observed" {
				t.Fatalf("transport evidence lost: %+v", got)
			}
		})
	}
}

func TestProbeMergePreservesCallerEvidence(t *testing.T) {
	caller := Target{Product: "nginx", Version: "9.9", Confidence: 1, CPE: []string{"caller"}}
	got := mergeProbe(caller, Target{Product: "nginx", Version: "1.2", Confidence: 0.8, CPE: []string{"probe"}})
	if got.Confidence != 1 || len(got.CPE) != 1 || got.CPE[0] != "caller" {
		t.Fatalf("caller evidence replaced: %+v", got)
	}
}

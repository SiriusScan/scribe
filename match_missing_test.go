package scribe

import "testing"

func TestAlternativeIdentificationNeeds(t *testing.T) {
	target := Target{Service: "http"}
	for _, nested := range []bool{false, true} {
		alternative := Match{AnyOf: []Match{{Services: []string{"http"}}, {Products: []string{"nginx"}}}}
		if nested {
			alternative = Match{AllOf: []Match{alternative}}
		}
		if alternative.missing(target) {
			t.Fatal("satisfied alternative requested more facts")
		}
		if ok, _ := alternative.evaluate(target); !ok {
			t.Fatal("satisfied alternative excluded")
		}
	}
	unresolved := Match{AnyOf: []Match{{Services: []string{"ssh"}}, {Products: []string{"nginx"}}}}
	if !unresolved.missing(target) {
		t.Fatal("unresolved alternative lost probe opportunity")
	}
	required := Match{AllOf: []Match{{Services: []string{"http"}}, {Products: []string{"nginx"}}}}
	if !required.missing(target) {
		t.Fatal("required identity lost")
	}
}

func TestAlternativeProductEvidence(t *testing.T) {
	for _, tc := range []struct {
		name       string
		branches   []Match
		identified bool
	}{
		{"later product", []Match{{Services: []string{"http"}}, {Products: []string{"nginx"}}}, true},
		{"earlier product", []Match{{Products: []string{"nginx"}}, {Services: []string{"ssh"}}}, true},
		{"mismatched product", []Match{{Services: []string{"http"}}, {Products: []string{"Apache"}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := Match{AnyOf: tc.branches}
			ok, identified := m.evaluate(Target{Service: "http", Product: "nginx"})
			if !ok || identified != tc.identified {
				t.Fatalf("applicable=%v identified=%v", ok, identified)
			}
		})
	}
}

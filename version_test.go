package scribe

import "testing"

func TestVersion(t *testing.T) {
	v := Version()
	if v.Module != "github.com/SiriusScan/scribe" {
		t.Fatal(v)
	}
}

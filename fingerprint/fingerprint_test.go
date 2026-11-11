package fingerprint

import (
	"net/http"
	"regexp"
	"testing"
)

func TestMatch(t *testing.T) {
	m := Default()
	f := m.Match("SSH-2.0-OpenSSH_9.0", nil)
	if f.Product != "OpenSSH" || f.Version != "9.0" {
		t.Fatal(f)
	}
	f = m.Match("", http.Header{"Server": []string{"nginx/1.2"}})
	if f.Version != "1.2" {
		t.Fatal(f)
	}
	if m.Match("unknown", nil) != (Facts{}) {
		t.Fatal("unknown matched")
	}
	custom := New(Rule{Pattern: regexp.MustCompile(`hello (\d+)`), Product: "custom"})
	if custom.Match("hello 42", nil).Version != "42" {
		t.Fatal("custom rule")
	}
}

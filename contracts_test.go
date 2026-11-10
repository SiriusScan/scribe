package scribe_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/SiriusScan/scribe"
)

func TestSkippedRuntimeCannotEmitFindings(t *testing.T) {
	engine := newEngine(t, 1, func(context.Context, scribe.Task) (scribe.Output, error) {
		return scribe.Output{Skipped: true, Data: "incomplete", Findings: []scribe.Finding{{ID: "contradiction"}}}, nil
	})
	err := engine.Run(context.Background(), tasks(1), func(result scribe.Result) error {
		if result.Status != scribe.Skipped || len(result.Output.Findings) != 0 || result.Output.Data != nil {
			t.Fatalf("skipped task retained contradictory output: %+v", result)
		}
		if result.SchemaVersion != 1 || result.ScriptSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("source"))) {
			t.Fatalf("missing execution provenance: %+v", result)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTargetRejectsMalformedHostSyntax(t *testing.T) {
	for _, host := range []string{"", "https://example.test", "example.test:443", "bad\x00host", "bad\vhost", "bad\u00a0host", "bad\\host", "[::1]", "host%bad", "user@host"} {
		if err := (scribe.Target{Host: host}).Validate(); err == nil {
			t.Errorf("accepted malformed host %q", host)
		}
	}
	for _, host := range []string{"example.test", "127.0.0.1", "::1", "2001:db8::1"} {
		if err := (scribe.Target{Host: host}).Validate(); err != nil {
			t.Errorf("rejected valid host %q: %v", host, err)
		}
	}
}

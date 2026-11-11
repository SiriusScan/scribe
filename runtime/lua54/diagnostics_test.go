package lua54

import (
	"context"
	"github.com/SiriusScan/scribe"
	"strings"
	"testing"
)

func TestDiagnosticsSurviveFailureAndBound(t *testing.T) {
	r, _ := NewNative(Options{})
	out, err := r.Execute(context.Background(), scribe.Task{Target: scribe.Target{Host: "localhost"}, Script: scribe.Script{ID: "logs", Dialect: scribe.Sirius, Source: []byte(`print("before"); return {api_version=1,action=function() log(string.rep("x",70000)); error("failed") end}`)}})
	if err == nil || !strings.HasPrefix(out.Logs, "before\n") || len(out.Logs) != 64<<10 || !out.LogsTruncated {
		t.Fatalf("capture: bytes=%d truncated=%v err=%v", len(out.Logs), out.LogsTruncated, err)
	}
}
func TestStaticCheck(t *testing.T) {
	for _, tc := range []struct {
		source  string
		dialect scribe.Dialect
		bad     bool
	}{
		{`local s=require "sirius"; return {api_version=1,action=function() return s.call("http.get") end}`, scribe.Sirius, false},
		{`local s=require "sirius"; s.missing()`, scribe.Sirius, true},
		{`local h=require "http"`, scribe.NSE, true},
		{`local s=require 'stdnse'; s.debug1("hello")`, scribe.NSE, false},
		{`error("must never execute")`, scribe.Sirius, false},
		{`require(variable)`, scribe.Sirius, true},
	} {
		err := Check(scribe.Script{ID: "check", Dialect: tc.dialect, Source: []byte(tc.source)})
		if (err != nil) != tc.bad {
			t.Errorf("%s: %v", tc.source, err)
		}
	}
}

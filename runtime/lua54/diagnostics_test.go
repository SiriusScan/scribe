package lua54

import (
	"context"
	"fmt"
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

// Shared compiled code must never share diagnostics or verdict state.
func TestParallelDiagnosticIsolation(t *testing.T) {
	r, err := NewNative(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			marker := fmt.Sprintf("fixture-%d.local", i)
			source := `return {api_version=1,action=function(t) log(t.host); if t.host == "fixture-0.local" then error("fixture failure") end; return {verdict='unknown'} end}`
			out, err := r.Execute(context.Background(), scribe.Task{Target: scribe.Target{Host: marker}, Script: scribe.Script{ID: "shared-diagnostics", Dialect: scribe.Sirius, Source: []byte(source)}})
			if out.Logs != marker+"\n" || out.LogsTruncated {
				t.Fatalf("diagnostics leaked: %+v err=%v", out, err)
			}
			if (i == 0) != (err != nil) {
				t.Fatalf("failure isolation: %v", err)
			}
		})
	}
}

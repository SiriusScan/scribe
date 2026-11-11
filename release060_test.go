package scribe

import (
	"context"
	"testing"
	"time"
)

func TestReleaseOptionsRejectNegativeLimits(t *testing.T) {
	for _, o := range []Options{{ScriptTimeout: -time.Second}, {GlobalInterval: -time.Second}} {
		if _, err := New(o); err == nil {
			t.Fatal("negative limit accepted")
		}
	}
}

func TestPlanDoesNotExecute(t *testing.T) {
	e := &Engine{options: Options{Plan: true}}
	r := e.execute(context.Background(), Task{Script: Script{ID: "plan", Dialect: Sirius, Source: []byte("error('must not execute')")}})
	if r.Status != Skipped || r.Verdict != Unknown || r.Output.SkipReason == "" {
		t.Fatalf("%+v", r)
	}
}

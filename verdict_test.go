package scribe_test

import (
	"context"
	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/runtime/lua54"
	"testing"
)

func TestVerdict(t *testing.T) {
	runtime, err := lua54.NewNative(lua54.Options{})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		body   string
		want   scribe.Verdict
		failed bool
	}{
		{"return {verdict='vulnerable'}", scribe.Vulnerable, false},
		{"return {verdict='not_vulnerable'}", scribe.NotVulnerable, false},
		{"return {}", scribe.Unknown, false},
		{"error('unsupported')", scribe.Unknown, true},
		{"return {verdict='bogus'}", scribe.Unknown, true},
	} {
		task := scribe.Task{Target: scribe.Target{Host: "localhost"}, Script: scribe.Script{ID: "test", Dialect: scribe.Sirius, Source: []byte("return {api_version=1,action=function() " + tc.body + " end}")}}
		err := engine.Run(context.Background(), []scribe.Task{task}, func(r scribe.Result) error {
			if r.Verdict != tc.want {
				t.Errorf("%s: %s", tc.body, r.Verdict)
			}
			return nil
		})
		if (err != nil) != tc.failed {
			t.Errorf("%s: %v", tc.body, err)
		}
	}
}

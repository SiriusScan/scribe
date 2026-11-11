package scribe

import (
	"encoding/json"
	"os"
	"testing"
)

func TestEventGolden(t *testing.T) {
	r := Result{SchemaVersion: 1, ScriptID: "fixture", Status: Skipped, Verdict: Unknown, Output: Output{Skipped: true, SkipReason: "product mismatch"}}
	data, err := json.MarshalIndent(Events(r), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	path := "testdata/events-v1.golden.json"
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(want) {
		t.Fatalf("event schema changed: %s", data)
	}
}

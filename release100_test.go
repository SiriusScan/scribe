package scribe

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzMatchMetadata(f *testing.F) {
	f.Add(`{"match":{"products":["nginx"],"min_version":"1.0.0"}}`)
	f.Add(`{"match":{"confidence":2}}`)
	f.Fuzz(func(t *testing.T, metadata string) {
		if len(metadata) > 65536 {
			t.Skip()
		}
		idx, err := NewIndex([]Script{{ID: "fuzz", Dialect: Sirius, Source: []byte("-- scribe: " + metadata)}})
		if err != nil {
			return
		}
		for _, m := range idx.Modules() {
			if m.Match != nil {
				if err := m.Match.validate(0); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}

func FuzzInventoryJSONL(f *testing.F) {
	f.Add("script\nname", "product\"name")
	f.Fuzz(func(t *testing.T, id, product string) {
		var b bytes.Buffer
		original := Module{Script: id, Dialect: Sirius, Match: &Match{Products: []string{product}}, Warnings: []string{}}
		if err := json.NewEncoder(&b).Encode(original); err != nil {
			t.Fatal(err)
		}
		if bytes.Count(b.Bytes(), []byte{'\n'}) != 1 {
			t.Fatal("broken JSONL framing")
		}
		var got Module
		if err := json.NewDecoder(&b).Decode(&got); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInventoryIsolation(t *testing.T) {
	idx, err := NewIndex([]Script{{ID: "fixture", Dialect: Sirius, Source: []byte(`-- scribe: {"match":{"products":["nginx"]}}`)}})
	if err != nil {
		t.Fatal(err)
	}
	idx.Modules()[0].Match.Products[0] = "changed"
	if idx.Modules()[0].Match.Products[0] != "nginx" {
		t.Fatal("inventory mutated index")
	}
}

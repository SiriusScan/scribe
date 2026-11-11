package scribe

import (
	"context"
	"fmt"
	"testing"
)

func TestSelection(t *testing.T) {
	idx, err := NewIndex([]Script{{ID: "http", Dialect: Sirius, Source: []byte("-- scribe: {\"services\":[\"http\"]}\n")}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		target Target
		n      int
	}{{Target{}, 1}, {Target{Service: "ssh"}, 0}, {Target{Service: "HTTP"}, 1}} {
		if got := len(idx.Select(tt.target)); got != tt.n {
			t.Fatalf("%+v: %d", tt.target, got)
		}
	}
	if _, err := NewIndex([]Script{{ID: "bad", Dialect: Sirius, Source: []byte("-- scribe: invalid")}}); err == nil {
		t.Fatal("accepted invalid metadata")
	}
}

type selectionRuntime struct{}

func (selectionRuntime) Dialect() Dialect                              { return Sirius }
func (selectionRuntime) Execute(context.Context, Task) (Output, error) { return Output{}, nil }
func BenchmarkSelection(b *testing.B) {
	var scripts []Script
	for i := 0; i < 100; i++ {
		scripts = append(scripts, Script{ID: fmt.Sprint(i), Dialect: Sirius, Source: []byte(fmt.Sprintf("-- scribe: {\"ports\":[%d]}", i+1))})
	}
	idx, _ := NewIndex(scripts)
	e, _ := New(Options{}, selectionRuntime{})
	target := Target{Host: "localhost", Port: 80}
	for _, selected := range []bool{false, true} {
		b.Run(fmt.Sprint(selected), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if selected {
					_ = e.RunSelected(context.Background(), idx, []Target{target}, func(Result) error { return nil })
				} else {
					var tasks []Task
					for _, s := range scripts {
						tasks = append(tasks, Task{Script: s, Target: target})
					}
					_ = e.Run(context.Background(), tasks, func(Result) error { return nil })
				}
			}
		})
	}
}

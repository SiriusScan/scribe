package localcap_test

import (
	"context"
	"errors"
	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/capability/localcap"
	"github.com/SiriusScan/scribe/runtime/lua54"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "small"), []byte("hello"), 0600)
	os.WriteFile(filepath.Join(dir, "large"), make([]byte, localcap.MaxBytes+1), 0600)
	functions, close, err := localcap.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer close()
	read := functions["local.file.read"]
	value, err := read(context.Background(), scribe.Target{}, []any{"small"})
	if err != nil || value != "hello" {
		t.Fatalf("%v %v", value, err)
	}
	for _, p := range []string{"large", "../outside", "."} {
		if _, err := read(context.Background(), scribe.Target{}, []any{p}); err == nil {
			t.Fatal(p)
		}
	}
	runtime, err := lua54.NewNative(lua54.Options{Functions: functions})
	if err != nil {
		t.Fatal(err)
	}
	task := scribe.Task{Target: scribe.Target{Host: "localhost"}, Capabilities: []string{}, Script: scribe.Script{ID: "local", Dialect: scribe.Sirius, Source: []byte(`return {api_version=1,action=function() return {data=sirius.call("local.file.read","small")} end}`)}}
	_, err = runtime.Execute(context.Background(), task)
	var denied *scribe.CapabilityDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("typed denial: %v", err)
	}
	task.Capabilities = []string{"local.file.read"}
	if _, err = runtime.Execute(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if _, err := runtime.Execute(ctx, task); !errors.Is(err, context.Canceled) {
					t.Errorf("cancel: %v", err)
				}
				if _, err := runtime.Execute(context.Background(), task); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
}
func BenchmarkLocalJobs(b *testing.B) {
	dir := b.TempDir()
	os.WriteFile(filepath.Join(dir, "small"), []byte("hello"), 0600)
	functions, close, err := localcap.New(dir)
	if err != nil {
		b.Fatal(err)
	}
	defer close()
	runtime, err := lua54.NewNative(lua54.Options{Functions: functions})
	if err != nil {
		b.Fatal(err)
	}
	for _, source := range []string{`return {api_version=1,action=function() return {verdict="unknown"} end}`, `return {api_version=1,action=function() return {data=sirius.call("local.file.read","small")} end}`} {
		b.Run(source, func(b *testing.B) {
			task := scribe.Task{Target: scribe.Target{Host: "localhost"}, Capabilities: []string{"local.file.read"}, Script: scribe.Script{ID: "bench", Dialect: scribe.Sirius, Source: []byte(source)}}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := runtime.Execute(context.Background(), task); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

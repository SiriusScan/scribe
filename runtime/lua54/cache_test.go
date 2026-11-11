package lua54

import (
	"context"
	"github.com/SiriusScan/scribe"
	"strings"
	"sync"
	"testing"
)

func TestCachedTemplateIsolation(t *testing.T) {
	r, _ := newRuntime(scribe.Sirius, Options{})
	input := task(scribe.Sirius, `counter=(counter or 0)+1
 local n=0
 return {api_version=1,action=function() n=n+1; assert(counter==1 and n==1); string.changed=true; return {data=counter} end}`)
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				if _, err := r.Execute(context.Background(), input); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if len(r.cache.items) != 1 || r.cache.items[0].code == nil {
		t.Fatal("template not cached")
	}
	input.Script.Source = []byte(`return {api_version=1,action=function() assert(string.changed==nil);return {data="changed"} end}`)
	if _, err := r.Execute(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	if len(r.cache.items) != 2 {
		t.Fatal("source digest was not part of cache key")
	}
}
func TestCacheBoundsAndTightenedLimits(t *testing.T) {
	r, _ := newRuntime(scribe.Sirius, Options{CacheEntries: 2, CacheBytes: 1 << 20})
	for _, id := range []string{"one", "two", "three"} {
		input := task(scribe.Sirius, `return {api_version=1,action=function() return {} end}`)
		input.Script.ID = id
		if _, err := r.Execute(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.cache.items) != 2 || r.cache.used > r.cache.ceiling {
		t.Fatal("cache bounds")
	}
	input := task(scribe.Sirius, `return {api_version=1,action=function() return {} end}`)
	input.Script.ID = "three"
	input.Limits.Memory = 1
	if _, err := r.Execute(context.Background(), input); err == nil {
		t.Fatal("cached template bypassed memory limit")
	}
}
func TestHintSkipBeforeVM(t *testing.T) {
	r, _ := newRuntime(scribe.Sirius, Options{})
	input := task(scribe.Sirius, "-- scribe: {\"services\":[\"ssh\"]}\nerror('must never initialize')")
	input.Limits.Memory = 1
	out, err := r.Execute(context.Background(), input)
	if err != nil || !out.Skipped || out.SkipReason == "" {
		t.Fatalf("%+v %v", out, err)
	}
	if r.cache.items[0].code != nil {
		t.Fatal("skip compiled code")
	}
	input.Target.Service = "ssh"
	input.Limits.Memory = 0
	if _, err = r.Execute(context.Background(), input); err == nil || !strings.Contains(err.Error(), "must never initialize") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestCachedCodePreservesGrantsAndCPU(t *testing.T) {
	r, _ := newRuntime(scribe.Sirius, Options{Functions: map[string]scribe.Function{"read": func(context.Context, scribe.Target, []any) (any, error) { return "ok", nil }}})
	input := task(scribe.Sirius, `return {api_version=1,action=function() return {data=sirius.call("read")} end}`)
	if _, err := r.Execute(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input.Capabilities = []string{}
	if _, err := r.Execute(context.Background(), input); err == nil {
		t.Fatal("cache leaked capability grants")
	}
	input = task(scribe.Sirius, `return {api_version=1,action=function(t,args) if args.loop then while true do end end;return {} end}`)
	if _, err := r.Execute(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	input.Script.Args = map[string]any{"loop": true}
	input.Limits.CPU = 10000
	if _, err := r.Execute(context.Background(), input); err == nil {
		t.Fatal("cached code bypassed CPU limit")
	}
}

func TestTinyCacheDoesNotRetainOversizedPlan(t *testing.T) {
	r, _ := newRuntime(scribe.Sirius, Options{CacheBytes: 256})
	input := task(scribe.Sirius, `return {api_version=1,action=function() return {} end}`)
	for range 2 {
		if _, err := r.Execute(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.cache.items) != 0 || r.cache.used != 0 {
		t.Fatal("retained entry above byte ceiling")
	}
}

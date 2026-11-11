package lua54

import (
	"context"
	"github.com/SiriusScan/scribe"
	"testing"
	"time"
)

func TestAuditedRuntimeDefaults(t *testing.T) {
	r, err := newRuntime(scribe.Sirius, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.limits.CPU != 10_000_000 || r.limits.Memory != 32<<20 || r.limits.Timeout != 5*time.Second || r.cache.entries != 128 || r.cache.ceiling != 16<<20 {
		t.Fatalf("unexpected defaults: %+v entries=%d bytes=%d", r.limits, r.cache.entries, r.cache.ceiling)
	}
	for _, o := range []Options{{Limits: Limits{Timeout: -1}}, {CacheEntries: -2}, {CacheEntries: 4097}, {Functions: map[string]scribe.Function{"": func(_ context.Context, _ scribe.Target, _ []any) (any, error) { return nil, nil }}}} {
		if _, err := NewNative(o); err == nil {
			t.Errorf("accepted invalid options: %+v", o)
		}
	}
	r, err = newRuntime(scribe.Sirius, Options{CacheEntries: -1})
	if err != nil || r.cache.entries != -1 {
		t.Fatalf("disabled cache: %v", err)
	}
}

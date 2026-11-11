package scribe_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/adapter/pingpp"
	"github.com/SiriusScan/scribe/capability/httpcap"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

func TestPingppSelectionParallelHTTP(t *testing.T) {
	var active, peak atomic.Int32
	ready := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		if n == 2 {
			close(ready)
		}
		select {
		case <-ready:
		case <-r.Context().Done():
			return
		}
		_, _ = w.Write([]byte("fixture"))
	}))
	defer server.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("testdata/sdk/pingpp.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	input := strings.ReplaceAll(string(fixture), "PORT", port)
	client, err := httpcap.New(httpcap.Options{Timeout: time.Second * 3})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	runtime, err := lua54.NewNative(lua54.Options{Functions: map[string]scribe.Function{"http.get": client.Function}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{Concurrency: 4}, runtime)
	if err != nil {
		t.Fatal(err)
	}
	scripts := []scribe.Script{}
	for _, id := range []string{"one", "two"} {
		scripts = append(scripts, scribe.Script{ID: id, Dialect: scribe.Sirius, Source: []byte(`-- scribe: {"services":["http"]}
return {api_version=1,action=function() local response=sirius.call("http.get","/"); return {verdict="not_vulnerable",data=response} end}`)})
	}
	scripts = append(scripts, scribe.Script{ID: "unsupported", Dialect: scribe.Sirius, Source: []byte(`return {api_version=1,action=function() return sirius.call("unsupported.api") end}`)}, scribe.Script{ID: "excluded", Dialect: scribe.Sirius, Source: []byte(`-- scribe: {"services":["ssh"]}
return {api_version=1,action=function() return {verdict="not_vulnerable"} end}`)})
	index, err := scribe.NewIndex(scripts)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	records := map[string]scribe.Result{}
	journalPath := filepath.Join(t.TempDir(), "results.jsonl")
	journal, err := os.Create(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	encoder := json.NewEncoder(journal)
	err = engine.Stream(ctx, index, pingpp.NewReader(strings.NewReader(input)).Next, func(r scribe.Result) error { records[r.ScriptID] = r; return encoder.Encode(r) })
	if err == nil {
		t.Fatal("expected aggregate execution error for unsupported API")
	}
	if len(records) != 4 || peak.Load() < 2 {
		t.Fatalf("records=%v peak=%d", records, peak.Load())
	}
	for _, id := range []string{"one", "two"} {
		if r := records[id]; r.Status != scribe.Completed || r.Verdict != scribe.NotVulnerable {
			t.Fatalf("%s: %+v", id, r)
		}
	}
	if r := records["unsupported"]; r.Status != scribe.Failed || r.Verdict != scribe.Unknown {
		t.Fatalf("unsupported became conclusive: %+v", r)
	}
	if r := records["excluded"]; r.Status != scribe.Skipped || r.Verdict != scribe.Unknown || r.Output.SkipReason == "" {
		t.Fatalf("skip became conclusive: %+v", r)
	}
	if err := journal.Sync(); err != nil {
		t.Fatal(err)
	}
	persistenceRoundTrip(t, journalPath, records)
}

// persistenceRoundTrip requires complete records, including inconclusive results.
func persistenceRoundTrip(t *testing.T, path string, expected map[string]scribe.Result) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	count := 0
	for {
		var r scribe.Result
		err := decoder.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		original, ok := expected[r.ScriptID]
		a, marshalErr := json.Marshal(original)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		var normalized scribe.Result
		if err := json.Unmarshal(a, &normalized); err != nil {
			t.Fatal(err)
		}
		if !ok || !reflect.DeepEqual(r, normalized) {
			t.Fatalf("persisted record differs: %+v", r)
		}
		delete(expected, r.ScriptID)
		count++
	}
	if len(expected) != 0 || count == 0 {
		t.Fatalf("incomplete journal: %d missing", len(expected))
	}
}

package lua54

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/adapter/pingpp"
	"github.com/SiriusScan/scribe/report"
)

// Local consumer storage evidence, independent of Sirius/vGPT storage.
func TestMarkerCorpusPingppPersistence(t *testing.T) {
	wire, err := os.Open("../../adapter/pingpp/testdata/scan.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer wire.Close()
	reader := pingpp.NewReader(wire)
	target, ok, err := reader.Next(context.Background())
	if err != nil || !ok {
		t.Fatalf("target: %v %v", ok, err)
	}
	if _, ok, err := reader.Next(context.Background()); ok || err != nil {
		t.Fatalf("wire EOF: %v %v", ok, err)
	}
	for _, source := range []string{
		"-- scribe: {\"match\":{\"products\":[\"nginx\"]}}\nreturn {api_version=1,action=function() return {verdict='not_vulnerable'} end}",
		"-- scribe: {\"match\":{\"products\":[\"Other\"]}}\nreturn {api_version=1,action=function() return {verdict='not_vulnerable'} end}",
		"-- scribe: {\"match\":{\"products\":[\"nginx\"]}}\nreturn {api_version=1,action=function() error('fixture failure') end}",
	} {
		rt, err := NewNative(Options{})
		if err != nil {
			t.Fatal(err)
		}
		engine, err := scribe.New(scribe.Options{StrictIdentification: true}, rt)
		if err != nil {
			t.Fatal(err)
		}
		idx, err := scribe.NewIndex([]scribe.Script{{ID: "persist", Dialect: scribe.Sirius, Source: []byte(source)}})
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.CreateTemp(t.TempDir(), "reports")
		if err != nil {
			t.Fatal(err)
		}
		var expected []report.Envelope
		err = engine.RunSelected(context.Background(), idx, []scribe.Target{target}, func(r scribe.Result) error {
			e := report.Map(r)
			expected = append(expected, e)
			return json.NewEncoder(f).Encode(e)
		})
		if (err != nil) != (len(expected) == 1 && expected[0].Evidence.Status == scribe.Failed) {
			t.Fatalf("execution error: %v", err)
		}
		if err = f.Sync(); err != nil {
			t.Fatal(err)
		}
		name := f.Name()
		if err = f.Close(); err != nil {
			t.Fatal(err)
		}
		f, err = os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		var actual []report.Envelope
		dec := json.NewDecoder(f)
		for {
			var e report.Envelope
			err = dec.Decode(&e)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			actual = append(actual, e)
		}
		f.Close()
		// JSON normalizes interface values; compare canonical wire representations.
		a, _ := json.Marshal(actual)
		b, _ := json.Marshal(expected)
		if !reflect.DeepEqual(a, b) || len(actual) != 1 {
			t.Fatalf("round trip: %s != %s", a, b)
		}
		e := actual[0]
		if e.Source.Config["script_sha256"] == "" || e.Evidence.Target.Product != "nginx" {
			t.Fatalf("lost evidence: %+v", e)
		}
		if e.Evidence.Status != scribe.Completed && (e.Assessment != "inconclusive" || e.Verdict != scribe.Unknown) {
			t.Fatalf("false clean: %+v", e)
		}
	}
}

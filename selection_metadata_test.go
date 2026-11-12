package scribe

import (
	"strings"
	"testing"
)

func TestMetadataRequiresCompleteSingleJSONValue(t *testing.T) {
	for _, suffix := range []string{" {}", " null", " garbage", " ]"} {
		_, err := NewIndex([]Script{{ID: "bad", Dialect: Sirius, Source: []byte("-- scribe: {\"match\":{\"products\":[\"nginx\"]}}" + suffix + "\nreturn {}")}})
		if err == nil {
			t.Fatalf("accepted trailing metadata %q", suffix)
		}
	}
	for _, ending := range []string{"", "\n", "\r\n"} {
		source := strings.Repeat("-- ordinary source line\n", 10000) + "-- scribe: {\"match\":{\"products\":[\"nginx\"]}}  " + ending
		idx, err := NewIndex([]Script{{ID: "valid", Dialect: Sirius, Source: []byte(source)}})
		if err != nil {
			t.Fatal(err)
		}
		if !idx.Matches(Target{Product: "nginx"}) || idx.Matches(Target{Product: "apache"}) {
			t.Fatal("metadata selection changed")
		}
	}
}

func BenchmarkIndexLargeSource(b *testing.B) {
	source := []byte("-- scribe: {\"match\":{\"products\":[\"nginx\"]}}\n" + strings.Repeat("-- ordinary source line\n", 10000))
	scripts := []Script{{ID: "large", Dialect: Sirius, Source: source}}
	b.ReportAllocs()
	b.SetBytes(int64(len(source)))
	for b.Loop() {
		idx, err := NewIndex(scripts)
		if err != nil || !idx.Matches(Target{Product: "nginx"}) {
			b.Fatal(err)
		}
	}
}

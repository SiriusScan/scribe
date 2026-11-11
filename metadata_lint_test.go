package scribe

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Legacy fixtures intentionally exercise compatibility. Report them without
// changing their semantics; malformed metadata is always a failure.
func TestCorpusMetadataLint(t *testing.T) {
	err := filepath.WalkDir("testdata", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".lua") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		index, err := NewIndex([]Script{{ID: path, Dialect: Sirius, Source: source}})
		if err != nil {
			t.Error(err)
			return nil
		}
		if index.entries[0].hints.Match == nil {
			t.Logf("legacy script lacks match block: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

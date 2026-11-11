package scribe

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Pin root exported symbol names; signatures require separate compatibility review.
func TestExportedAPI(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var symbols []string
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.TypeSpec:
				if ast.IsExported(d.Name.Name) {
					symbols = append(symbols, "type "+d.Name.Name)
				}
			case *ast.FuncDecl:
				if ast.IsExported(d.Name.Name) {
					prefix := "func "
					if d.Recv != nil {
						prefix = "method "
					}
					symbols = append(symbols, prefix+d.Name.Name)
				}
			case *ast.ValueSpec:
				for _, name := range d.Names {
					if ast.IsExported(name.Name) {
						symbols = append(symbols, "value "+name.Name)
					}
				}
			}
			return true
		})
	}
	sort.Strings(symbols)
	got := strings.Join(symbols, "\n") + "\n"
	if os.Getenv("SCRIBE_UPDATE_API") == "1" {
		if err := os.WriteFile("testdata/api-v1.txt", []byte(got), 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile("testdata/api-v1.txt")
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatal("exported symbol inventory changed; review v1 compatibility before updating golden")
	}
}

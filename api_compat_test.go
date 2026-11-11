package scribe

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
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

// TestPublicSignatures pins declarations, fields, tags, methods and constants in
// every importable first-party package. Comments are deliberately excluded.
func TestPublicSignatures(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{if ne .Name \"main\"}}{{.Dir}}{{end}}", "./...").Output()
	if err != nil {
		t.Fatal(err)
	}
	var entries []string
	for _, dir := range strings.Fields(string(out)) {
		if strings.Contains(dir, "/internal/") {
			continue
		}
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			fs := token.NewFileSet()
			f, err := parser.ParseFile(fs, path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.FileExports(f)
			for _, d := range f.Decls {
				if fn, ok := d.(*ast.FuncDecl); ok {
					fn.Body = nil
				}
				if g, ok := d.(*ast.GenDecl); ok && g.Tok == token.IMPORT {
					continue
				}
				var b bytes.Buffer
				if err := format.Node(&b, fs, d); err != nil {
					t.Fatal(err)
				}
				wd, _ := os.Getwd()
				pkg, _ := filepath.Rel(wd, dir)
				entries = append(entries, pkg+": "+b.String())
			}
		}
	}
	sort.Strings(entries)
	got := strings.Join(entries, "\n\n") + "\n"
	const path = "testdata/api-signatures-v1.txt"
	if os.Getenv("SCRIBE_UPDATE_API") == "1" {
		if err := os.WriteFile(path, []byte(got), 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatal("public declarations changed; review compatibility before updating golden")
	}
}

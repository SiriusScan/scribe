package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestVGPTCorpus(t *testing.T) {
	paths, err := filepath.Glob("../../testdata/vgpt/*.lua")
	if err != nil || len(paths) == 0 {
		t.Fatalf("fixtures: %v", err)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			source, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, version := range []string{"2.4.49", "2.4.51"} {
				t.Run(version, func(t *testing.T) {
					for _, bodyOnly := range []bool{false, true} {
						t.Run(fmt.Sprintf("body=%v", bodyOnly), func(t *testing.T) {
							server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
								// Recorded results expose GET /, status 200 and Apache/2.4.49 (Unix).
								// Traversal responses are modeled too, though these scripts only use banners.
								banner := "Apache/" + version + " (Unix)"
								if !bodyOnly {
									w.Header().Set("Server", banner)
								}
								if r.URL.Path != "/" {
									if version == "2.4.49" {
										fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
									} else {
										http.Error(w, "Forbidden", 403)
									}
									return
								}
								fmt.Fprint(w, "<html>"+banner+"</html>")
							}))
							defer server.Close()
							host, port, err := net.SplitHostPort(server.Listener.Addr().String())
							if err != nil {
								t.Fatal(err)
							}
							args := []string{"--dialect", "sirius", "--host", host, "--port", port, "--service", "http"}
							for _, transport := range []string{"cli", "http"} {
								for _, check := range []bool{true, false} {
									callArgs := append([]string{}, args...)
									if check {
										callArgs = append(callArgs, "--check")
									}
									var output []byte
									if transport == "cli" {
										callArgs = append(callArgs, "--script", path)
										var out, diag bytes.Buffer
										if code := run(context.Background(), callArgs, &out, &diag); code != 0 {
											t.Fatalf("%s check=%v: %s %s", transport, check, out.String(), diag.String())
										}
										output = out.Bytes()
									} else {
										body, err := json.Marshal(map[string]any{"args": callArgs, "scripts": []inlineScript{{ID: filepath.Base(path), Source: string(source)}}})
										if err != nil {
											t.Fatal(err)
										}
										rec := httptest.NewRecorder()
										runHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/run", bytes.NewReader(body)))
										if rec.Code != 200 {
											t.Fatalf("HTTP %d: %s", rec.Code, rec.Body.String())
										}
										output = rec.Body.Bytes()
									}
									var result struct {
										Status  string
										Verdict string
										Error   string
									}
									decoder := json.NewDecoder(bytes.NewReader(output))
									if err := decoder.Decode(&result); err != nil {
										t.Fatalf("%v: %s", err, output)
									}
									if err := decoder.Decode(new(any)); err != io.EOF {
										t.Fatalf("extra or incomplete stream: %v", err)
									}
									wantStatus, wantVerdict := "completed", "not_vulnerable"
									if version == "2.4.49" {
										wantVerdict = "vulnerable"
									}
									if check {
										wantStatus = "checked"
										wantVerdict = ""
									}
									if result.Status != wantStatus || result.Verdict != wantVerdict || result.Error != "" {
										t.Fatalf("%s check=%v: %s", transport, check, output)
									}
								}
							}
						})
					}
				})
			}
		})
	}
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
)

func TestModulePacingTransports(t *testing.T) {
	path := scriptFile(t, "return {api_version=1,action=function() return {data='paced'} end}")
	for _, transport := range []string{"cli", "http"} {
		for _, interval := range []string{"80ms", "-1ms"} {
			t.Run(transport+"/"+interval, func(t *testing.T) {
				args := []string{"--dialect", "sirius", "--script", path, "--script", path, "--host", "localhost", "--concurrency", "2", "--module-concurrency", "1", "--module-interval", interval}
				var out, diag bytes.Buffer
				start := time.Now()
				code := 0
				if transport == "cli" {
					code = run(context.Background(), args, &out, &diag)
				} else {
					body, _ := json.Marshal(map[string]any{"args": args})
					rec := httptest.NewRecorder()
					runHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/run", bytes.NewReader(body)))
					out.Write(rec.Body.Bytes())
					if rec.Code != 200 {
						code = 1
					}
				}
				if interval == "-1ms" {
					if code == 0 {
						t.Fatal("negative interval accepted")
					}
					return
				}
				if code != 0 {
					t.Fatalf("code=%d output=%s diagnostic=%s", code, &out, &diag)
				}
				if time.Since(start) < 80*time.Millisecond {
					t.Fatal("module pacing bypassed")
				}
				dec := json.NewDecoder(&out)
				for i := 0; i < 2; i++ {
					var r scribe.Result
					if err := dec.Decode(&r); err != nil {
						t.Fatal(err)
					}
					if r.Status != scribe.Completed || r.Output.Data != "paced" {
						t.Fatalf("%+v", r)
					}
				}
				var extra any
				if err := dec.Decode(&extra); err != io.EOF {
					t.Fatalf("incomplete or excess stream: %v", err)
				}
			})
		}
	}
}

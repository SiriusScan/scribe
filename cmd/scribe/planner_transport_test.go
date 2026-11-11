package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/SiriusScan/scribe"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestPlannerTransports(t *testing.T) {
	for _, mode := range []string{"http", "tls", "redirect", "banner", "skip"} {
		t.Run(mode, func(t *testing.T) {
			var addr string
			if mode == "banner" {
				l, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer l.Close()
				go func() {
					for {
						c, e := l.Accept()
						if e != nil {
							return
						}
						io.WriteString(c, "SSH-2.0-OpenSSH_9.3\r\n")
						c.Close()
					}
				}()
				addr = l.Addr().String()
			} else {
				h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "redirect" && r.URL.Path == "/" {
						http.Redirect(w, r, "/final", 302)
						return
					}
					w.Header().Set("Server", "nginx/1.2")
				})
				var s *httptest.Server
				if mode == "tls" {
					s = httptest.NewTLSServer(h)
				} else {
					s = httptest.NewServer(h)
				}
				defer s.Close()
				addr = s.Listener.Addr().String()
			}
			host, port, _ := net.SplitHostPort(addr)
			product := "nginx"
			if mode == "banner" {
				product = "OpenSSH"
			}
			if mode == "skip" {
				product = "impossible"
			}
			source := "-- scribe: {\"match\":{\"products\":[\"" + product + "\"],\"on_unknown\":\"probe\"}}\nreturn {api_version=1,action=function() return {verdict='unknown',data='executed'} end}"
			path := scriptFile(t, source)
			args := []string{"--dialect", "sirius", "--script", path, "--host", host, "--port", port}
			for _, transport := range []string{"cli", "http"} {
				t.Run(transport, func(t *testing.T) {
					var out, diag bytes.Buffer
					if transport == "cli" {
						if code := run(context.Background(), args, &out, &diag); code != 0 {
							t.Fatalf("%d %s", code, diag.String())
						}
					} else {
						body, _ := json.Marshal(map[string]any{"args": args})
						rec := httptest.NewRecorder()
						runHandler().ServeHTTP(rec, httptest.NewRequest("POST", "/run", bytes.NewReader(body)))
						if rec.Code != 200 {
							t.Fatal(rec.Code, rec.Body.String())
						}
						out.Write(rec.Body.Bytes())
					}
					var r scribe.Result
					dec := json.NewDecoder(&out)
					if err := dec.Decode(&r); err != nil {
						t.Fatal(err)
					}
					var extra any
					if err := dec.Decode(&extra); err != io.EOF {
						t.Fatalf("incomplete or extra stream: %v", err)
					}
					n, _ := strconv.Atoi(port)
					if r.Target.Port != uint16(n) {
						t.Fatal(r)
					}
					if mode == "skip" {
						if r.Status != scribe.Skipped || r.Output.SkipReason == "" {
							t.Fatal(r)
						}
						return
					}
					if r.Status != scribe.Completed || r.Verdict != scribe.Unknown || r.Target.Product != product || len(r.Target.CPE) == 0 || r.Target.Confidence == 0 {
						t.Fatalf("%+v", r)
					}
					if mode == "tls" && (!r.Target.TLS || r.Target.TLSVersion == "" || r.Target.CertSubject == "") {
						t.Fatal(r.Target)
					}
					if mode == "banner" && r.Target.Banner == "" {
						t.Fatal(r.Target)
					}
				})
			}
		})
	}
}

package lua54

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/capability/httpcap"
	"github.com/SiriusScan/scribe/capability/tcpcap"
)

// The pinned original corpus also runs through real bounded transports.
// TLS uses an untrusted local certificate and must fail conservatively.
func TestMarkerCorpusSockets(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "tls"} {
		for _, marker := range []string{"vulnerable", "clean", "unrecognized"} {
			t.Run(protocol+"/"+marker, func(t *testing.T) {
				var addr net.Addr
				var fn scribe.Function
				client, err := httpcap.New(httpcap.Options{})
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if protocol == "http" {
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Sirius-Fixture", marker) }))
					defer server.Close()
					addr = server.Listener.Addr()
					fn = client.Function
				} else if protocol == "tls" {
					server := httptest.NewTLSServer(nil)
					defer server.Close()
					addr = server.Listener.Addr()
					fn = tcpcap.Function
				} else {
					listener, err := net.Listen("tcp", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					addr = listener.Addr()
					fn = tcpcap.Function
					done := make(chan struct{})
					go func() {
						defer close(done)
						c, e := listener.Accept()
						if e != nil {
							return
						}
						defer c.Close()
						c.SetDeadline(time.Now().Add(time.Second))
						b := make([]byte, 8)
						if _, e = io.ReadFull(c, b); e == nil {
							io.WriteString(c, marker)
						}
					}()
					defer func() { listener.Close(); <-done }()
				}
				source, err := os.ReadFile("../../testdata/sirius/" + protocol + "-marker.lua")
				if err != nil {
					t.Fatal(err)
				}
				name := "tcp.exchange"
				if protocol == "http" {
					name = "http.get"
				}
				rt, err := NewNative(Options{Functions: map[string]scribe.Function{name: fn}})
				if err != nil {
					t.Fatal(err)
				}
				engine, err := scribe.New(scribe.Options{StrictIdentification: true}, rt)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				count := 0
				err = engine.Run(ctx, []scribe.Task{{Script: scribe.Script{ID: protocol + "-marker", Dialect: scribe.Sirius, Source: source}, Target: scribe.Target{Host: "localhost", IP: "127.0.0.1", Port: uint16(addr.(*net.TCPAddr).Port), Protocol: "tcp", Service: "http", Product: "Scribe fixture", TLS: protocol == "tls"}}}, func(r scribe.Result) error {
					count++
					want := scribe.Unknown
					if marker == "vulnerable" {
						want = scribe.Vulnerable
					}
					if marker == "clean" {
						want = scribe.NotVulnerable
					}
					if protocol == "tls" {
						if r.Status != scribe.Failed || r.Verdict != scribe.Unknown {
							t.Fatalf("untrusted TLS: %+v", r)
						}
					} else if r.Status != scribe.Completed || r.Verdict != want {
						t.Fatalf("result: %+v", r)
					}
					return nil
				})
				if (err != nil && protocol != "tls") || count != 1 {
					t.Fatalf("records=%d err=%v", count, err)
				}
			})
		}
	}
}

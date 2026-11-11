package tcpcap_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/capability/tcpcap"
	"github.com/SiriusScan/scribe/runtime/lua54"
)

// Exercise the actual Lua bridge: transport failures cannot produce clean output.
func TestLuaTransportEdges(t *testing.T) {
	for _, mode := range []string{"partial", "timeout", "cancel", "tls"} {
		t.Run(mode, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			release := make(chan struct{})
			defer close(release)
			accepted := make(chan struct{})
			go func() {
				c, e := listener.Accept()
				close(accepted)
				if e != nil {
					return
				}
				defer c.Close()
				if mode == "partial" {
					c.Write([]byte("part"))
				}
				if mode == "tls" {
					c.Write([]byte("invalid TLS\r\n"))
					return
				}
				<-release
			}()
			rt, err := lua54.NewNative(lua54.Options{Functions: map[string]scribe.Function{"tcp.exchange": tcpcap.Function}})
			if err != nil {
				t.Fatal(err)
			}
			engine, err := scribe.New(scribe.Options{}, rt)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if mode == "cancel" {
				go func() { <-accepted; cancel() }()
			}
			task := scribe.Task{Target: scribe.Target{Host: "localhost", IP: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Protocol: "tcp", TLS: mode == "tls"}, Script: scribe.Script{ID: "edge", Dialect: scribe.Sirius, Source: []byte(`return {api_version=1, action=function() local r=sirius.call("tcp.exchange"); return {verdict="unknown", data=r} end}`)}}
			count := 0
			_ = engine.Run(ctx, []scribe.Task{task}, func(r scribe.Result) error {
				count++
				if mode == "partial" {
					if r.Status != scribe.Completed || r.Output.Verdict != scribe.Unknown {
						t.Fatalf("partial result: %+v", r)
					}
				} else if r.Status != scribe.Failed && r.Status != scribe.Cancelled {
					t.Fatalf("transport failure status: %+v", r)
				}
				if r.Output.Verdict == scribe.NotVulnerable {
					t.Fatal("false clean")
				}
				return nil
			})
			if count != 1 {
				t.Fatalf("terminal records: %d", count)
			}
		})
	}
}

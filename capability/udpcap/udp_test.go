package udpcap

import (
	"context"
	"fmt"
	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/runtime/lua54"
	"net"
	"strings"
	"testing"
	"time"
)

func TestExchange(t *testing.T) {
	for _, reply := range []string{"", "reply\x00bytes"} {
		t.Run(reply, func(t *testing.T) {
			c, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			done := make(chan string, 1)
			go func() {
				b := make([]byte, 32)
				n, a, e := c.ReadFrom(b)
				if e != nil {
					done <- e.Error()
					return
				}
				done <- string(b[:n])
				c.WriteTo([]byte(reply), a)
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			target := scribe.Target{Host: "localhost", IP: "127.0.0.1", Protocol: "udp", Port: uint16(c.LocalAddr().(*net.UDPAddr).Port)}
			got, err := Function(ctx, target, []any{"request"})
			if err != nil {
				t.Fatal(err)
			}
			if got.(map[string]any)["data"] != reply {
				t.Fatalf("reply: %#v", got)
			}
			if request := <-done; request != "request" {
				t.Fatal(request)
			}
		})
	}
}

func TestValidationAndCancellation(t *testing.T) {
	target := scribe.Target{Host: "127.0.0.1", Protocol: "udp", Port: 9}
	for _, args := range [][]any{nil, {1}, {"a", "b"}} {
		if got, err := Function(context.Background(), target, args); err == nil || got != nil {
			t.Fatalf("%#v %v", got, err)
		}
	}
	ctx := context.Background()
	if got, err := Function(ctx, target, []any{"x"}); err == nil || got != nil {
		t.Fatalf("%#v %v", got, err)
	}
	target.Protocol = "tcp"
	if _, err := Function(context.Background(), target, []any{"x"}); err == nil {
		t.Fatal("accepted TCP")
	}
}

func TestLuaInvalidPayload(t *testing.T) {
	rt, err := lua54.NewNative(lua54.Options{Functions: map[string]scribe.Function{"udp.exchange": Function}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := scribe.New(scribe.Options{}, rt)
	if err != nil {
		t.Fatal(err)
	}
	task := scribe.Task{Target: scribe.Target{Host: "127.0.0.1", Port: 9, Protocol: "udp"}, Script: scribe.Script{ID: "udp", Dialect: scribe.Sirius, Source: []byte(`return {api_version=1, action=function() sirius.call("udp.exchange", 42); return {verdict="not_vulnerable"} end}`)}}
	ctx := context.Background()
	count := 0
	_ = engine.Run(ctx, []scribe.Task{task}, func(r scribe.Result) error {
		count++
		if r.Status != scribe.Failed || r.Output.Verdict == scribe.NotVulnerable {
			t.Fatalf("%+v", r)
		}
		return nil
	})
	if count != 1 {
		t.Fatal(count)
	}
}

func TestSession(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		var peer string
		for _, want := range []string{"first", "", "last"} {
			b := make([]byte, 32)
			n, a, e := c.ReadFrom(b)
			if e != nil {
				done <- e
				return
			}
			if string(b[:n]) != want || (peer != "" && peer != a.String()) {
				done <- fmt.Errorf("request or peer mismatch")
				return
			}
			peer = a.String()
			if _, e = c.WriteTo([]byte(want), a); e != nil {
				done <- e
				return
			}
		}
		done <- nil
	}()
	target := scribe.Target{Host: "127.0.0.1", Protocol: "udp", Port: uint16(c.LocalAddr().(*net.UDPAddr).Port)}
	got, err := Function(context.Background(), target, []any{[]any{"first", "", "last"}})
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"first", "", "last"} {
		if got.([]any)[i].(map[string]any)["data"] != want {
			t.Fatal(got)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// A later timeout must discard the first successful reply.
	go func() {
		b := make([]byte, 32)
		_, a, e := c.ReadFrom(b)
		if e == nil {
			c.WriteTo([]byte("ok"), a)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if got, err := Function(ctx, target, []any{[]any{"one", "two"}}); err == nil || got != nil {
		t.Fatalf("partial success: %v %v", got, err)
	}
}

func TestSessionValidation(t *testing.T) {
	for _, v := range []any{[]any{}, make([]any, 17), []any{"valid", 42}, []any{strings.Repeat("x", 65508)}} {
		if _, _, err := parsePayloads([]any{v}); err == nil {
			t.Fatalf("accepted %v", v)
		}
	}
}

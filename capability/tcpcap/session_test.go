package tcpcap

import (
	"context"
	"github.com/SiriusScan/scribe"
	"io"
	"net"
	"testing"
	"time"
)

func TestSession(t *testing.T) {
	for _, truncated := range []bool{false, true} {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			c, e := l.Accept()
			if e != nil {
				done <- e
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(time.Second))
			_, e = io.WriteString(c, "hello\r\n")
			if e == nil {
				b := make([]byte, 4)
				_, e = io.ReadFull(c, b)
				if e == nil && string(b) != "PING" {
					e = io.ErrUnexpectedEOF
				}
			}
			if e == nil {
				reply := "PONG"
				if truncated {
					reply = "PO"
				}
				_, e = io.WriteString(c, reply)
			}
			done <- e
		}()
		target := scribe.Target{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port), Protocol: "tcp"}
		v, e := Function(context.Background(), target, []any{[]any{[]any{"", "\r\n"}, []any{"PING", int64(0)}, []any{"", int64(4)}}})
		if truncated {
			if e == nil || v != nil {
				t.Fatalf("partial session: %v %v", v, e)
			}
		} else {
			if e != nil {
				t.Fatal(e)
			}
			replies := v.(map[string]any)["replies"].([]any)
			if len(replies) != 3 || replies[0].(map[string]any)["data"] != "hello\r\n" || replies[1].(map[string]any)["data"] != "" || replies[2].(map[string]any)["data"] != "PONG" {
				t.Fatal(v)
			}
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		l.Close()
	}
}

func TestSessionValidation(t *testing.T) {
	target := scribe.Target{Host: "127.0.0.1", Port: 1, Protocol: "tcp"}
	for _, steps := range [][]any{nil, make([]any, 17), {true}, {[]any{"", int64(-2)}}, {[]any{"ok"}, []any{false}}} {
		if v, e := Function(context.Background(), target, []any{steps}); e == nil || v != nil {
			t.Fatalf("accepted invalid session: %v %v", v, e)
		}
	}
}

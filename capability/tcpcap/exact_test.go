package tcpcap

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
)

func TestExactRead(t *testing.T) {
	for _, reply := range []string{"abcd", "ab"} {
		t.Run(reply, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := l.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				for _, b := range []byte(reply) {
					c.Write([]byte{b})
					time.Sleep(time.Millisecond)
				}
			}()
			target := scribe.Target{Host: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port), Protocol: "tcp"}
			v, err := Function(context.Background(), target, []any{"", int64(4)})
			if reply == "abcd" {
				if err != nil {
					t.Fatal(err)
				}
				if v.(map[string]any)["data"] != reply {
					t.Fatal(v)
				}
			} else if err == nil || v != nil {
				t.Fatalf("partial reply accepted: %v %v", v, err)
			}
			<-done
			for _, n := range []any{int64(0), int64(65537), 2.5, true} {
				if _, err := Function(context.Background(), target, []any{"", n}); err == nil {
					t.Fatalf("accepted %v", n)
				}
			}
		})
	}
}

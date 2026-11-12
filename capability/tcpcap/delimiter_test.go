package tcpcap

import (
	"context"
	"github.com/SiriusScan/scribe"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDelimiterExchange(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		fail        bool
	}{
		{"fragmented", "220 ready\r\n", false},
		{"truncated", "220 ready\r", true},
		{"bounded", strings.Repeat("x", 65536), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, e := l.Accept()
				if e != nil {
					return
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				for _, part := range []string{tc.reply[:1], tc.reply[1:]} {
					if _, e = c.Write([]byte(part)); e != nil {
						return
					}
				}
			}()
			target := scribe.Target{Host: "localhost", IP: "127.0.0.1", Port: uint16(l.Addr().(*net.TCPAddr).Port), Protocol: "tcp"}
			v, e := Function(context.Background(), target, []any{"", "\r\n"})
			if tc.fail {
				if e == nil || v != nil {
					t.Fatalf("expected failure, got %v %v", v, e)
				}
			} else if e != nil || v.(map[string]any)["data"] != tc.reply {
				t.Fatalf("got %v %v", v, e)
			}
			<-done
		})
	}
}

func TestDelimiterValidation(t *testing.T) {
	target := scribe.Target{Host: "localhost", Port: 1, Protocol: "tcp"}
	for _, d := range []string{"", strings.Repeat("x", 257)} {
		if v, e := Function(context.Background(), target, []any{"", d}); e == nil || v != nil {
			t.Fatalf("accepted delimiter length %d", len(d))
		}
	}
}

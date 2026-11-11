package tcpcap

import (
	"context"
	"github.com/SiriusScan/scribe"
	"net"
	"net/http/httptest"
	"testing"
)

func TestExchange(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 4)
		n, e := c.Read(b)
		if e == nil {
			c.Write(b[:n])
		}
	}()
	target := scribe.Target{Host: "localhost", IP: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Protocol: "tcp"}
	value, err := Function(context.Background(), target, []any{"ping"})
	if err != nil {
		t.Fatal(err)
	}
	if value.(map[string]any)["data"] != "ping" {
		t.Fatal(value)
	}
	<-done
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Function(ctx, target, nil); err == nil {
		t.Fatal("cancellation ignored")
	}
	target.Protocol = "udp"
	if _, err := Function(context.Background(), target, nil); err == nil {
		t.Fatal("UDP accepted")
	}
}

func TestTLSVerificationFailure(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	addr := server.Listener.Addr().(*net.TCPAddr)
	_, err := Function(context.Background(), scribe.Target{Host: "localhost", IP: "127.0.0.1", Port: uint16(addr.Port), Protocol: "tcp", TLS: true}, nil)
	if err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}

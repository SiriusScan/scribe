package scribe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbeFragmentedBanner(t *testing.T) {
	for _, stalled := range []bool{false, true} {
		t.Run(map[bool]string{false: "fragmented", true: "stalled"}[stalled], func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c, err := listener.Accept()
				if err != nil {
					return
				}
				defer c.Close()
				c.Write([]byte("SSH-"))
				time.Sleep(10 * time.Millisecond)
				if !stalled {
					c.Write([]byte("2.0-OpenSSH_9.6\r\n"))
				}
				time.Sleep(60 * time.Millisecond)
			}()
			start := time.Now()
			facts := probe(context.Background(), Target{Host: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Protocol: "tcp"})
			if time.Since(start) > time.Second {
				t.Fatal("probe exceeded bounded wait")
			}
			if !stalled && (facts.Product != "OpenSSH" || facts.Version != "9.6") {
				t.Fatalf("fragmented identity lost: %+v", facts)
			}
			if stalled && facts.Product != "" {
				t.Fatalf("partial banner identified: %+v", facts)
			}
			<-done
		})
	}
}

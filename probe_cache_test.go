package scribe

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestProbeCacheServiceEligibility(t *testing.T) {
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan error, 1)
	go func() {
		b := make([]byte, 8192)
		n, addr, err := c.ReadFrom(b)
		if err == nil {
			b[2] = 0x81
			_, err = c.WriteTo(b[:n], addr)
		}
		done <- err
	}()
	target := Target{Host: "127.0.0.1", Port: uint16(c.LocalAddr().(*net.UDPAddr).Port), Protocol: "udp"}
	cache := make(probeCache)
	if got := cache.enrich(context.Background(), target, 4); got.Service != "" {
		t.Fatal(got)
	}
	target.Service = "dns"
	got := cache.enrich(context.Background(), target, 4)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(cache) != 2 {
		t.Fatalf("service-specific probe was suppressed: %d entries", len(cache))
	}
	if got.Service != "dns" || got.Product != "" {
		t.Fatal(got)
	}
	// A repeated task must reuse its service-specific observations.
	cache.enrich(context.Background(), target, 4)
	if len(cache) != 2 {
		t.Fatal("cache did not reuse observations")
	}
}

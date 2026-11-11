package scribe

import (
	"context"
	"net"
	"testing"
)

func TestUDPProbe(t *testing.T) {
	for _, service := range []string{"dns", "ntp"} {
		for _, valid := range []bool{false, true} {
			t.Run(service+map[bool]string{false: "/invalid", true: "/valid"}[valid], func(t *testing.T) {
				c, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					b := make([]byte, 8192)
					n, a, e := c.ReadFrom(b)
					if e != nil {
						return
					}
					b = b[:n]
					if service == "dns" {
						b[2] = 0x81
					} else {
						copy(b[24:32], b[40:48])
						b[0] = 0x24
						b[1] = 1
					}
					if !valid {
						b[0] ^= 0xff
					}
					c.WriteTo(b, a)
				}()
				f := probe(context.Background(), Target{Host: "127.0.0.1", Port: uint16(c.LocalAddr().(*net.UDPAddr).Port), Protocol: "udp", Service: service})
				<-done
				if (f.Service == service) != valid {
					t.Fatalf("facts: %+v", f)
				}
				if f.Product != "" {
					t.Fatal("invented product")
				}
			})
		}
	}
}

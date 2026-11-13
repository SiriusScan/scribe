package scribe

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSSDPProbe(t *testing.T) {
	const reply = "HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\nUSN: uuid:original-fixture::upnp:rootdevice\r\nSERVER: misleading-product/1\r\n\r\n"
	for _, wire := range []string{reply, strings.Replace(reply, "200 OK", "404 Missing", 1), strings.ReplaceAll(reply, "upnp:rootdevice", "ssdp:all"), strings.TrimSuffix(reply, "\r\n"), strings.Replace(reply, "uuid:original-fixture", "uuid:", 1), strings.Replace(reply, "SERVER:", "ST: upnp:rootdevice\r\nSERVER:", 1)} {
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		done := make(chan string, 1)
		go func() {
			b := make([]byte, 8192)
			n, a, e := c.ReadFrom(b)
			if e != nil {
				done <- ""
				return
			}
			done <- string(b[:n])
			c.WriteTo([]byte(wire), a)
		}()
		facts := probe(context.Background(), Target{Host: "127.0.0.1", Port: uint16(c.LocalAddr().(*net.UDPAddr).Port), Protocol: "udp", Service: "ssdp"})
		request := <-done
		c.Close()
		if request != "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n" {
			t.Fatalf("request %q", request)
		}
		if (facts.Service == "ssdp") != (wire == reply) || facts.Product != "" || facts.Version != "" {
			t.Fatalf("reply %q: %+v", wire, facts)
		}
	}
}

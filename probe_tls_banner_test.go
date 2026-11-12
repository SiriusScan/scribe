package scribe

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestProbeTLSBannerRetainsTransportIdentity(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	config := certServer.TLS.Clone()
	certServer.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
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
		c.Write([]byte("SSH-2.0-OpenSSH_9.6\r\n"))
	}()
	host, port, _ := net.SplitHostPort(listener.Addr().String())
	n, _ := strconv.Atoi(port)
	facts := probe(context.Background(), Target{Host: host, Port: uint16(n), Protocol: "tcp", TLS: true})
	<-done
	if !facts.TLS || facts.TLSVersion == "" || facts.CertSubject == "" || facts.Product != "OpenSSH" || facts.Service != "ssh" || facts.Banner == "" {
		t.Fatalf("lost transport or banner facts: %+v", facts)
	}
}

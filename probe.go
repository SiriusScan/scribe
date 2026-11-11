package scribe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/SiriusScan/scribe/fingerprint"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

func mergeProbe(t, f Target) Target {
	if t.Service == "" {
		t.Service = f.Service
	}
	if t.Product == "" {
		t.Product = f.Product
		if t.Version == "" {
			t.Version = f.Version
		}
	}
	if t.Banner == "" {
		t.Banner = f.Banner
	}
	if t.Confidence == 0 {
		t.Confidence = f.Confidence
	}
	if len(t.CPE) == 0 {
		t.CPE = f.CPE
	}
	if t.CertSubject == "" {
		t.CertSubject = f.CertSubject
	}
	if t.ALPN == "" {
		t.ALPN = f.ALPN
	}
	if t.TLSVersion == "" {
		t.TLSVersion = f.TLSVersion
	}
	return t
}

// probe reads a bounded passive TCP banner. It never sends application data.
func probe(ctx context.Context, t Target) Target {
	if t.Protocol != "tcp" || t.Port == 0 {
		return Target{}
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	host := t.Host
	if t.IP != "" {
		host = t.IP
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(t.Port))))
	if err != nil {
		return Target{}
	}
	defer c.Close()
	facts := Target{}
	if t.TLS {
		tc := tls.Client(c, &tls.Config{ServerName: t.Host, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if tc.HandshakeContext(ctx) != nil {
			return facts
		}
		c = tc
		state := tc.ConnectionState()
		facts.ALPN = state.NegotiatedProtocol
		facts.TLSVersion = tls.VersionName(state.Version)
		if len(state.PeerCertificates) > 0 {
			facts.CertSubject = state.PeerCertificates[0].Subject.String()
		}
	}
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	b := make([]byte, 8192)
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	n, _ := c.Read(b)
	c.SetDeadline(deadline)
	if n == 0 {
		if _, err := fmt.Fprintf(c, "HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", t.Host); err != nil {
			return facts
		}
		response, err := http.ReadResponse(bufio.NewReader(io.LimitReader(c, 8192)), nil)
		if err == nil {
			response.Body.Close()
			f := fingerprint.Default().Match("", response.Header)
			facts.Service = "http"
			facts.Product = f.Product
			facts.Version = f.Version
			facts.Confidence = 0.8
		}
		return facts
	}
	f := fingerprint.Default().Match(string(b[:n]), http.Header{})
	return Target{Confidence: 0.8, Banner: string(b[:n]), Service: f.Service, Product: f.Product, Version: f.Version}
}

// probeCache is owned by one producer; failures are cached too.
type probeCache map[string]Target

func (p probeCache) enrich(ctx context.Context, t Target, limit int) Target {
	key := fmt.Sprintf("%s/%s/%d/%s/%t", t.Host, t.IP, t.Port, t.Protocol, t.TLS)
	f, ok := p[key]
	if !ok {
		if len(p) >= limit {
			return t
		}
		f = probe(ctx, t)
		p[key] = f
	}
	return mergeProbe(t, f)
}

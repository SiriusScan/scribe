package scribe

import (
	"context"
	"github.com/SiriusScan/scribe/fingerprint"
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
	return t
}

// probe reads a bounded passive TCP banner. It never sends application data.
func probe(ctx context.Context, t Target) Target {
	if t.Protocol != "tcp" || t.Port == 0 || t.TLS {
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
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	b := make([]byte, 8192)
	n, _ := c.Read(b)
	f := fingerprint.Default().Match(string(b[:n]), http.Header{})
	return Target{Banner: string(b[:n]), Service: f.Service, Product: f.Product, Version: f.Version}
}

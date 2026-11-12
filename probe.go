package scribe

import (
	"bytes"
	"context"
	"crypto/tls"
	"github.com/SiriusScan/scribe/fingerprint"

	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func mergeProbe(t, f Target) Target {
	t.TLS = t.TLS || f.TLS
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
	identityCompatible := (t.Product == "" || f.Product == "" || t.Product == f.Product) &&
		(t.Version == "" || f.Version == "" || t.Version == f.Version)
	if t.Confidence == 0 && identityCompatible {
		t.Confidence = f.Confidence
	}
	if len(t.CPE) == 0 && identityCompatible {
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

// probe performs bounded banner, TLS and HTTP identification without trust validation.
func probe(ctx context.Context, t Target) Target {
	if t.Protocol == "udp" && t.Port != 0 {
		return udpProbe(ctx, t)
	}
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
	if t.TLS || t.Port == 443 || t.Port == 8443 || t.Port == 9443 {
		tc := tls.Client(c, &tls.Config{ServerName: t.Host, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
		if tc.HandshakeContext(ctx) != nil {
			return facts
		}
		c = tc
		facts.TLS = true
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
	n, readErr := c.Read(b)
	// Assemble a fragmented first banner line without enlarging the endpoint budget.
	for n > 0 && n < len(b) && readErr == nil && !bytes.Contains(b[:n], []byte("\n")) {
		var more int
		more, readErr = c.Read(b[n:])
		n += more
		if more == 0 {
			break
		}
	}
	c.SetDeadline(deadline)
	if n == 0 {
		if !t.TLS && !facts.TLS {
			secure := t
			secure.TLS = true
			detected := probe(ctx, secure)
			if detected.TLS {
				return detected
			}
		}
		scheme := "http"
		if facts.TLS {
			scheme = "https"
		}
		u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(int(t.Port))), Path: "/"}
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true, MaxResponseHeaderBytes: 8192}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Host != u.Host {
				return http.ErrUseLastResponse
			}
			return nil
		}}
		req, err := http.NewRequestWithContext(ctx, "HEAD", u.String(), nil)
		if err != nil {
			return facts
		}
		response, err := client.Do(req)
		if err == nil {
			response.Body.Close()
			f := fingerprint.Default().Match("", response.Header)
			facts.Service, facts.Product, facts.Version = "http", f.Product, f.Version
			if f.Product != "" {
				facts.Confidence = 0.8
				facts.CPE = inferredCPE(f.Product, f.Version)
			}
		}
		return facts
	}
	f := fingerprint.Default().Match(string(b[:n]), http.Header{})
	facts.CPE = inferredCPE(f.Product, f.Version)
	if f.Product != "" {
		facts.Confidence = 0.8
	}
	facts.Banner = string(b[:n])
	facts.Service, facts.Product, facts.Version = f.Service, f.Product, f.Version
	return facts
}

// probeCache is owned by one producer; failures are cached too.
type probeCacheKey struct {
	host, ip, protocol, service string
	port                        uint16
	tls                         bool
}

type probeCache map[probeCacheKey]Target

func (p probeCache) enrich(ctx context.Context, t Target, limit int, community ...string) Target {
	key := probeCacheKey{t.Host, t.IP, t.Protocol, t.Service, t.Port, t.TLS}
	f, ok := p[key]
	if !ok {
		if len(p) >= limit {
			return t
		}
		if t.Protocol == "udp" && (t.Port == 161 || t.Service == "snmp") && len(community) > 0 && community[0] != "" {
			f = snmpProbe(ctx, t, community[0])
		} else {
			f = probe(ctx, t)
		}
		p[key] = f
	}
	return mergeProbe(t, f)
}

// Only pinned fingerprint identities have CPE mappings.
func inferredCPE(product, version string) []string {
	prefix := map[string]string{"Cherokee": "cherokee-project:cherokee", "LiteSpeed": "litespeedtech:litespeed_web_server", "H2O": "h2o_project:h2o", "Traefik": "traefik:traefik", "Squid": "squid-cache:squid", "Varnish": "varnish-cache:varnish", "Envoy": "envoyproxy:envoy", "HAProxy": "haproxy:haproxy", "Pure-FTPd": "pureftpd:pure-ftpd", "Sendmail": "sendmail:sendmail", "Caddy": "caddyserver:caddy", "OpenResty": "openresty:openresty", "IIS": "microsoft:internet_information_services", "lighttpd": "lighttpd:lighttpd", "Tomcat": "apache:tomcat", "Jetty": "eclipse:jetty", "Postfix": "postfix:postfix", "Exim": "exim:exim", "vsftpd": "vsftpd:vsftpd", "ProFTPD": "proftpd:proftpd", "MySQL": "oracle:mysql", "MariaDB": "mariadb:mariadb", "Redis": "redis:redis", "Dropbear": "dropbear_ssh_project:dropbear_ssh", "nginx": "nginx:nginx", "Apache": "apache:http_server", "OpenSSH": "openbsd:openssh"}[product]
	if prefix == "" {
		return nil
	}
	if version == "" {
		version = "*"
	}
	for _, r := range version {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == '*') {
			return nil
		}
	}
	return []string{"cpe:/a:" + prefix + ":" + version}
}

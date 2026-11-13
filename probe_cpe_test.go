package scribe

import (
	"net/http"
	"testing"

	"github.com/SiriusScan/scribe/fingerprint"
)

func TestProductCPESelection(t *testing.T) {
	for _, tc := range []struct{ header, banner, product, cpe string }{
		{"lighttpd/1.4.76", "", "lighttpd", "cpe:/a:lighttpd:lighttpd:1.4.76"},
		{"lighttpd", "", "lighttpd", "cpe:/a:lighttpd:lighttpd:*"},
		{"Microsoft-IIS/10.0", "", "IIS", "cpe:/a:microsoft:internet_information_services:10.0"},
		{"Microsoft-IIS", "", "IIS", "cpe:/a:microsoft:internet_information_services:*"},
		{"nginx/1.26.2", "", "nginx", "cpe:/a:nginx:nginx:1.26.2"},
		{"nginx", "", "nginx", "cpe:/a:nginx:nginx:*"},
		{"", "+OK Dovecot 2.3.21 ready.\r\n", "Dovecot", "cpe:/a:dovecot:dovecot:2.3.21"},
		{"", "+OK Dovecot ready.\r\n", "Dovecot", "cpe:/a:dovecot:dovecot:*"},
		{"", "220 FileZilla Server 1.9.4 ready\r\n", "FileZilla", "cpe:/a:filezilla-project:filezilla_server:1.9.4"},
		{"", "220-FileZilla Server", "FileZilla", "cpe:/a:filezilla-project:filezilla_server:*"},
		{"Apache/2.4.62 (Unix)", "", "Apache", "cpe:/a:apache:http_server:2.4.62"},
		{"Apache", "", "Apache", "cpe:/a:apache:http_server:*"},
		{"Varnish/7.6.1", "", "Varnish", "cpe:/a:varnish-cache:varnish:7.6.1"},
		{"Varnish", "", "Varnish", "cpe:/a:varnish-cache:varnish:*"},
		{"Squid/7.6.1", "", "Squid", "cpe:/a:squid-cache:squid:7.6.1"},
		{"LiteSpeed/7.6.1", "", "LiteSpeed", "cpe:/a:litespeedtech:litespeed_web_server:7.6.1"},
		{"Cherokee/7.6.1", "", "Cherokee", "cpe:/a:cherokee-project:cherokee:7.6.1"},
		{"Cherokee", "", "Cherokee", "cpe:/a:cherokee-project:cherokee:*"},
		{"LiteSpeed", "", "LiteSpeed", "cpe:/a:litespeedtech:litespeed_web_server:*"},
		{"H2O/7.6.1", "", "H2O", "cpe:/a:h2o_project:h2o:7.6.1"},
		{"H2O", "", "H2O", "cpe:/a:h2o_project:h2o:*"},
		{"Traefik/7.6.1", "", "Traefik", "cpe:/a:traefik:traefik:7.6.1"},
		{"Squid", "", "Squid", "cpe:/a:squid-cache:squid:*"},
		{"Traefik", "", "Traefik", "cpe:/a:traefik:traefik:*"},
		{"envoy/1.32.3", "", "Envoy", "cpe:/a:envoyproxy:envoy:1.32.3"},
		{"envoy", "", "Envoy", "cpe:/a:envoyproxy:envoy:*"},
		{"HAProxy/3.0.5", "", "HAProxy", "cpe:/a:haproxy:haproxy:3.0.5"},
		{"HAProxy", "", "HAProxy", "cpe:/a:haproxy:haproxy:*"},
		{"Caddy/2.8.4", "", "Caddy", "cpe:/a:caddyserver:caddy:2.8.4"},
		{"openresty/1.27.1.1", "", "OpenResty", "cpe:/a:openresty:openresty:1.27.1.1"},
		{"Caddy", "", "Caddy", "cpe:/a:caddyserver:caddy:*"},
		{"", "220 Pure-FTPd ready", "Pure-FTPd", "cpe:/a:pureftpd:pure-ftpd:*"},
		{"", "220 mail Sendmail 8.17.1 ready", "Sendmail", "cpe:/a:sendmail:sendmail:8.17.1"},
	} {
		t.Run(tc.product+"/"+tc.header, func(t *testing.T) {
			f := fingerprint.Default().Match(tc.banner, http.Header{"Server": {tc.header}})
			observed := Target{Product: f.Product, Version: f.Version, CPE: inferredCPE(f.Product, f.Version)}
			if len(observed.CPE) != 1 || observed.CPE[0] != tc.cpe {
				t.Fatalf("facts: %+v", observed)
			}
			m := Match{Products: []string{tc.product}, CPE: []string{tc.cpe}}
			if ok, id := m.evaluate(observed); !ok || !id {
				t.Fatalf("selection: %v %v", ok, id)
			}
			conflict := mergeProbe(Target{Product: "other"}, observed)
			if len(conflict.CPE) != 0 {
				t.Fatal("conflicting product acquired CPE")
			}
			if reason := m.skipReason(conflict); reason != "declarative match: product identification mismatched" {
				t.Fatal(reason)
			}
			observed.Product = ""
			if reason := m.skipReason(observed); reason != "declarative match: product identification missing" {
				t.Fatal(reason)
			}
			m.Products = nil
			if _, id := m.evaluate(observed); id {
				t.Fatal("CPE established clean gate")
			}
		})
	}
	if got := inferredCPE("Caddy", "2.8:injected"); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestApacheMisleadingIdentity(t *testing.T) {
	for _, header := range []string{"ApacheProxy", "ApacheTomcat/9.0", "Apache/2..4", "Apache/2.4evil", "Apache/", "Apache/2.4:injected"} {
		t.Run(header, func(t *testing.T) {
			f := fingerprint.Default().Match("", http.Header{"Server": {header}})
			observed := Target{Product: f.Product, Version: f.Version, CPE: inferredCPE(f.Product, f.Version)}
			m := Match{Products: []string{"Apache"}}
			if ok, id := m.evaluate(observed); ok || id {
				t.Fatalf("misleading identity accepted: %+v", observed)
			}
			if reason := m.skipReason(observed); reason != "declarative match: product identification missing" {
				t.Fatal(reason)
			}
			if len(observed.CPE) != 0 {
				t.Fatal(observed.CPE)
			}
		})
	}
}

func TestNginxMisleadingIdentity(t *testing.T) {
	for _, header := range []string{"nginxProxy", "nginxPlus/9.0", "nginx/2..4", "nginx/2.4evil", "nginx/", "nginx/2.4:injected"} {
		t.Run(header, func(t *testing.T) {
			f := fingerprint.Default().Match("", http.Header{"Server": {header}})
			observed := Target{Product: f.Product, Version: f.Version, CPE: inferredCPE(f.Product, f.Version)}
			m := Match{Products: []string{"nginx"}}
			if ok, id := m.evaluate(observed); ok || id {
				t.Fatalf("misleading identity accepted: %+v", observed)
			}
			if reason := m.skipReason(observed); reason != "declarative match: product identification missing" {
				t.Fatal(reason)
			}
			if len(observed.CPE) != 0 {
				t.Fatal(observed.CPE)
			}
		})
	}
}

func TestLighttpdMisleadingIdentity(t *testing.T) {
	for _, header := range []string{"lighttpdProxy", "lighttpdTomcat/9.0", "lighttpd/2..4", "lighttpd/2.4evil", "lighttpd/", "lighttpd/2.4:injected"} {
		t.Run(header, func(t *testing.T) {
			f := fingerprint.Default().Match("", http.Header{"Server": {header}})
			observed := Target{Product: f.Product, Version: f.Version, CPE: inferredCPE(f.Product, f.Version)}
			m := Match{Products: []string{"lighttpd"}}
			if ok, id := m.evaluate(observed); ok || id {
				t.Fatalf("misleading identity accepted: %+v", observed)
			}
			if reason := m.skipReason(observed); reason != "declarative match: product identification missing" {
				t.Fatal(reason)
			}
			if len(observed.CPE) != 0 {
				t.Fatal(observed.CPE)
			}
		})
	}
}
func TestIISMisleadingIdentity(t *testing.T) {
	for _, header := range []string{"Microsoft-IISProxy", "Microsoft-IISTomcat/9.0", "Microsoft-IIS/2..4", "Microsoft-IIS/2.4evil", "Microsoft-IIS/", "Microsoft-IIS/2.4:injected"} {
		t.Run(header, func(t *testing.T) {
			f := fingerprint.Default().Match("", http.Header{"Server": {header}})
			observed := Target{Product: f.Product, Version: f.Version, CPE: inferredCPE(f.Product, f.Version)}
			m := Match{Products: []string{"IIS"}}
			if ok, id := m.evaluate(observed); ok || id {
				t.Fatalf("misleading identity accepted: %+v", observed)
			}
			if reason := m.skipReason(observed); reason != "declarative match: product identification missing" {
				t.Fatal(reason)
			}
			if len(observed.CPE) != 0 {
				t.Fatal(observed.CPE)
			}
		})
	}
}

func TestTomcatMisleadingIdentity(t *testing.T) {
	for _, header := range []string{"TomcatProxy", "TomcatTomcat/9.0", "Tomcat/2..4", "Tomcat/2.4evil", "Tomcat/", "Tomcat/2.4:injected"} {
		t.Run(header, func(t *testing.T) {
			f := fingerprint.Default().Match("", http.Header{"Server": {header}})
			observed := Target{Product: f.Product, Version: f.Version, CPE: inferredCPE(f.Product, f.Version)}
			m := Match{Products: []string{"Tomcat"}}
			if ok, id := m.evaluate(observed); ok || id {
				t.Fatalf("misleading identity accepted: %+v", observed)
			}
			if reason := m.skipReason(observed); reason != "declarative match: product identification missing" {
				t.Fatal(reason)
			}
			if len(observed.CPE) != 0 {
				t.Fatal(observed.CPE)
			}
		})
	}
}

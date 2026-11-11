package httpcap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
)

func fixtureTarget(t *testing.T, rawURL string) scribe.Target {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(u.Port(), 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return scribe.Target{Host: u.Hostname(), Port: uint16(port), Protocol: "tcp", TLS: u.Scheme == "https"}
}

func newClient(t *testing.T, opts Options) *Client {
	t.Helper()
	c, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestGetKnownTarget(t *testing.T) {
	var gotURI, gotHost, gotAuth, gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURI, gotHost = r.RequestURI, r.Host
		gotAuth, gotCookie = r.Header.Get("Authorization"), r.Header.Get("Cookie")
		w.Header().Add("X-Evidence", "first")
		w.Header().Add("X-Evidence", "second")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("fixture evidence"))
	}))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	target := fixtureTarget(t, srv.URL)
	target.IP, target.Host = target.Host, "scan.invalid"
	result, err := newClient(t, Options{}).Function(context.Background(), target, []any{"/a%2Fb?detail=1"})
	if err != nil {
		t.Fatal(err)
	}
	response := result.(map[string]any)
	if response["status"] != int64(202) || response["body"] != "fixture evidence" {
		t.Fatalf("unexpected response: %#v", response)
	}
	values := response["headers"].(map[string]any)["x-evidence"].([]any)
	if len(values) != 2 || values[0] != "first" || values[1] != "second" {
		t.Fatalf("header values lost: %#v", values)
	}
	if gotURI != "/a%2Fb?detail=1" || gotHost != net.JoinHostPort("scan.invalid", strconv.Itoa(int(target.Port))) {
		t.Fatalf("wrong request origin: URI=%q Host=%q", gotURI, gotHost)
	}
	if gotAuth != "" || gotCookie != "" {
		t.Fatalf("unexpected ambient credentials: auth=%q cookie=%q", gotAuth, gotCookie)
	}
}

func TestRedirectIsEvidenceWithoutFollow(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "/next")
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("redirect evidence"))
	}))
	defer srv.Close()
	result, err := newClient(t, Options{}).Function(context.Background(), fixtureTarget(t, srv.URL), []any{"/redirect"})
	if err != nil {
		t.Fatal(err)
	}
	response := result.(map[string]any)
	if response["status"] != int64(302) || response["body"] != "redirect evidence" || calls.Load() != 1 {
		t.Fatalf("redirect was followed or discarded: %#v, calls=%d", response, calls.Load())
	}
}

func TestFixedIPPreservesTLSName(t *testing.T) {
	var gotSNI, gotHost string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSNI, gotHost = r.TLS.ServerName, r.Host
		_, _ = w.Write([]byte("TLS evidence"))
	}))
	defer srv.Close()
	cert := srv.Certificate()
	if len(cert.DNSNames) == 0 {
		t.Fatal("TLS fixture has no DNS subject")
	}
	target := fixtureTarget(t, srv.URL)
	target.IP, target.Host = target.Host, cert.DNSNames[0]
	client := newClient(t, Options{})
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	client.transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	if _, err := client.Function(context.Background(), target, []any{"/"}); err != nil {
		t.Fatal(err)
	}
	if gotSNI != target.Host || gotHost != net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))) {
		t.Fatalf("logical TLS origin lost: SNI=%q Host=%q", gotSNI, gotHost)
	}
}

func TestCancellationAndTimeout(t *testing.T) {
	started := make(chan struct{}, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
	}))
	defer srv.Close()
	target := fixtureTarget(t, srv.URL)
	client := newClient(t, Options{Timeout: 2 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := client.Function(ctx, target, []any{"/"})
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not reach local fixture")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation was lost: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled HTTP request did not return")
	}
	_, err := newClient(t, Options{Timeout: 30 * time.Millisecond}).Function(context.Background(), target, []any{"/"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request timeout was not enforced: %v", err)
	}
}

func TestBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("12345"))
	}))
	defer srv.Close()
	target := fixtureTarget(t, srv.URL)
	if _, err := newClient(t, Options{MaxBodyBytes: 5}).Function(context.Background(), target, []any{"/"}); err != nil {
		t.Fatalf("exact limit should succeed: %v", err)
	}
	result, err := newClient(t, Options{MaxBodyBytes: 4}).Function(context.Background(), target, []any{"/"})
	if err == nil || result != nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("oversize body became successful evidence: result=%#v err=%v", result, err)
	}
}

func TestRejectInvalidPathsAndEndpointsBeforeDial(t *testing.T) {
	client := newClient(t, Options{})
	target := scribe.Target{Host: "scan.invalid", Port: 80, Protocol: "tcp"}
	for _, path := range []string{"", "relative", "http://other.invalid/", "https://other.invalid/", "//other.invalid/", "/bad%escape", "/fragment#part", "/bad\\path", "/raw space", "/control\n"} {
		t.Run(strconv.Quote(path), func(t *testing.T) {
			if result, err := client.Function(context.Background(), target, []any{path}); err == nil || result != nil {
				t.Fatalf("accepted invalid path %q: %#v %v", path, result, err)
			}
		})
	}
	for _, args := range [][]any{nil, {1}, {"/", "/extra"}} {
		if _, err := client.Function(context.Background(), target, args); err == nil {
			t.Fatalf("accepted invalid arguments: %#v", args)
		}
	}
	for _, endpoint := range []scribe.Target{
		{Host: "scan.invalid", Protocol: "tcp"},
		{Host: "scan.invalid", Port: 80, Protocol: "udp"},
		{Host: "scan.invalid", Port: 80},
		{Host: "http://scan.invalid", Port: 80, Protocol: "tcp"},
		{Host: "scan.invalid", IP: "not-an-IP", Port: 80, Protocol: "tcp"},
	} {
		if _, err := client.Function(context.Background(), endpoint, []any{"/"}); err == nil {
			t.Fatalf("accepted invalid endpoint: %#v", endpoint)
		}
	}
}

func TestIPv6Endpoint(t *testing.T) {
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("IPv6 evidence"))
	}))
	_ = srv.Listener.Close()
	srv.Listener = listener
	srv.Start()
	defer srv.Close()
	target := fixtureTarget(t, srv.URL)
	result, err := newClient(t, Options{}).Function(context.Background(), target, []any{"/"})
	if err != nil || result.(map[string]any)["body"] != "IPv6 evidence" {
		t.Fatalf("IPv6 origin failed: %#v %v", result, err)
	}
}

func TestOptionValidation(t *testing.T) {
	for _, opts := range []Options{{Timeout: -1}, {MaxBodyBytes: -1}, {MaxBodyBytes: 1<<63 - 1}} {
		if _, err := New(opts); err == nil {
			t.Fatalf("accepted invalid options: %#v", opts)
		}
	}
}

func TestReuseAndFixedIPPartition(t *testing.T) {
	var connections atomic.Int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	target := fixtureTarget(t, server.URL)
	target.IP = target.Host
	target.Host = "logical.invalid"
	c := newClient(t, Options{})
	for range 3 {
		if _, err := c.Function(context.Background(), target, []any{"/"}); err != nil {
			t.Fatal(err)
		}
	}
	if connections.Load() != 1 {
		t.Fatalf("connections=%d", connections.Load())
	}
	// Same logical hostname and port with a changed fixed IP must dial anew.
	target.IP = "127.0.0.2"
	if _, err := c.Function(context.Background(), target, []any{"/"}); err == nil {
		t.Fatal("reused previous fixed IP connection")
	}
	c.Close()
	if _, err := c.Function(context.Background(), target, []any{"/"}); err == nil {
		t.Fatal("closed client accepted request")
	}
}

func TestEndpointPoolBound(t *testing.T) {
	c := newClient(t, Options{})
	var releases []func()
	for i := 0; i < 64; i++ {
		_, release, err := c.acquire(strconv.Itoa(i))
		if err != nil {
			t.Fatal(err)
		}
		releases = append(releases, release)
	}
	if _, _, err := c.acquire("overflow"); err == nil {
		t.Fatal("unbounded pools")
	}
	releases[0]()
	_, release, err := c.acquire("replacement")
	if err != nil {
		t.Fatal(err)
	}
	release()
	for _, r := range releases[1:] {
		r()
	}
	if len(c.pools) != 64 {
		t.Fatalf("pool count %d", len(c.pools))
	}
}

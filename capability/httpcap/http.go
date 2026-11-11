// Package httpcap provides bounded HTTP requests to the task's known endpoint.
package httpcap

import (
	"context"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SiriusScan/scribe"
)

const (
	defaultTimeout      = 10 * time.Second
	defaultMaxBodyBytes = int64(1 << 20)
)

// Options bounds each request. Zero fields use finite defaults.
type Options struct {
	// Timeout bounds the complete HTTP request; zero uses ten seconds, negative is invalid.
	Timeout time.Duration
	// MaxBodyBytes bounds response bytes; zero uses 1 MiB. Negative and MaxInt64 are invalid.
	MaxBodyBytes int64
	// DisableReuse forces a fresh connection for each request.
	DisableReuse bool
}

// Client grants GET requests only to the endpoint supplied by the caller.
// Reusable connections are partitioned by logical authority, fixed IP and TLS.
// The zero Client is not usable; initialize it with New and close it after use.
type Client struct {
	client       *http.Client
	transport    *http.Transport
	maxBodyBytes int64
	mu           sync.Mutex
	pools        map[string]*endpointPool
	closed       bool
	disableReuse bool
}

type dialAddressKey struct{}

// New creates a client without environment proxies, cookie storage, redirects,
// or ambient authentication. Response headers are limited to 64 KiB.
func New(options Options) (*Client, error) {
	if options.Timeout < 0 {
		return nil, fmt.Errorf("HTTP timeout must be positive")
	}
	if options.Timeout == 0 {
		options.Timeout = defaultTimeout
	}
	if options.MaxBodyBytes < 0 || options.MaxBodyBytes == math.MaxInt64 {
		return nil, fmt.Errorf("HTTP body limit must be positive and less than MaxInt64")
	}
	if options.MaxBodyBytes == 0 {
		options.MaxBodyBytes = defaultMaxBodyBytes
	}
	dialer := &net.Dialer{Timeout: options.Timeout, KeepAlive: -1}
	transport := &http.Transport{
		// A nil Proxy deliberately ignores HTTP_PROXY and HTTPS_PROXY.
		Proxy:             nil,
		DisableKeepAlives: options.DisableReuse,
		MaxIdleConns:      2, MaxIdleConnsPerHost: 2, MaxConnsPerHost: 32,
		DisableCompression:     true,
		TLSHandshakeTimeout:    options.Timeout,
		ResponseHeaderTimeout:  options.Timeout,
		IdleConnTimeout:        options.Timeout,
		MaxResponseHeaderBytes: 64 << 10,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			address, ok := ctx.Value(dialAddressKey{}).(string)
			if !ok {
				return nil, fmt.Errorf("HTTP request has no target endpoint")
			}
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, fmt.Errorf("HTTP requires a TCP connection")
			}
			return dialer.DialContext(ctx, network, address)
		},
	}
	return &Client{
		client: &http.Client{
			Transport: transport,
			Timeout:   options.Timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		transport:    transport,
		maxBodyBytes: options.MaxBodyBytes,
		pools:        make(map[string]*endpointPool), disableReuse: options.DisableReuse,
	}, nil
}

// Close releases any idle transport resources. It does not cancel active calls.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.transport.CloseIdleConnections()
	for _, p := range c.pools {
		p.transport.CloseIdleConnections()
	}
}

// Function implements scribe.Function for the "http.get" capability. Its single
// argument must be an origin-form path such as "/status?detail=1". Results contain
// status (integer), body (string), and headers (lowercase names to string arrays).
// Non-2xx responses are returned as evidence; redirects are never followed.
// A body larger than MaxBodyBytes returns an error, never a partial success.
func (c *Client) Function(ctx context.Context, target scribe.Target, args []any) (any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("HTTP context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if target.Port == 0 || target.Protocol != "tcp" {
		return nil, fmt.Errorf("HTTP requires an explicit TCP target and nonzero port")
	}
	if len(args) != 1 {
		return nil, fmt.Errorf("http.get requires exactly one origin-form path")
	}
	path, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("http.get path must be a string")
	}
	u, err := originPath(path)
	if err != nil {
		return nil, err
	}
	u.Scheme = "http"
	if target.TLS {
		u.Scheme = "https"
	}
	port := strconv.Itoa(int(target.Port))
	u.Host = net.JoinHostPort(target.Host, port)
	connectionHost := target.Host
	if target.IP != "" {
		connectionHost = target.IP
	}
	ctx = context.WithValue(ctx, dialAddressKey{}, net.JoinHostPort(connectionHost, port))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}
	client, release, err := c.acquire(u.Scheme + "://" + u.Host + "/" + connectionHost)
	if err != nil {
		return nil, err
	}
	defer release()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read HTTP response: %w", err)
	}
	if int64(len(body)) > c.maxBodyBytes {
		return nil, fmt.Errorf("HTTP response body exceeds %d bytes", c.maxBodyBytes)
	}
	headers := make(map[string]any, len(resp.Header))
	for name, values := range resp.Header {
		copyValues := make([]any, len(values))
		for i, value := range values {
			copyValues[i] = value
		}
		headers[strings.ToLower(name)] = copyValues
	}
	return map[string]any{
		"status":  int64(resp.StatusCode),
		"headers": headers,
		"body":    string(body),
	}, nil
}

func originPath(path string) (*url.URL, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "#\\") {
		return nil, fmt.Errorf("http.get requires an origin-form path without an authority or fragment")
	}
	for _, ch := range path {
		if ch <= ' ' || ch == 0x7f {
			return nil, fmt.Errorf("HTTP path contains whitespace or control characters")
		}
	}
	u, err := url.ParseRequestURI(path)
	if err != nil || u.IsAbs() || u.Host != "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid HTTP origin-form path %q", path)
	}
	return u, nil
}

var _ scribe.Function = (*Client)(nil).Function

// endpointPool owns a transport for exactly one connection identity. Active
// pools are never evicted; admission fails conservatively at the finite bound.
type endpointPool struct {
	transport *http.Transport
	client    *http.Client
	active    int
}

func (c *Client) acquire(key string) (*http.Client, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, nil, fmt.Errorf("HTTP client is closed")
	}
	if c.disableReuse {
		return c.client, func() {}, nil
	}
	p := c.pools[key]
	if p == nil {
		if len(c.pools) >= 64 {
			for k, old := range c.pools {
				if old.active == 0 {
					old.transport.CloseIdleConnections()
					delete(c.pools, k)
					break
				}
			}
			if len(c.pools) >= 64 {
				return nil, nil, fmt.Errorf("HTTP endpoint pool limit exceeded")
			}
		}
		transport := c.transport.Clone()
		client := *c.client
		client.Transport = transport
		p = &endpointPool{transport: transport, client: &client}
		c.pools[key] = p
	}
	p.active++
	return p.client, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		p.active--
		if c.closed {
			p.transport.CloseIdleConnections()
		}
	}, nil
}

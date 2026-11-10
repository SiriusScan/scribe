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
	"time"

	"github.com/SiriusScan/scribe"
)

const (
	defaultTimeout      = 10 * time.Second
	defaultMaxBodyBytes = int64(1 << 20)
)

// Options bounds each request. Zero fields use finite defaults.
type Options struct {
	Timeout      time.Duration
	MaxBodyBytes int64
}

// Client grants GET requests only to the endpoint supplied by the caller.
// Connections are not reused, so changing a target's fixed IP can never reuse a
// connection to another IP under the same logical hostname.
type Client struct {
	client       *http.Client
	transport    *http.Transport
	maxBodyBytes int64
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
		Proxy:                  nil,
		DisableKeepAlives:      true,
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
	}, nil
}

// Close releases any idle transport resources. It does not cancel active calls.
func (c *Client) Close() {
	c.transport.CloseIdleConnections()
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
	resp, err := c.client.Do(req)
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

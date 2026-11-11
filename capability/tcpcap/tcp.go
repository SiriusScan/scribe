// Package tcpcap provides bounded, one-connection TCP exchanges.
package tcpcap

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/SiriusScan/scribe"
	"io"
	"net"
	"strconv"
	"time"
)

// Function connects to the supplied endpoint, optionally sends one string, and
// receives one chunk (at most 64 KiB). No arguments performs a banner grab.
// The exchange has a five-second ceiling, tightened by the context deadline.
// Returned data is text (empty on EOF); eof is a boolean. TLS version is a
// numeric protocol identifier, certificate dates are RFC3339 strings.
// Target.TLS enables a verified TLS handshake and certificate metadata.
func Function(ctx context.Context, target scribe.Target, args []any) (any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context required")
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if target.Protocol != "tcp" || target.Port == 0 {
		return nil, fmt.Errorf("explicit TCP endpoint required")
	}
	payload := ""
	if len(args) > 1 {
		return nil, fmt.Errorf("tcp.exchange accepts at most one string")
	}
	if len(args) == 1 {
		var ok bool
		payload, ok = args[0].(string)
		if !ok {
			return nil, fmt.Errorf("payload must be a string")
		}
	}
	if len(payload) > 65536 {
		return nil, fmt.Errorf("payload exceeds 64 KiB")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(target.Port))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	result := map[string]any{}
	var stream net.Conn = conn
	if target.TLS {
		secure := tls.Client(conn, &tls.Config{ServerName: target.Host, MinVersion: tls.VersionTLS12})
		if err = secure.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		state := secure.ConnectionState()
		cert := state.PeerCertificates[0]
		result["tls"] = map[string]any{"version": int(state.Version), "cipher_suite": tls.CipherSuiteName(state.CipherSuite), "subject": cert.Subject.String(), "issuer": cert.Issuer.String(), "not_before": cert.NotBefore.Format(time.RFC3339), "not_after": cert.NotAfter.Format(time.RFC3339)}
		stream = secure
	}
	for len(payload) > 0 {
		n, e := io.WriteString(stream, payload)
		if e != nil {
			return nil, e
		}
		if n == 0 {
			return nil, io.ErrShortWrite
		}
		payload = payload[n:]
	}
	buffer := make([]byte, 65536)
	n, err := stream.Read(buffer)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result["data"] = string(buffer[:n])
	result["eof"] = err == io.EOF
	return result, nil
}

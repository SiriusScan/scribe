// Package tcpcap provides bounded, one-connection TCP exchanges.
package tcpcap

import (
	"bufio"
	"bytes"
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
// receives one chunk (at most 64 KiB). An optional second integer argument
// requests exactly that many bytes (1..65536); premature EOF is an error.
// A string second argument reads through a 1..256-byte delimiter, inclusive,
// within 64 KiB; missing delimiters are errors.
// One array argument runs 1..16 argument arrays on the same connection and
// returns ordered replies. A failed step discards all replies.
// No arguments performs a banner grab.
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
	steps := [][]any{args}
	if len(args) == 1 {
		if sequence, ok := args[0].([]any); ok {
			if len(sequence) == 0 || len(sequence) > 16 {
				return nil, fmt.Errorf("session requires 1..16 exchanges")
			}
			steps = nil
			for _, item := range sequence {
				pair, ok := item.([]any)
				if !ok {
					return nil, fmt.Errorf("session exchanges must be arrays")
				}
				steps = append(steps, pair)
			}
		}
	}
	// Validate every exchange before opening the connection.
	for _, step := range steps {
		if _, err := exchange(nil, step); err != nil {
			return nil, err
		}
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
	buffered := struct {
		io.Reader
		io.Writer
	}{bufio.NewReaderSize(stream, 4096), stream}
	replies := make([]any, 0, len(steps))
	for _, step := range steps {
		reply, e := exchange(buffered, step)
		if e != nil {
			return nil, e
		}
		replies = append(replies, reply)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(args) == 1 {
		if _, ok := args[0].([]any); ok {
			result["replies"] = replies
			return result, nil
		}
	}
	for k, v := range replies[0].(map[string]any) {
		result[k] = v
	}
	return result, nil
}

func exchange(stream io.ReadWriter, args []any) (any, error) {
	payload := ""
	readBytes := 0
	delimiter := ""
	if len(args) > 2 {
		return nil, fmt.Errorf("tcp.exchange accepts a payload and optional byte count")
	}
	if len(args) >= 1 {
		var ok bool
		payload, ok = args[0].(string)
		if !ok {
			return nil, fmt.Errorf("payload must be a string")
		}
	}
	if len(args) == 2 {
		switch v := args[1].(type) {
		case int64:
			if v < 1 || v > 65536 {
				return nil, fmt.Errorf("read byte count must be an integer from 1 to 65536")
			}
			readBytes = int(v)
		case string:
			if len(v) == 0 || len(v) > 256 {
				return nil, fmt.Errorf("read delimiter must contain 1 to 256 bytes")
			}
			delimiter = v
		default:
			return nil, fmt.Errorf("read selector must be an integer byte count or string delimiter")
		}
	}
	if len(payload) > 65536 {
		return nil, fmt.Errorf("payload exceeds 64 KiB")
	}
	if stream == nil {
		return nil, nil
	}
	result := map[string]any{}
	var err error
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
	var n int
	if delimiter != "" {
		// Read only through the delimiter, without consuming subsequent frames.
		for n < len(buffer) {
			var count int
			count, err = io.ReadFull(stream, buffer[n:n+1])
			n += count
			if err != nil {
				break
			}
			if bytes.HasSuffix(buffer[:n], []byte(delimiter)) {
				break
			}
		}
		if err == nil && !bytes.HasSuffix(buffer[:n], []byte(delimiter)) {
			err = fmt.Errorf("reply delimiter absent within 64 KiB")
		}
	} else if readBytes > 0 {
		n, err = io.ReadFull(stream, buffer[:readBytes])
	} else {
		n, err = stream.Read(buffer)
	}
	if err != nil && (readBytes > 0 || delimiter != "" || err != io.EOF) {
		return nil, err
	}
	result["data"] = string(buffer[:n])
	result["eof"] = err == io.EOF
	return result, nil
}

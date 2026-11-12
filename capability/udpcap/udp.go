// Package udpcap provides bounded endpoint-local UDP request/reply exchanges.
package udpcap

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/SiriusScan/scribe"
)

// Function sends one string datagram and receives one reply from the supplied
// UDP endpoint. Both datagrams are bounded to 65507 bytes. The five-second
// deadline is tightened by the caller context. Protocol correlation belongs
// to the script; a reply alone establishes no verdict.
func Function(ctx context.Context, target scribe.Target, args []any) (any, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context required")
	}
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if target.Protocol != "udp" || target.Port == 0 || target.TLS {
		return nil, fmt.Errorf("explicit UDP endpoint without TLS required")
	}
	payloads, session, err := parsePayloads(args)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	host := target.Host
	if target.IP != "" {
		host = target.IP
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(int(target.Port))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	buffer := make([]byte, 65508)
	results := make([]any, 0, len(payloads))
	for _, payload := range payloads {
		if n, err := conn.Write([]byte(payload)); err != nil {
			return nil, err
		} else if n != len(payload) {
			return nil, fmt.Errorf("short datagram write")
		}
		n, err := conn.Read(buffer)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if n > 65507 {
			return nil, fmt.Errorf("reply exceeds 65507 bytes")
		}
		results = append(results, map[string]any{"data": string(buffer[:n])})
	}
	if session {
		return results, nil
	}
	return results[0], nil
}

// parsePayloads validates the entire session before any network activity.
func parsePayloads(args []any) ([]string, bool, error) {
	if len(args) != 1 {
		return nil, false, fmt.Errorf("udp.exchange requires one payload or payload array")
	}
	values, session := args[0].([]any)
	if !session {
		values = args
	}
	if len(values) < 1 || len(values) > 16 {
		return nil, false, fmt.Errorf("UDP session requires 1..16 payloads")
	}
	payloads := make([]string, len(values))
	for i, value := range values {
		payload, ok := value.(string)
		if !ok || len(payload) > 65507 {
			return nil, false, fmt.Errorf("payload must be a string of at most 65507 bytes")
		}
		payloads[i] = payload
	}
	return payloads, session, nil
}

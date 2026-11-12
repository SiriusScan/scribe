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
	if len(args) != 1 {
		return nil, fmt.Errorf("udp.exchange requires one string payload")
	}
	payload, ok := args[0].(string)
	if !ok || len(payload) > 65507 {
		return nil, fmt.Errorf("payload must be a string of at most 65507 bytes")
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
	if n, err := conn.Write([]byte(payload)); err != nil {
		return nil, err
	} else if n != len(payload) {
		return nil, fmt.Errorf("short datagram write")
	}
	buffer := make([]byte, 65508)
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
	return map[string]any{"data": string(buffer[:n])}, nil
}

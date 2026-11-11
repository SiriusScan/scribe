package scribe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"strconv"
	"time"
)

// udpProbe identifies only correlated DNS and NTP responses. SNMP is omitted:
// guessing community credentials is outside planner identification.
func udpProbe(ctx context.Context, t Target) Target {
	var request []byte
	service := ""
	switch {
	case t.Port == 53 || t.Service == "dns":
		request = []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
		if _, err := rand.Read(request[:2]); err != nil {
			return Target{}
		}
		service = "dns"
	case t.Port == 123 || t.Service == "ntp":
		request = make([]byte, 48)
		request[0] = 0x23
		if _, err := rand.Read(request[40:48]); err != nil {
			return Target{}
		}
		service = "ntp"
	default:
		return Target{}
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	host := t.Host
	if t.IP != "" {
		host = t.IP
	}
	c, err := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(int(t.Port))))
	if err != nil {
		return Target{}
	}
	defer c.Close()
	deadline, _ := ctx.Deadline()
	c.SetDeadline(deadline)
	if _, err = c.Write(request); err != nil {
		return Target{}
	}
	b := make([]byte, 8193)
	n, err := c.Read(b)
	if err != nil || n > 8192 {
		return Target{}
	}
	valid := false
	if service == "dns" {
		valid = n >= 12 && binary.BigEndian.Uint16(b[:2]) == binary.BigEndian.Uint16(request[:2]) && b[2]&0xf8 == 0x80 && binary.BigEndian.Uint16(b[4:6]) == 1 && n >= len(request) && string(b[12:len(request)]) == string(request[12:])
	}
	if service == "ntp" {
		valid = n >= 48 && b[0]&7 == 4 && (b[0]>>3)&7 >= 3 && (b[0]>>3)&7 <= 4 && b[1] > 0 && b[1] <= 15 && string(b[24:32]) == string(request[40:48])
	}
	if !valid {
		return Target{}
	}
	return Target{Service: service, Confidence: 0.8}
}

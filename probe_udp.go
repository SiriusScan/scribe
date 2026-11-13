package scribe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// udpProbe identifies DNS, NTP and SSDP responses without credentials.
// SNMP uses the separately supplied caller community policy.
func udpProbe(ctx context.Context, t Target) Target {
	var request []byte
	service := ""
	switch {
	case t.Port == 1900 || t.Service == "ssdp":
		request = []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: upnp:rootdevice\r\n\r\n")
		service = "ssdp"
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
	if service == "ssdp" {
		valid = validSSDPReply(b[:n])
	}
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

// validSSDPReply accepts only a complete response to the selected search target.
// Location and server headers remain untrusted observations, never product facts.
func validSSDPReply(b []byte) bool {
	if !bytes.Contains(b, []byte("\r\n\r\n")) {
		return false
	}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b)), nil)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	st, usn := response.Header.Values("ST"), response.Header.Values("USN")
	return response.Proto == "HTTP/1.1" && response.StatusCode == 200 &&
		len(st) == 1 && st[0] == "upnp:rootdevice" && len(usn) == 1 &&
		strings.HasPrefix(usn[0], "uuid:") && len(strings.TrimSuffix(strings.TrimPrefix(usn[0], "uuid:"), "::upnp:rootdevice")) > 0 &&
		strings.HasSuffix(usn[0], "::upnp:rootdevice")
}

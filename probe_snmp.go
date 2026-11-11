package scribe

import (
	"context"
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"net"
	"strconv"
	"time"
)

type snmpBinding struct {
	Name  asn1.ObjectIdentifier
	Value asn1.RawValue
}
type snmpPDU struct {
	ID       int
	Error    int
	Index    int
	Bindings []snmpBinding
}
type snmpMessage struct {
	Version   int
	Community string
	PDU       asn1.RawValue
}

func snmpProbe(ctx context.Context, t Target, community string) Target {
	if len(community) == 0 || len(community) > 255 {
		return Target{}
	}
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Target{}
	}
	id := int(binary.BigEndian.Uint32(nonce[:]) & 0x7fffffff)
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0}
	pdu, _ := asn1.Marshal(snmpPDU{ID: id, Bindings: []snmpBinding{{Name: oid, Value: asn1.RawValue{Tag: 5}}}})
	pdu[0] = 0xa0
	request, err := asn1.Marshal(snmpMessage{1, community, asn1.RawValue{FullBytes: pdu}})
	if err != nil {
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
	var msg snmpMessage
	rest, err := asn1.Unmarshal(b[:n], &msg)
	if err != nil || len(rest) != 0 || msg.Version != 1 || msg.Community != community || msg.PDU.Class != 2 || msg.PDU.Tag != 2 || !msg.PDU.IsCompound {
		return Target{}
	}
	raw := append([]byte(nil), msg.PDU.FullBytes...)
	raw[0] = 0x30
	var response snmpPDU
	rest, err = asn1.Unmarshal(raw, &response)
	if err != nil || len(rest) != 0 || response.ID != id || response.Error != 0 || response.Index != 0 || len(response.Bindings) != 1 || !response.Bindings[0].Name.Equal(oid) || response.Bindings[0].Value.Tag != 4 {
		return Target{}
	}
	return Target{Service: "snmp", Confidence: 0.8}
}

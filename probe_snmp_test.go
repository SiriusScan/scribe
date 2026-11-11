package scribe

import (
	"context"
	"encoding/asn1"
	"net"
	"testing"
)

func TestSNMPIdentification(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(map[bool]string{true: "valid", false: "wrong-id"}[valid], func(t *testing.T) {
			c, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				b := make([]byte, 8192)
				n, a, e := c.ReadFrom(b)
				if e != nil {
					return
				}
				var msg snmpMessage
				asn1.Unmarshal(b[:n], &msg)
				raw := msg.PDU.FullBytes
				raw[0] = 0x30
				var p snmpPDU
				asn1.Unmarshal(raw, &p)
				if !valid {
					p.ID++
				}
				p.Bindings[0].Value = asn1.RawValue{Tag: 4, Bytes: []byte("test device")}
				raw, _ = asn1.Marshal(p)
				raw[0] = 0xa2
				msg.PDU = asn1.RawValue{FullBytes: raw}
				b, _ = asn1.Marshal(msg)
				c.WriteTo(b, a)
			}()
			target := Target{Host: "127.0.0.1", Protocol: "udp", Service: "snmp", Port: uint16(c.LocalAddr().(*net.UDPAddr).Port)}
			if got := snmpProbe(context.Background(), target, ""); got.Service != "" {
				t.Fatal("enabled without policy")
			}
			got := probeCache{}.enrich(context.Background(), target, 1, "fixture-community")
			<-done
			// Supplied service remains intact; confidence proves a correlated response.
			if (got.Confidence == 0.8) != valid || got.Product != "" {
				t.Fatalf("facts: %+v", got)
			}
		})
	}
}

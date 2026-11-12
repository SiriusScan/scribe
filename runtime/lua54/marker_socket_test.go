package lua54

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/SiriusScan/scribe"
	"github.com/SiriusScan/scribe/capability/httpcap"
	"github.com/SiriusScan/scribe/capability/tcpcap"
)

// The pinned original corpus also runs through real bounded transports.
// TLS rejection and isolated local-CA trust both retain conservative verdicts.
func TestMarkerCorpusSockets(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "tls", "trusted-tls"} {
		for _, product := range []string{"Scribe fixture", "", "Other"} {
			for _, exhaustive := range []bool{false, true} {
				for _, marker := range []string{"vulnerable", "clean", "unrecognized"} {
					t.Run(fmt.Sprintf("%s/%s/product=%s/exhaustive=%t", protocol, marker, product, exhaustive), func(t *testing.T) {
						if protocol == "trusted-tls" && os.Getenv("SCRIBE_TLS_CHILD") == "" {
							cmd := exec.Command(os.Args[0], "-test.run=^TestMarkerCorpusSockets/trusted-tls/"+marker+"/product="+product+"/exhaustive="+fmt.Sprint(exhaustive)+"$")
							cmd.Env = append(os.Environ(), "SCRIBE_TLS_CHILD=1")
							if out, err := cmd.CombinedOutput(); err != nil {
								t.Fatalf("trusted TLS child: %v\n%s", err, out)
							}
							return
						}
						var addr net.Addr
						var fn scribe.Function
						client, err := httpcap.New(httpcap.Options{})
						if err != nil {
							t.Fatal(err)
						}
						defer client.Close()
						if protocol == "http" {
							server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("X-Sirius-Fixture", marker) }))
							defer server.Close()
							addr = server.Listener.Addr()
							fn = client.Function
						} else if protocol == "tls" {
							server := httptest.NewTLSServer(nil)
							defer server.Close()
							addr = server.Listener.Addr()
							fn = tcpcap.Function
						} else {
							var listener net.Listener
							if protocol == "trusted-tls" {
								key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
								if e != nil {
									t.Fatal(e)
								}
								cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
								der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
								if e != nil {
									t.Fatal(e)
								}
								ca := filepath.Join(t.TempDir(), "ca.pem")
								if e = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
									t.Fatal(e)
								}
								t.Setenv("SSL_CERT_FILE", ca)
								t.Setenv("SSL_CERT_DIR", t.TempDir())
								listener, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
							} else {
								listener, err = net.Listen("tcp", "127.0.0.1:0")
							}
							if err != nil {
								t.Fatal(err)
							}
							defer listener.Close()
							addr = listener.Addr()
							fn = tcpcap.Function
							done := make(chan struct{})
							go func() {
								defer close(done)
								c, e := listener.Accept()
								if e != nil {
									return
								}
								defer c.Close()
								c.SetDeadline(time.Now().Add(time.Second))
								b := make([]byte, 8)
								if _, e = io.ReadFull(c, b); e == nil {
									io.WriteString(c, marker)
								}
							}()
							defer func() { listener.Close(); <-done }()
						}
						scriptProtocol := protocol
						if protocol == "trusted-tls" {
							scriptProtocol = "tls"
						}
						source, err := os.ReadFile("../../testdata/sirius/" + scriptProtocol + "-marker.lua")
						if err != nil {
							t.Fatal(err)
						}
						name := "tcp.exchange"
						if protocol == "http" {
							name = "http.get"
						}
						rt, err := NewNative(Options{Functions: map[string]scribe.Function{name: fn}})
						if err != nil {
							t.Fatal(err)
						}
						engine, err := scribe.New(scribe.Options{StrictIdentification: true, Exhaustive: exhaustive}, rt)
						if err != nil {
							t.Fatal(err)
						}
						ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
						defer cancel()
						count := 0
						idx, e := scribe.NewIndex([]scribe.Script{{ID: protocol + "-marker", Dialect: scribe.Sirius, Source: source}})
						if e != nil {
							t.Fatal(e)
						}
						err = engine.RunSelected(ctx, idx, []scribe.Target{{Host: "localhost", IP: "127.0.0.1", Port: uint16(addr.(*net.TCPAddr).Port), Protocol: "tcp", Service: "http", Product: product, TLS: protocol == "tls" || protocol == "trusted-tls"}}, func(r scribe.Result) error {
							count++
							want := scribe.Unknown
							if marker == "vulnerable" {
								want = scribe.Vulnerable
							}
							if marker == "clean" {
								want = scribe.NotVulnerable
							}
							if product != "Scribe fixture" {
								if r.Status != scribe.Skipped || r.Verdict != scribe.Unknown || r.Output.SkipReason != "script hints exclude supplied endpoint facts" {
									t.Fatalf("identity gate: %+v", r)
								}
							} else if protocol == "tls" {
								if r.Status != scribe.Failed || r.Verdict != scribe.Unknown {
									t.Fatalf("untrusted TLS: %+v", r)
								}
							} else if r.Status != scribe.Completed || r.Verdict != want {
								t.Fatalf("result: %+v", r)
							}
							return nil
						})
						if (err != nil && protocol != "tls") || count != 1 {
							t.Fatalf("records=%d err=%v", count, err)
						}
					})
				}
			}
		}

	}
}

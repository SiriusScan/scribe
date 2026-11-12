package lua54

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/SiriusScan/scribe"
	"os"
	"strings"
	"testing"
)

func TestMarkerCorpus(t *testing.T) {
	for _, fixture := range []struct{ name, digest, function string }{
		{"tls-pop3-auth", "b1750c93e0b9a8fd571b8b9a77afaab387e9d38a31f332df85e73367467d9c9a", "tcp.exchange"},
		{"tcp-pop3-auth", "6c1e7317ed7121f9683af0acd760357ada2e835cc7bb569ffd8ffbb114231e5b", "tcp.exchange"},
		{"tcp-redis-auth", "fa1300cc0c1e9e718b0d296891be0b208f4b6010f83fb050c896a4cea0b8141a", "tcp.exchange"},
		{"tls-redis-auth", "cae4f8930fa230d2709265e25b20b549f76e995b7f8763c998274dcda508b444", "tcp.exchange"},
		{"tcp-smtp-vrfy", "54229aaff42e6754cec7492b4cad172deecd34f0f1428295e02c180400caee2b", "tcp.exchange"}, {"tls-smtp-vrfy", "70cb7790ea1c5debc9ec0e20cd7e4b0504340adb9996f52eee5cbfb4e69ffe1a", "tcp.exchange"}, {"tcp-ftp-anonymous", "67df32b6be4775ca55e9a2c026a4de2931ef1f0dc96c596c11bd6053044e44df", "tcp.exchange"}, {"tls-legacy-version", "604b151b66df764627532fae28866db1c8b55a3896a0c53afb3312563aa7ce34", "tcp.exchange"}, {"http-directory-index", "9ef0a031f02db43c083b4fd7776f8f4e3bd90ba84558e3b5e985063f9f99e922", "http.get"}, {"http-cookie", "92bc4e23652e19a6a4b826fd8571c2902d89d463a9a318c230ab24ae17d46342", "http.get"}, {"http-security-headers", "3688e1380e6258d4b39adde7357703222462ce832b2fbb645dbcaba0649cded3", "http.get"}, {"http-marker", "233d593087b6b58ee84d6fe4cc2731c9b556da9c0b9b166648fd48c246803c6b", "http.get"}, {"tcp-marker", "eb1fd95d6b05339647f635b54488044b782271a0e7ca95cff3a3973f845654fc", "tcp.exchange"}, {"tls-marker", "d2b314eb779c734fbfd1382e2b2b7ea16b5a4554e16ecb0bdc81204d20779369", "tcp.exchange"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			source, err := os.ReadFile("../../testdata/sirius/" + fixture.name + ".lua")
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(source)); got != fixture.digest {
				t.Fatalf("fixture digest changed: %s", got)
			}
			markers := []string{"vulnerable", "clean", "unrecognized"}
			if fixture.name == "tcp-redis-auth" || fixture.name == "tls-redis-auth" || fixture.name == "tcp-pop3-auth" || fixture.name == "tls-pop3-auth" {
				markers = append(markers, "missing-tls")
			}
			for _, marker := range markers {
				for _, product := range []string{"Scribe fixture", "", "Other"} {
					for _, exhaustive := range []bool{false, true} {
						rt, err := NewNative(Options{Functions: map[string]scribe.Function{fixture.function: func(_ context.Context, _ scribe.Target, args []any) (any, error) {
							if fixture.name == "tcp-redis-auth" || fixture.name == "tls-redis-auth" || fixture.name == "tcp-pop3-auth" || fixture.name == "tls-pop3-auth" {
								request := "*1\r\n$4\r\nPING\r\n"
								if strings.Contains(fixture.name, "pop3") {
									request = "USER root\r\n"
								}
								if len(args) != 1 || args[0] != request {
									t.Fatalf("unexpected request: %v", args)
								}
								data := "unexpected"
								if marker == "vulnerable" {
									data = "+PONG\r\n"
								}
								if marker == "clean" || marker == "missing-tls" {
									data = "-NOAUTH Authentication required.\r\n"
								}
								if strings.Contains(fixture.name, "pop3") {
									data = strings.ReplaceAll(data, "+PONG\r\n", "+OK logged in\r\n")
									data = strings.ReplaceAll(data, "-NOAUTH Authentication required.\r\n", "-ERR authentication required\r\n")
								}
								r := map[string]any{"data": data}
								if marker != "missing-tls" {
									r["tls"] = map[string]any{"version": 771}
								}
								return r, nil
							}
							if fixture.name == "tcp-smtp-vrfy" || fixture.name == "tls-smtp-vrfy" {
								data := "unexpected"
								if marker == "vulnerable" {
									data = "250 root"
								}
								if marker == "clean" {
									data = "502 Command not implemented"
								}
								return map[string]any{"data": data, "tls": map[string]any{"version": 771}}, nil
							}
							if fixture.name == "tcp-ftp-anonymous" {
								data := "unexpected"
								if marker == "vulnerable" {
									data = "331 Password required"
								}
								if marker == "clean" {
									data = "530 Anonymous disabled"
								}
								return map[string]any{"data": data}, nil
							}
							if fixture.name == "tls-legacy-version" {
								version := 0
								if marker == "vulnerable" {
									version = 769
								}
								if marker == "clean" {
									version = 771
								}
								return map[string]any{"data": "", "tls": map[string]any{"version": version}}, nil
							}
							if fixture.name == "http-directory-index" {
								status := 503
								body := ""
								if marker == "vulnerable" {
									status = 200
									body = "<title>Index of /</title>"
								}
								if marker == "clean" {
									status = 403
								}
								return map[string]any{"status": status, "body": body}, nil
							}
							if fixture.function == "tcp.exchange" {
								return map[string]any{"data": marker, "tls": map[string]any{"version": 771}}, nil
							}
							if fixture.name == "http-cookie" {
								cookie := "session=abc"
								if marker == "clean" {
									cookie += "; Secure; HttpOnly"
								}
								if marker == "unrecognized" {
									cookie = "other=abc"
								}
								return map[string]any{"status": 200, "headers": map[string]any{"set-cookie": []any{cookie}}}, nil
							}
							if fixture.name == "http-security-headers" {
								status := 200
								headers := map[string]any{}
								if marker == "clean" {
									headers["content-security-policy"] = []any{"default-src 'self'"}
									headers["x-content-type-options"] = []any{"nosniff"}
								}
								if marker == "unrecognized" {
									status = 503
								}
								return map[string]any{"status": status, "headers": headers}, nil
							}
							return map[string]any{"status": 200, "headers": map[string]any{"x-sirius-fixture": []any{marker}}}, nil
						}}})
						if err != nil {
							t.Fatal(err)
						}
						engine, err := scribe.New(scribe.Options{StrictIdentification: true, Exhaustive: exhaustive}, rt)
						if err != nil {
							t.Fatal(err)
						}
						idx, err := scribe.NewIndex([]scribe.Script{{ID: fixture.name, Dialect: scribe.Sirius, Source: source}})
						if err != nil {
							t.Fatal(err)
						}
						service := "http"
						if fixture.name == "tcp-redis-auth" || fixture.name == "tls-redis-auth" || fixture.name == "tcp-pop3-auth" || fixture.name == "tls-pop3-auth" {
							service = "redis"
							if strings.Contains(fixture.name, "pop3") {
								service = "pop3"
							}
						}
						count := 0
						err = engine.RunSelected(context.Background(), idx, []scribe.Target{{Host: "fixture", Service: service, Product: product}}, func(r scribe.Result) error {
							count++
							want := scribe.Unknown
							if marker == "vulnerable" {
								want = scribe.Vulnerable
							}
							if marker == "clean" || (marker == "missing-tls" && (fixture.name == "tcp-redis-auth" || fixture.name == "tcp-pop3-auth")) {
								want = scribe.NotVulnerable
							}
							if product != "Scribe fixture" {
								if r.Status != scribe.Skipped || r.Output.SkipReason == "" {
									t.Fatalf("missing skip: %+v", r)
								}
								reason := "script hints exclude supplied endpoint facts"
								if r.Output.SkipReason != reason {
									t.Fatalf("reason: %+v", r)
								}
								want = scribe.Unknown
							} else if r.Status != scribe.Completed {
								t.Fatalf("execution: %+v", r)
							}
							if r.Verdict != want {
								t.Fatalf("marker=%s product=%s: %+v", marker, product, r)
							}
							return nil
						})
						if err != nil || count != 1 {
							t.Fatalf("count=%d err=%v", count, err)
						}
					}
				}
			}
		})
	}
}

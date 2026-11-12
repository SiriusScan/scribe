package lua54

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/SiriusScan/scribe"
	"os"
	"testing"
)

func TestMarkerCorpus(t *testing.T) {
	for _, fixture := range []struct{ name, digest, function string }{
		{"http-cookie", "92bc4e23652e19a6a4b826fd8571c2902d89d463a9a318c230ab24ae17d46342", "http.get"}, {"http-security-headers", "3688e1380e6258d4b39adde7357703222462ce832b2fbb645dbcaba0649cded3", "http.get"}, {"http-marker", "233d593087b6b58ee84d6fe4cc2731c9b556da9c0b9b166648fd48c246803c6b", "http.get"}, {"tcp-marker", "eb1fd95d6b05339647f635b54488044b782271a0e7ca95cff3a3973f845654fc", "tcp.exchange"}, {"tls-marker", "d2b314eb779c734fbfd1382e2b2b7ea16b5a4554e16ecb0bdc81204d20779369", "tcp.exchange"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			source, err := os.ReadFile("../../testdata/sirius/" + fixture.name + ".lua")
			if err != nil {
				t.Fatal(err)
			}
			if got := fmt.Sprintf("%x", sha256.Sum256(source)); got != fixture.digest {
				t.Fatalf("fixture digest changed: %s", got)
			}
			for _, marker := range []string{"vulnerable", "clean", "unrecognized"} {
				for _, product := range []string{"Scribe fixture", "", "Other"} {
					for _, exhaustive := range []bool{false, true} {
						rt, err := NewNative(Options{Functions: map[string]scribe.Function{fixture.function: func(context.Context, scribe.Target, []any) (any, error) {
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
						idx, err := scribe.NewIndex([]scribe.Script{{ID: "http-marker", Dialect: scribe.Sirius, Source: source}})
						if err != nil {
							t.Fatal(err)
						}
						count := 0
						err = engine.RunSelected(context.Background(), idx, []scribe.Target{{Host: "fixture", Service: "http", Product: product}}, func(r scribe.Result) error {
							count++
							want := scribe.Unknown
							if marker == "vulnerable" {
								want = scribe.Vulnerable
							}
							if marker == "clean" {
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

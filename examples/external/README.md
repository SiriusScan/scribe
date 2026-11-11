# External-import acceptance gate

This is a separate Go module (`example.com/scribe/external-acceptance`) that
imports `github.com/SiriusScan/scribe` the way an outside consumer would. A
`replace` directive in [go.mod](go.mod) points at the repository root until a
tagged release exists; a real consumer would drop the `replace` and pin a
version.

The tests run the same native script ([testdata/http-header.lua](testdata/http-header.lua))
through the SDK and a freshly built `scribe` CLI against a controlled local
HTTP service, compare the structured output (ignoring elapsed time), and
cover cancellation, rules, limits, and error propagation. This is the
Phase 0 acceptance gate from the [roadmap](../../docs/roadmap.md); the CLI is
built with `GOPROXY=off` to prove the import works offline.

```sh
go test -race ./...
go vet ./...
```

From the repository root, `make acceptance` (also part of `make check`) runs
the same commands.

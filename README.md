# Sirius Scribe

**An embeddable Go runtime for Lua vulnerability scripts.**

Scribe runs selected scripts against host and service facts supplied by a caller.
Use it as a Go module inside an endpoint agent or scanner, or run the same engine
through the `scribe` CLI. It does not discover hosts, scan port ranges, fingerprint
services, consume job queues, or persist findings.

This is an initial working foundation. The native Sirius dialect and experimental
NSE profile have distinct contracts. **Full Nmap NSE compatibility is a roadmap
goal and has not been established.** See the [compatibility contract](docs/compatibility.md).

## Two script dialects

- **`sirius`**: a versioned Lua 5.4 contract with structured findings and explicitly
  registered, in-process Go capabilities. No subprocess is needed to call Go code.
- **`nse`**: an experimental Lua 5.4 compatibility profile for a documented subset
  of NSE rule/action behavior and helper APIs. Unsupported modules fail explicitly.
  This repository contains original fixtures, not Nmap's script corpus.

Both profiles use a pinned pure-Go Lua runtime, isolated state per invocation, and
finite execution budgets. The root package contains the scheduler and transport
types; `runtime/lua54` provides the interpreter implementations without exposing VM
types through the root API. Native Go capabilities remain trusted process code.

## Build and run

Requires Go 1.24 or later.

For the native demonstration, first run `go run ./examples/fixture` from a clone
in another terminal. The sample script recognizes that server's explicit marker;
it is an API demonstration, not a real-world CVE detector.

```sh
go install github.com/SiriusScan/scribe/cmd/scribe@latest

# Execute a native check against a known HTTP endpoint.
scribe --dialect sirius --script examples/scripts/http-header.lua \
  --host 127.0.0.1 --port 8080 --service http

# Execute an original NSE-shaped fixture, with no network discovery.
scribe --dialect nse --script examples/scripts/service-info.nse \
  --host 127.0.0.1 --port 8080 --service http --state open
```

CLI results are JSONL on stdout. Diagnostics go to stderr. Script failures produce
error results and a nonzero exit; a completed script with no findings is only an
execution outcome, not proof that a target has no vulnerabilities.

## Embed in Go

```go
native, err := lua54.NewNative(lua54.Options{
    Functions: map[string]scribe.Function{
        "my.protocol.check": myProtocolCheck, // Go function called in-process
    },
})
if err != nil { return err }

engine, err := scribe.New(scribe.Options{Concurrency: 4}, native)
if err != nil { return err }

return engine.Run(ctx, []scribe.Task{{
    Script: scribe.Script{
        ID: "my-check", Dialect: scribe.Sirius, Source: scriptSource,
    },
    Target: scribe.Target{Host: "example.test", IP: "192.0.2.10", Port: 443, TLS: true},
}}, func(result scribe.Result) error {
    return saveResult(result)
})
```

Imports are `github.com/SiriusScan/scribe` and
`github.com/SiriusScan/scribe/runtime/lua54`. The complete
[embedding example](examples/embed/main.go) registers a Go function and executes
the same public API used by the CLI. Hosts choose their capabilities; the core
does not install HTTP, filesystem, shell, or credential access implicitly.

## Design and adoption

- [Architecture and decisions](docs/architecture.md)
- [Native script API](docs/script-api.md)
- [NSE compatibility and limitations](docs/compatibility.md)
- [Sirius scanner and endpoint-agent integration](docs/integration.md)
- [Delivery roadmap and acceptance gates](docs/roadmap.md)
- [Research with pinned primary sources](docs/research/)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

The architecture follows the importable-module and CLI delivery model seen in
ProjectDiscovery's httpx, naabu, and Nuclei. Scribe does not depend on those scanner
engines. The [research memo](docs/research/go-patterns.md) records the actual API
patterns and their differences.

## Development

```sh
make check
make build
make compat   # measured NSE-fixture report -> compat/report.json
```

Tests use deterministic local services and original scripts. They cover execution,
limits, scheduling, dialect isolation, and the target-bound HTTP capability.
`make compat` measures the original NSE-shaped fixtures in `compat/` with pinned
digests and asserted outputs. Neither establishes compatibility with the 612-script
Sirius NSE catalog or deployment into a running Sirius scanner or endpoint agent.

## License

First-party code, documentation, and original examples are [MIT](LICENSE).
Dependencies retain their own licenses. No Nmap code, scripts, or libraries are
relicensed here; distributing a supported upstream corpus requires reviewing its
actual licenses. See [licensing research](docs/research/nse-runtime.md#mit-licensing-boundary).

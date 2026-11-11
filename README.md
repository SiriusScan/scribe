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

Diagnostics are retained in JSONL `output.logs` (up to 64 KiB per invocation);
`output.logs_truncated` marks discarded bytes. Capture includes `print`, `log`,
and the experimental stdnse diagnostic helpers, including on errors and skips.
Diagnostic text never supplies a verdict.

Use `scribe --check --dialect sirius --script script.lua` without a target
to compile and check literal requires and direct module member references.
The same check supports the existing experimental NSE subset. It does not
execute initialization, rules, actions, or network calls. A successful check
does not certify dynamic accesses or runtime behavior; dynamic requires fail.
Reports are JSONL with a nonzero exit on unsupported references or syntax errors.

`scribe --version` prints the module/build version and commit.
`make install` builds with the current Git revision embedded and installs into
`/usr/local/bin`; `PREFIX` and `DESTDIR` may override the destination.

HTTP mode: run `scribe serve --listen 127.0.0.1:8080`, then send
`POST /run` with `{"args":["--dialect","sirius","--script","examples/scripts/example.lua","--host","example.internal"]}`
(replace the script path with an installed script). Arguments use the same flags,
validation, defaults, and local script files as the CLI. Responses stream the same
JSONL records with `Content-Type: application/x-ndjson`. Validation failures return
400; execution failures remain structured result records under HTTP 200. Always
inspect execution status and verdict, and handle interrupted streams as incomplete.
Other routes return 404 and unsupported methods return 405.

This is a trusted-caller service: it has no authentication and permits caller-selected
local script paths and network targets. Keep it on loopback or behind an authenticated
proxy. Request bodies are limited to 128 KiB, with four concurrent requests (excess
requests return 503), and finite HTTP read/write timeouts. Client disconnects and
server termination cancel execution through the existing context path. There is no
queue or persistence. CLI help/version commands are not HTTP execution requests.

## apps01 HTTP deployment

Service URL: `http://192.168.123.22:18081/run` (POST). Port 18081 was
checked with `ss -ltnp`; the service binds only the LAN address. The host firewall
allows trusted LAN `192.168.123.0/24` and Activepieces network `172.22.0.0/16`.
This endpoint has no authentication; keep those access boundaries in place.

From this checkout on apps01, run `sudo env PATH="$PATH" make install-service`.
This installs the pinned checkout build and `deploy/scribe.service`, enables it
at boot, and restarts it. Subsequent `make install` restarts an active service;
`make restart-service` explicitly restarts it (both require system privileges).
The unit runs as `agi`, uses `/home/agi/Projects/scribe` as its working directory,
and restarts on failure. Adjust these paths/user for another host. Scripts must
exist on the server; its private `/tmp` is separate from caller `/tmp`.
Use `systemctl status scribe` and `journalctl -u scribe` for diagnostics.

Example request body (script path relative to the service working directory):
```json
{"args":["--dialect","sirius","--script","examples/scripts/http-header.lua","--host","127.0.0.1","--port","8080"]}
```
The response is newline-delimited JSON, with `schema_version`, script identity
and digest, target, execution `status`, explicit `verdict`, `output`, optional
`error`, and elapsed time. HTTP 400 means request/pre-execution rejection; 503
means capacity exhausted. HTTP 200 only means result streaming started.

Activepieces pass/fail rule: require a complete stream and the expected number
of records, each with `status == "completed"`. Only explicit `vulnerable` is a
positive detection; only explicit `not_vulnerable` is a negative detection.
`unknown`, errors, skips, empty output, and interrupted streams are inconclusive
and must never become a clean bill of health or a positive detection.

Run `make smoke-http` in a separate shell while the service is running. It starts
local ephemeral HTTP/TCP fixtures, POSTs real Sirius scripts to the installed
service, asserts all three verdicts and the exact `tcp.exchange` banner, then
cleans up. Override `SCRIBE_URL` if needed. This verifies the HTTP execution
boundary, not the full vGPT workflow or Sirius scanner/agent integration.

The external acceptance module retains its local `replace` so `make check`
tests this checkout and its CLI offline, including changes before a release.


HTTP callers may supply inline source with `scripts`. Each entry requires a
nonempty `id` and `source`; `--script` is optional when inline scripts are
present. File and inline scripts may be combined (64 total). The existing
128 KiB JSON body cap applies, including JSON escaping; each source also obeys
the same source size limit as files. Inline scripts use the selected dialect,
arguments, validation, digest calculation, and JSONL result contract.
Invalid Lua produces a structured execution error. Require a complete response
and inspect execution status and explicit verdict; HTTP 200 is insufficient.

```sh
curl --fail-with-body http://192.168.123.22:18081/run \
  -H 'Content-Type: application/json' \
  --data '{"args":["--dialect","sirius","--host","example.internal"],"scripts":[{"id":"check.lua","source":"return {api_version=1,action=function() return {verdict=\"unknown\"} end}"}]}'
```

Scanner adapter preparation: --facts endpoints.json and POST /run's facts array
supply multiple known endpoints with service, product and version facts. Every
selected script runs on every endpoint. See [script API](docs/script-api.md)
for the input contract and the exported report.Map version 1 evidence envelope.
This does not establish app-scanner integration acceptance.


### Throughput controls

The SDK and CLI use bounded target lookahead with per-run host controls:
`--host-concurrency 2`, `--host-interval 100ms`, `--host-error-budget 3` and
`--strategy host-spray` (default `script-spray`). `--facts-jsonl FILE` streams
endpoint objects from a bounded server-local regular file. A hint exclusion or
exhausted host budget produces a skipped/unknown JSONL record with a reason;
it does not establish a negative vulnerability result. Lua code-template caching
preserves fresh invocation state, and HTTP reuse is partitioned by logical
hostname, fixed IP, port and TLS. See [engine throughput](docs/engine-throughput.md)
for SDK options, cancellation/streaming behavior and measured before/after results.

Consume ping++ PR #1 `pingpp.scan/v1` JSONL with
`scribe --dialect sirius --script check.lua --pingpp-jsonl scan.jsonl`.
The importable `adapter/pingpp.NewReader(r).Next` feeds `RunTargetStream` and
existing selection. Only attempted confirmed-open endpoints are scheduled;
strong/exact endpoint claims supply unambiguous service/product/version facts.
No eligible endpoints means no results, never a clean assessment. Upstream target
errors fail the stream. Input is bounded to 4 MiB/document and 65536 documents.

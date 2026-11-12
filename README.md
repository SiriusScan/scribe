# Sirius Scribe

**An embeddable Go runtime for Lua vulnerability scripts.**

Scribe runs selected scripts against host and service facts supplied by a caller.
Use it as a Go module inside an endpoint agent or scanner, or run the same engine
through the `scribe` CLI. It does not discover hosts, scan port ranges, fingerprint
services, consume job queues, or persist findings.

Version v0.2.0 provides an importable SDK. The native Sirius dialect and experimental
NSE profile have distinct contracts. **Full Nmap NSE compatibility has not been established; native Sirius capabilities
are the development priority.** See the [compatibility contract](docs/compatibility.md).

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

## Go SDK v0.2.0

Import `github.com/SiriusScan/scribe` for `Options`, `New`, tasks and results.
Register an explicit runtime from `runtime/lua54`; the root package has no CLI
flags, logging side effects or interpreter types. `Engine.Run` accepts tasks and a
serial callback; `Batch` collects results in completion order; `Stream` consumes
endpoint facts with bounded lookahead and smart selection. `RunSelected` handles
a known endpoint slice. Existing entry points remain supported.

See [executable godoc examples](sdk_example_test.go) for a single invocation,
ping++ JSONL batch input, and selection with skip reasons. `adapter/pingpp`
preserves supplied endpoint claims; it does no fingerprinting. Producers own
blocking input interruption. Pass a context to every run; inspect both the
returned error and every record's status/verdict. Unsupported calls and selection
skips remain unknown. A callback failure can prevent terminal delivery.

The public extension contracts are `Runtime` and `Function`; capabilities and
adapters remain opt-in packages. Selection metadata is private implementation.
The local [integration test](sdk_integration_test.go) feeds a pinned JSONL fixture
through selection and parallel HTTP execution and checks unsupported coverage.
This is SDK fixture evidence, not full Sirius scanner/agent acceptance.

Declarative selection metadata may use a `match` block, for example:
`-- scribe: {"match":{"products":["Acme"],"services":["http"],"min_version":"1.2.0","max_version":"2.0.0"}}`.
Fields combine with AND; string arrays use case-insensitive OR. `any_of` and
`all_of` contain nested match blocks (at most eight levels). Inclusive version
bounds require semantic versions; missing or invalid target versions cannot match.
`banner_regex` uses Go regular expressions against caller-supplied `Target.Banner`.
Ports are advisory. Missing or mismatched required facts yield skipped/unknown.
A clean verdict with a match block requires a matching product declaration;
service, port and banner alone cannot establish product identity. Direct engine
runs enforce the same gate. Legacy metadata keeps its previous behavior.

Planner identification facts include target `cpe` (an array of exact identifiers)
and `confidence` (0–1; zero means unspecified). Match metadata accepts the same
fields: CPE alternatives use OR, and confidence is a minimum threshold. These
constraints combine with existing fields using AND. Low confidence skips include
a threshold reason; exhaustive execution still preserves the clean-verdict gate.

Selected runs with `on_unknown:"probe"` can collect a passive TCP banner, then
HTTP HEAD response headers, or TLS handshake facts when the target has TLS set.
Results include `cert_subject`, `alpn`, and `tls_version`. Certificate collection
does not validate trust. Probes offer HTTP/1.1 ALPN, have a 250 ms endpoint budget
and an 8 KiB response input bound. Successful HTTP identification uses confidence
0.8. Probe failures are cached, as are successes, within each run up to MaxHosts.
Caller product/version facts are preserved. CPEs remain caller supplied.

Direct SDK Run enables this same bounded cache with `Options{PlannerProbes:true}`;
the default performs no probes. UDP, automatic TLS detection, certificate trust
assessment, HTTP/2, redirects, and CPE inference remain unsupported. These checks
provide build/runtime evidence, not scanner or Activepieces integration acceptance.

Planner probes use a 250 ms endpoint budget, an 8 KiB response header/banner limit, TLS detection on common HTTPS ports and a handshake attempt on silent TCP endpoints. Certificate subjects, TLS version and ALPN are observations without certificate trust validation. HTTP HEAD redirects allow at most three requests on the same host and port. Pinned nginx, Apache and OpenSSH fingerprints infer CPE hints; these are not vulnerability verdicts. CLI JSONL and POST /run expose facts and confidence under `target`, and planner skip reasons under `output.skip_reason`. Missing verdicts remain unknown. UDP and arbitrary product inference remain unsupported.

### Runnable Go SDK quickstart

Import `github.com/SiriusScan/scribe` and `github.com/SiriusScan/scribe/runtime/lua54`.
Construct a native runtime with `lua54.NewNative(lua54.Options{})`, then pass it
to `scribe.New(scribe.Options{Concurrency: 2}, runtime)`. Handle both errors.
Each task supplies a script with explicit `Dialect: scribe.Sirius` and target facts.

The executable godoc examples in [sdk_example_test.go](sdk_example_test.go) show:

- `Engine.Run(ctx, tasks, sink)` delivers each result to a caller-owned callback.
- `Engine.Batch(ctx, tasks)` collects a finite task batch.
- `Engine.Stream(ctx, index, nextTarget, sink)` applies selection to a bounded target stream.

Run all three with `go test -v -run '^ExampleEngine_' .`. The Stream example
builds an immutable `NewIndex` and demonstrates a service exclusion. Use declarative
`-- scribe: {"match":{"services":["http"]}}` metadata for new scripts.
See [examples/external](examples/external) for a runnable separate-module consumer.
Always check execution status and explicit verdict separately: completed unknown,
skips, errors and missing records are inconclusive. Caller facts take precedence
when optional planner probes fill missing identification.

SNMP planner identification is disabled by default. SDK callers may set
`Options.SNMPCommunity`; CLI and HTTP callers may pass `--snmp-community VALUE`.
The policy uses exactly one supplied v2c community (maximum 255 bytes), with no
credential guessing. It applies to planner probes on UDP port 161 or supplied
`snmp` service endpoints and identifies only the service, never product or verdict.
Communities are credentials; use trusted callers and avoid retaining request args.
See package godoc for API versioning and CHANGELOG.md for release history.

v0.6.0 planning and limits: `--plan` emits skipped/unknown JSONL records for
all script/target pairs. `output.skip_reason` reports exclusions or `plan: would
run`; dynamic Lua rules are not evaluated and no probes or actions execute.
Library callers set `Options.Plan` with the existing Run/Batch/Stream methods.
`--timeout` (default 5s) bounds each invocation; library callers can set
`Options.ScriptTimeout` to tighten runtime deadlines. `--concurrency` (default 4,
maximum 256) bounds active scripts. `--global-interval 100ms` spaces starts across
hosts within each run (`Options.GlobalInterval`); these limits are per run, not
shared across independent Engine calls or HTTP requests. POST /run accepts these
same flags in its args array. Planning records never establish a verdict.

Pinned fingerprint rules additionally recognize IIS, lighttpd, Tomcat, Jetty,
Postfix, Exim, vsftpd, ProFTPD, MySQL/MariaDB version banners, Redis INFO version
lines and Dropbear SSH banners. These produce identification/CPE hints only.
Passive probes do not actively request database or Redis identification; callers
can use package fingerprint on protocol payloads they already collected.

### Result summaries for library consumers

Import `github.com/SiriusScan/scribe`. After collecting SDK results, use
`unique := scribe.Deduplicate(results)` and
`summary := scribe.Summarize(unique)`. The executable godoc example
`ExampleSummarize` demonstrates this API. Deduplication compares full evidence
except elapsed time; conflicting results remain separate. Memory scales with
the supplied result slice. Streaming consumers can call `Summary.Add` without
retaining execution records.

CLI `--summary` appends a schema-version-1 record with `type: "summary"`,
`total`, `by_status`, `by_verdict`, and `by_skip_reason`. Pass the same flag
in POST /run args. Counts include every delivered record (no implicit dedupe).
Only completed explicit verdicts count as vulnerable or not_vulnerable.
A summary describes delivered evidence; it does not prove stream completeness.
Service shutdown cancels execution and allows up to five seconds for handlers
to drain terminal records before closing connections.

Module inventory: `scribe --dialect sirius --script path/to/check.lua --list-modules`
prints one JSONL object per script with `script`, `dialect`, `match`, and
`warnings`. It validates metadata without executing scripts or probing targets.
Invalid metadata fails the invocation; missing match blocks produce lint warnings.

### Embedding checklist

Use the runnable [embed example](examples/embed) for callback handling and
per-run admission limits. GlobalInterval and HostInterval pace task starts, not
network requests inside a script. ModuleConcurrency limits active invocations by
exact dialect and script ID; separate Run calls have independent limits.
Keep the result sink open through cooperative cancellation and verify complete
terminal records before assessing a batch. Job envelopes must supply exact
capability grants; missing grants deny calls.

The pinned `testdata/sirius/http-security-headers.lua` checks CSP and nosniff
configuration on successful HTTP responses. It is an original configuration
fixture, not a CVE detector; non-200 responses remain unknown. Its declared
fixture product must be replaced with an appropriate reviewed deployment policy
before operational use.

Since v1.56.0, `--pingpp-jsonl` also preserves upstream `cpe` hints from accepted
strong/exact endpoint product claims. Hints are sorted and deduplicated, and
product or version conflicts suppress them. Existing CPE planner constraints can
select these enumeration facts; CPEs never establish a vulnerability verdict.

tcp.exchange(payload, byte_count) optionally reads exactly 1–65536 bytes across
fragmented TCP/TLS records. The second argument is a Lua integer. Omitting it
retains single-chunk reads. The existing five-second/context deadline covers the
whole exchange; premature EOF fails without returning partial successful data.
This supports fixed-length protocol replies without treating socket read
boundaries as message boundaries.


v1.58.0 adds delimiter-framed tcp.exchange replies: a string second argument
reads through that delimiter (1..256 bytes), inclusive, within the existing 64 KiB
reply ceiling and five-second deadline. Missing delimiters and premature EOF are
errors without partial successful output. Connection setup and verified TLS use
the existing path. Multi-exchange sessions remain follow-up work; Phase 3 stays
paused. Controlled loopback evidence is separate from live consumer acceptance.

For a line-framed reply, use `sirius.call("tcp.exchange", "PING\r\n", "\r\n")`.
The returned `data` includes the delimiter. This performs one exchange on one
connection; it does not create a persistent session.

TCP sessions (v1.59.0): `sirius.call("tcp.exchange", {{"", "\r\n"},
{"PING\r\n", "\r\n"}})` reads a greeting then sends a command on the same
connection. The result contains `replies`, in order, with each exchange's `data`
and `eof`; TLS metadata remains at the top level. Sessions accept 1..16 exchanges,
each using the existing optional byte-count/delimiter selector and 64 KiB bounds.
All steps share one five-second deadline and verified TLS setup. Any failed step
returns an execution error without partial successful output. Missing verdicts
remain unknown.


v1.60.0 adds original pinned Cherokee HTTP Server identity and CPE hints through
the shared fingerprint/planner mapper. Boundary tests reject misleading prefixes
and malformed versions; versionless identity retains an unknown version. Shared
selection tests preserve caller authority and conservative clean gates. No
throughput claim; live consumer persistence remains separate. Phase 3 stays paused.

v1.61.0 uses one invocation-owned 4 KiB read buffer per TCP/verified TLS
connection. Delimiter reads retain subsequent frames for later exact-length,
delimiter or default reads. Existing reply limits, session validation, deadline
and all-or-error results remain intact. A deterministic coalesced-frame regression
checks ordered mixed framing and one underlying read for a 3 KiB reply sequence.
This removes per-byte socket reads; no end-to-end throughput claim is made.
Local transport evidence is separate from live consumer persistence. Phase 3 stays paused.

Module scheduling: CLI and POST /run args accept `--module-concurrency N`
and `--module-interval 100ms`. Limits apply per exact dialect/script ID within
a run alongside global and host limits. Zero uses global concurrency or disables
module pacing respectively. For example, `--concurrency 8 --module-concurrency 2
--module-interval 100ms` limits each module while allowing other modules to run.


## v1.65.0 — write-only session commands

v1.65.0 adds write-only tcp.exchange steps: integer read selector 0 sends the
payload and returns empty data with eof=false without reading. This supports
commands without replies within existing bounded TCP/verified TLS sessions.
Write failures still discard session output; all steps validate before dialing.
Existing deadlines, grants and reply limits apply. Phase 3 stays paused; local
transport evidence is separate from live consumer persistence acceptance.

For example, `sirius.call("tcp.exchange", {{"PING", 0}, {"", 4}})` sends
PING without waiting, then reads exactly four bytes on the same connection.


v1.66.0 adds bounded read-to-EOF tcp.exchange replies with integer selector -1.
Use `sirius.call("tcp.exchange", "REQUEST\r\n", -1)` for close-delimited
responses. Empty EOF succeeds with eof=true; replies above 64 KiB and transport
errors fail without partial output. The existing verified TLS/session path and
shared five-second deadline apply. Local socket evidence is separate from live
consumer persistence acceptance. Phase 3 stays paused.


v1.67.0 adds `udp.exchange` through the existing native capability registry and
CLI/POST runner: `sirius.call("udp.exchange", "REQUEST")` sends one datagram and
returns `{data=...}` from the connected explicit UDP endpoint. Payload and reply
are bounded to 65507 bytes, with one five-second deadline tightened by context.
Empty datagrams are valid; transport errors produce no successful output.
Scripts must validate protocol correlation and explicitly decide verdicts. SDK
users opt in with capability/udpcap.Function and exact udp.exchange grants.
This closes the native UDP transport gap; it adds no discovery or retries.
Local socket evidence is separate from live consumer persistence acceptance.
Phase 3 stays paused.


v1.68.0 adds bounded UDP sessions: `sirius.call("udp.exchange", {"FIRST", "SECOND"})`
sends 1..16 string datagrams sequentially on one connected endpoint and returns
an ordered array of `{data=...}` replies. The source port remains stable. All
payloads validate before dialing; one five-second context-bounded deadline covers
the entire session. Any failed exchange discards all results. Single-string calls
retain their existing result shape. Scripts remain responsible for correlation;
no retries or discovery are added. Local socket evidence is separate from live
consumer persistence acceptance. Phase 3 stays paused.


v1.69.0 rejects duplicate endpoint subjects within a pingpp.scan/v1 document
before returning any targets, including conflicting states and equivalent IPv6
spellings. Distinct ports and transports remain independent; separate documents
remain independent. This prevents duplicate script scheduling from ambiguous
enumeration input. No throughput claim; live consumer persistence remains
separate and Phase 3 stays paused.


v1.70.0 adds an optional integer reply ceiling to `udp.exchange` (1..65507):
`sirius.call("udp.exchange", "REQUEST", 512)`. The same ceiling applies to every
reply in a session. Oversized datagrams fail without partial output; a one-byte
sentinel detects truncation. Defaults, exact grants, source-port stability and the
shared context-bounded five-second deadline remain intact. This extends bounded
raw protocol execution without discovery or retries. Local socket evidence is
separate from live consumer persistence acceptance. Phase 3 stays paused.


v1.71.0 requires each selection metadata declaration to contain exactly one JSON
value; trailing objects, values and malformed text fail index construction.
Index construction scans source lines incrementally instead of allocating a full
line slice. Behavioral fixtures retain product selection for large sources and
LF/CRLF/unterminated final lines. No public API change or throughput claim.
Live consumer persistence remains separate; Phase 3 stays paused.



v1.72.0 makes planner probe eligibility respect observed contradictions before
requesting missing facts. Required branches and impossible alternatives suppress
unnecessary probes; viable alternatives and improvable confidence retain them.
Probes never replace caller facts or establish clean verdicts. Behavioral tests
cover nested branches and missing product evidence. No public API change or
measured throughput claim. Live consumer persistence remains separate; Phase 3
stays paused.


v1.73.0 canonicalizes pingpp.scan/v1 endpoint claim subjects before indexing,
so equivalent IPv6 spellings combine accepted identity evidence. Exact port and
transport isolation, confidence filtering and conservative conflict handling remain
intact. Host-wide and malformed subjects supply no identity. No public API change
or throughput claim; live consumer persistence remains separate. Phase 3 paused.


v1.74.0 reuses prepared selection metadata for repeated direct Engine.Run scripts
within each run, keyed by source SHA-256 and bounded by Window entries. Excess
unique sources retain ordinary validation and execution. Endpoint matching and
clean gates remain invocation-specific; invalid metadata retains execution errors.
This extends selected-run metadata reuse to direct SDK batches. No public API
change or measured throughput claim. Live consumer persistence remains separate;
Phase 3 stays paused.


v1.75.0 makes direct SDK batch identification probes demand-driven through the
existing matcher. Satisfied facts and observed contradictions avoid network I/O;
missing eligible identity facts retain bounded cached probes. Scripts without
match declarations retain explicit PlannerProbes behavior. Conservative clean
gates and per-run cache ownership remain intact. No throughput claim or public
API change. Live consumer persistence remains separate; Phase 3 stays paused.

v1.76.0 avoids redundant full-source snapshots while preparing metadata for direct
SDK execution. Public indexes and selections retain owned source snapshots;
endpoint selection and conservative verdict gates remain unchanged. This removes
an allocation path, with no measured throughput claim.

v1.77.0 exposes field-specific planner skip diagnostics for service, transport,
version, banner and CPE constraints through the shared nested matcher. Missing
facts remain distinct from observed mismatches; mixed alternative failures retain
the general reason. Selection and false-clean gates remain conservative. No public
API change or throughput claim. Live consumer persistence remains separate;
Phase 3 stays paused.

Planner banner probes assemble fragmented first lines on TCP and TLS within the
existing 50 ms banner window, 250 ms endpoint budget and 8 KiB response ceiling.
This supports split protocol greetings without adding retries or discovery.
Fingerprint observations remain separate from vulnerability verdicts.


v1.79.0 keys per-run planner probe observations by structured endpoint and service
hint. A cached unsupported UDP probe no longer suppresses later DNS/NTP/SNMP
eligibility on the same endpoint with a different supplied service. Failures remain
cached per key and cache capacity stays bounded. Caller facts and conservative
verdict gates remain authoritative. No public API change or throughput claim;
live consumer persistence remains separate and Phase 3 stays paused.


v1.80.0 gates merged planner probe confidence and CPE hints on agreement with
both caller product and version. Conflicting versions retain caller identity and
transport/banner observations without importing incompatible identity evidence.
Unrecognized banners no longer establish product confidence. Regression tests
cover agreeing, absent and conflicting versions/products and caller evidence
authority. No public API change or throughput claim; live consumer persistence
remains separate and Phase 3 stays paused.


v1.81.0 moves direct SDK batch declarative exclusions ahead of scheduler host
admission, reusing prepared metadata and the existing skip-record path. Excluded
endpoints no longer exhaust MaxHosts or occupy pending worker capacity. Probes
still precede final matching; exhaustive execution retains host bounds and clean
gates. Regression coverage runs twenty endpoints with one host slot, requiring
complete skipped/unknown records and the one eligible action. No public API
change or measured throughput claim. Live consumer persistence remains separate;
Phase 3 stays paused.


v1.82.0 removes pending-window shifts when dispatch selects the queue head.
Consumed references are cleared before advancing the slice; non-head dispatch
retains stable ordering and host-spray fairness. A 4096-action regression pins
ordered completed/unknown output alongside existing cancellation completeness
coverage. This reduces queue movement; no measured throughput claim is made.
Live consumer persistence remains separate; Phase 3 stays paused.


v1.83.0 adds optional min_version_exclusive/max_version_exclusive match flags.
They require their corresponding semantic-version bounds; empty ranges fail
metadata validation. Existing bounds remain inclusive by default. Exclusive
boundaries share nested selection, probe eligibility and version skip diagnostics;
missing versions never establish clean identification. No throughput claim.
Live consumer persistence remains separate; Phase 3 stays paused.

For a fixed release boundary, use for example
`"match":{"products":["widget"],"max_version":"2.0.0","max_version_exclusive":true}`
in the existing script metadata declaration. Version 2.0.0 is excluded; earlier
semantic versions match. `min_version_exclusive` works analogously. Each flag
requires its corresponding bound. Omitted flags preserve inclusive matching.

The native `http.head` capability accepts an origin-form path, for example
`sirius.call("http.head", "/status")`, and returns the same status/header shape
as `http.get` with an empty body. Redirects are not followed. SDK users register
`Client.HeadFunction` under the exact `http.head` grant.

For a single library call from ping++ JSONL into the planner, use
`pingpp.Run(ctx, engine, index, input, sink)`. It reuses the bounded reader and
`Engine.RunTargetStream`; register Lua runtimes/capabilities on the engine as
usual. The caller owns interruption of blocking input. Require a nil returned
error and complete terminal records before assessing explicit verdicts: results
from earlier documents can precede a later input or sink failure.


v1.94.0 rejects empty script indexes before requesting streaming targets. This
prevents an invalid plan from blocking on caller-owned ping++ input or triggering
producer I/O. Shared planner tests cover streaming and draining paths; the
pingpp.Run regression requires zero reads and zero result callbacks. Existing
nonempty selection, cancellation and verdict semantics remain authoritative.
No public API change or throughput claim. Live consumer persistence remains
separate; Phase 3 stays paused.

HTTP scripts may supply explicit request headers with either capability:
`sirius.call("http.get", "/status", {["X-Probe"] = "marker"})` (also
`http.head`). Headers are invocation-local string values, limited to 64 entries
and 8 KiB combined names/values. Invalid names, control characters, duplicate
case-insensitive names and authority/framing/proxy headers fail before network
I/O. The existing fixed endpoint, verified TLS, response limits and redirect
policy apply. Responses remain evidence; scripts must explicitly decide verdicts.


v1.96.0 bounds pingpp.scan/v1 document admission to 65,536 endpoints and
262,144 claims before indexing or target conversion, including direct SDK calls.
Oversized documents fail atomically with zero targets; JSONL byte limits remain
in force. Behavioral tests cover both SDK ceilings. No public API change or
throughput claim. Live consumer persistence remains separate; Phase 3 stays paused.


v1.97.0 adds native http.post for body-dependent HTTP probes through the shared
HTTP client and CLI/POST runner. Use
`sirius.call("http.post", "/probe", "marker=value", {["Content-Type"]="application/x-www-form-urlencoded"})`.
The string request body is limited to 1 MiB; optional headers follow GET/HEAD
policy. Endpoint confinement, verified TLS, redirects-as-evidence and response
limits share the existing path. SDK callers register Client.PostFunction with
the exact http.post grant. The additive method preserves existing signatures;
the API fixture was reviewed and updated. Behavioral loopback and real Lua CLI
tests require response evidence, including non-2xx responses. Missing verdicts
remain unknown. No throughput claim; live consumer persistence remains separate.
Phase 3 stays paused.

v1.99.0 adds native `http.put` with the same path, body and optional header
arguments as `http.post`. SDK users register `Client.PutFunction` with exact
`http.put` grants. Requests and responses retain the shared finite HTTP limits.

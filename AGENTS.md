# Working on Sirius Scribe

Scribe executes Lua vulnerability scripts against supplied host/port facts. Keep
discovery, orchestration queues, persistence, and service fingerprinting in callers.

- Keep the root Go package importable, silent, and independent of CLI flags.
- Use explicit `sirius` and `nse` dialect selection. Never silently fall back.
- Keep interpreter types out of the root API. Each invocation owns its Lua state.
- Keep finite limits around compilation, rules, actions, I/O, and output conversion.
- Never operate a Lua state concurrently or use a cancellation goroutine to mutate it.
- Errors, unsupported APIs, skips, and empty output must never become clean bills of
  health or positive vulnerability findings.
- Support claims need pinned script/API fixtures. Original NSE-shaped fixtures do
  not establish compatibility with an upstream script corpus.
- First-party code and original examples are MIT. Do not copy or vendor Nmap
  scripts/libraries under that license. Preserve third-party license notices.
- Add focused behavioral tests for runtime, scheduling, and protocol changes.
- Before delivery run `go test -race ./...`, `go vet ./...`, and
  `CGO_ENABLED=0 go build ./cmd/scribe`. Keep build evidence separate from actual
  Sirius scanner/agent integration acceptance.
- Do not upgrade golua beyond v0.1.2 without deliberately reviewing the Lua
  language baseline: later upstream releases target Lua 5.5.

<!-- apps01:surfaces:start -->
## Development environment

Project: Scribe
Host: apps01

No development surfaces are assigned.

These assignments document intended access; they do not provision credentials or enforce infrastructure permissions. Keep secrets outside the repository. Use credential references, inspect shared resources, and avoid interrupting other projects.
<!-- apps01:surfaces:end -->

Sirius is the MVP superset direction. Extend native capabilities as needed;
do not pursue NSE library coverage. Keep execution status separate from explicit
verdicts; missing verdicts remain unknown.

HTTP mode lives in cmd/scribe and delegates to the CLI run/result path. Preserve
JSONL execution status/verdict semantics across transports; HTTP 200 alone does
not indicate successful execution or a vulnerability verdict. Keep request size,
concurrency and transport timeouts bounded. Default to loopback; caller-selected
scripts and targets require trusted access. Keep HTTP concerns out of the root API.

## apps01 Scribe service

The trusted Activepieces endpoint is `POST http://192.168.123.22:18081/run`.
Deploy with `sudo env PATH="$PATH" make install-service`; the checked-in
`deploy/scribe.service` runs as agi, starts at boot and restarts on failure.
Reinstalling with `make install` restarts an active service. Check `ss -ltnp`
before changing its port. Preserve LAN/Activepieces firewall restrictions.
Requests are `{"args":["--dialect","sirius", ...]}` using CLI flags and
server-local script paths. Responses are JSONL execution records, including
status and verdict. Require a complete stream and completed execution; only
explicit vulnerable/not_vulnerable verdicts establish positive/negative results.
Unknown, errors, skips, and missing results are inconclusive regardless of HTTP
200. Run `make smoke-http` from another shell for the three-verdict and TCP banner
fixture checks; this does not establish full vGPT workflow acceptance. See README
for the complete request/response and operational contract.

Scanner adapter contract: keep product/version caller-supplied; facts arrays
expand selected scripts across endpoints. Preserve report envelope v1 evidence
and conservative assessments. Cancellation must emit terminal queued-task records
while the result sink remains available; missing transport records are inconclusive.

Embedded jobs use package job schema v1 and the existing report envelope. Missing
job grants deny all registered capability calls; grants match exact function
names. Keep typed runtime denial errors and conservative report semantics. Job
limits may tighten, never enlarge, configured runtime ceilings. Legacy nil Task
grants retain SDK compatibility; do not use that convention in job envelopes.

Endpoint-local SDK capabilities live in capability/localcap and are opt-in.
Keep exact local.file.stat/read, local.process.list and local.package.list grants.
Confine file access with os.Root, require regular files, and bound reads and
inventory enumeration. Callers must select trusted local filesystems; kernel
filesystem calls are not context-interruptible. Unsupported inventory platforms
return errors, never empty successful inventories. Never add a command runner.
Version() reports module metadata; an embedder's VCS revision is not Scribe's.

Engine hardening checks: `make check` runs the race suite, including the original
Sirius verdict corpus in testdata/sirius and bounded batch load/recovery tests,
plus Windows/Darwin amd64 CLI cross-compilation. Cross-compilation is build
 evidence only, not platform runtime or scanner integration acceptance.

Planner policy: preserve opt-in StrictIdentification for legacy callers and enforce
declared matching products for clean verdicts. Exhaustive runs retain the clean
gate and mark only completed explicit verdicts as planner misses. Passive probes
are selected-run scoped, bounded and cache failures; never replace supplied facts.
Probe coverage currently excludes TLS, UDP and HTTP headers.

Planner probes use a 250 ms endpoint budget, an 8 KiB response header/banner limit, TLS detection on common HTTPS ports and a handshake attempt on silent TCP endpoints. Certificate subjects, TLS version and ALPN are observations without certificate trust validation. HTTP HEAD redirects allow at most three requests on the same host and port. Pinned nginx, Apache and OpenSSH fingerprints infer CPE hints; these are not vulnerability verdicts. CLI JSONL and POST /run expose facts and confidence under `target`, and planner skip reasons under `output.skip_reason`. Missing verdicts remain unknown. UDP and arbitrary product inference remain unsupported.

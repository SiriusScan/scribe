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
Probe coverage includes TCP, TLS, HTTP headers and bounded DNS/NTP UDP identification.

Planner probes use a 250 ms endpoint budget, an 8 KiB response header/banner limit, TLS detection on common HTTPS ports and a handshake attempt on silent TCP endpoints. Certificate subjects, TLS version and ALPN are observations without certificate trust validation. HTTP HEAD redirects allow at most three requests on the same host and port. Pinned nginx, Apache and OpenSSH fingerprints infer CPE hints; these are not vulnerability verdicts. CLI JSONL and POST /run expose facts and confidence under `target`, and planner skip reasons under `output.skip_reason`. Missing verdicts remain unknown. Arbitrary product inference remains unsupported.

Planner transport regression fixtures live in cmd/scribe/planner_transport_test.go;
keep CLI and POST /run assertions shared and require complete JSONL streams.
BenchmarkPlannerExecution in runtime/lua54 verifies actual action output and
completed/skipped counts for 512-pair selected and unfiltered workloads.
Record benchmark environment and samples in docs/roadmap.md; selection pair
counts alone do not establish execution throughput.

UDP planner probes support correlated DNS root NS queries and NTP client queries
on standard ports or explicitly supplied dns/ntp services. They share the 250 ms
budget and 8 KiB response ceiling, infer service only, and never infer a product
or verdict. SNMP v2c identification requires explicit Options.SNMPCommunity / --snmp-community; empty disables it. Never guess communities or promote sysDescr to a product/verdict.
Corpus metadata lint fails missing match blocks under the default strict test; invalid metadata fails. Preserve fixture verdicts with declared matching caller facts.

Public API declarations are pinned in testdata/api-signatures-v1.txt across
importable first-party packages, including platform source variants. Update with
SCRIBE_UPDATE_API=1 only after compatibility review. Phase 3 remains paused.

Post-v1 hardening: reuse BenchmarkPlannerExecution for the 32 × 16 executed-Lua
matrix; report verified actions/s and raw samples, and avoid performance claims
from runs overlapping fuzz/load work. Script-spray stops at its first eligible
pending task; host-spray retains its fairness scan. FuzzParallelPlanner seeds run
in the race suite; run explicit bounded fuzz campaigns for planner/engine changes.
Phase 3 remains paused.

v1.0.2: table-library builtin Go functions are immutable shared values; library
 tables remain invocation-owned and populated through accounted SetEnv calls.
Never share mutable library tables. FuzzMixedFailures covers exact grants, Lua
errors and sink error propagation; adapter/pingpp FuzzReader covers mixed wire
input. pingpp.scan/v1 already has a pinned adapter and CLI path: extend it rather
than creating a second mapper. No ping++ schema/repository change is required.

`make acceptance-local` composes controlled local HTTP/TLS, external SDK/CLI
cancellation and pingpp.scan/v1 fixture checks. SDK JSONL disk round trips are
local persistence evidence only; real Sirius/vGPT storage acceptance is separate.

SSH listener acceptance is included in make acceptance-local and requires pinned
OpenSSH service/product/version observations from a controlled loopback socket.
The 2026-11-11 local consumer access audit is recorded in docs/roadmap.md;
directory readability does not establish a usable pinned ping++ wire emitter.

v1.1.0 expands original pinned Caddy/OpenResty/Pure-FTPd/Sendmail observations
and product-specific false-clean guards across HTTP, SSH, FTP, SMTP and database
families, including TLS-marked endpoints. TLS alone never identifies a product.
The ping++ emitter remains a follow-up; use the pinned Scribe adapter fixtures.
Phase 3 remains paused.

The optional real emitter acceptance uses PINGPP_REPO (default local nested checkout), cmd/pingpp-scan at pingpp commit 2c397a1. It verifies TCP observations through the adapter, not execution or workflow persistence. Phase 3 remains paused.

v1.4.0 local cancellation/persistence acceptance uses a fake consumer JSONL report
store, requires all active/queued terminal records after cooperative cancellation,
and reopens synced evidence to EOF. This is local persistence evidence only.
Planner product skips distinguish missing and mismatched identification; retain
conservative clean gates and caller identity authority. Phase 3 stays paused.

v1.5.0 adds per-run ModuleConcurrency keyed by exact dialect and script ID;
zero uses global concurrency. Retain bounded active-only module accounting and
host/global pacing. examples/embed documents cooperative deadlines and limits.
Phase 3 remains paused.

v1.6.0 broadens combined matcher/dialect policy matrices and reuses the verified
executed-Lua benchmark with ModuleConcurrency 0/1. Preserve complete counts and
action outputs; shared-host samples make no speedup claim. Planner and mixed
failure fuzz campaigns run sequentially with race instrumentation and finite
budgets. Live Sirius workflow persistence remains separate from pinned real
ping++ emitter-to-Lua local acceptance. Phase 3 stays paused.

v1.7.0 documents Engine.Run serialized completion-order callbacks and sink
backpressure; retain cancellation/drain and sink error behavior. Lua TCP edge
fixtures require unknown partial-read results and error/cancelled transport
failures. POST inline scripts reuse runScripts; do not introduce a second runner.
Phase 3 remains paused.

v1.8.0 pins parallel diagnostic isolation across shared compiled Sirius code.
Keep logs invocation-owned, bounded and retained on action failure. Existing
log capture, --check and --version are reused. Phase 3 remains paused.

v1.9.0 pins Sirius verdict field types and an original HTTP marker corpus script
with a SHA-256 fixture assertion. Keep its normal/exhaustive product skip reasons
and false-clean guards in acceptance-local. This registered-response fixture is
local API evidence, not upstream corpus or live workflow acceptance. Phase 3 stays paused.

v1.10.0 extends nested all_of/any_of selection coverage and pins original TCP/TLS
marker scripts alongside HTTP in acceptance-local. Registered responses establish
Lua bridge/verdict behavior, not socket interoperability. acceptance-local explicitly
runs the cancellation fake-store EOF/completeness gate. Phase 3 stays paused.

v1.11.0 pins exact nested matcher skip reasons under normal/exhaustive policy.
The marker corpus now exercises real HTTP/TCP sockets and conservative untrusted
TLS rejection in acceptance-local. Successful trusted TLS corpus execution remains
follow-up work. Phase 3 stays paused.

v1.21.0 reuses the socket corpus matrix for pinned Redis TCP/trusted TLS scripts.
Retain exact RESP request assertions, product skip policy and unknown malformed
responses. Controlled command-policy evidence is not general Redis authorization
acceptance. Phase 3 stays paused.

v1.22.0 parameterizes the shared socket matrix for original POP3 TCP/trusted TLS
USER fixtures. Preserve exact requests, malformed-response unknown verdicts and
normal/exhaustive product gates. Controlled USER responses do not establish full
POP3 login/session acceptance. SMTP socket coverage remains open; Phase 3 stays paused.

v1.23.0 reuses the shared TCP/trusted TLS socket matrix for pinned SMTP VRFY
fixtures, including exact requests and conservative malformed-response policy.
Historical fixture service hints remain http; this is single-exchange policy
evidence, not SMTP session interoperability. Live consumer cancellation and durable
persistence remain blocked by the consumer route/store contract. Phase 3 stays paused.

v1.24.0 compacts pending cancellation/error-budget records in one stable pass and
clears removed queue references. Preserve queued order, terminal completeness and
host-spray fairness. Socket corpus expansion is complete for this priority pass;
prioritize planner, measured scheduling/throughput and existing pingpp adapter gaps.
Live consumer cancellation remains blocked; Phase 3 stays paused.

v1.25.0 makes missing-fact detection branch-aware: a satisfied any_of alternative
needs no sibling identification probe; unresolved alternatives and required
all_of facts retain probing. Preserve explicit product clean gates and caller
identity authority. Phase 3 stays paused.

v1.26.0 indexes pingpp.scan/v1 claims by exact endpoint subject per document.
Preserve endpoint isolation, confidence/contradiction filtering and conservative
identity conflicts; reuse the existing adapter. No throughput claim without
executed measurements. Live consumer persistence remains separate; Phase 3 paused.

v1.27.0 clears consumed pingpp Reader target slots and releases drained pending
arrays. Preserve target order and returned facts; keep reader memory bounded by
its current document. This is retention hardening, with no throughput claim.
Phase 3 stays paused.

v1.28.0 short-circuits any_of evaluation only after applicability and positive
product evidence are established. Service-only alternatives must retain later
product evidence; mismatched alternatives never identify a product. No throughput
claim. Phase 3 stays paused.

v1.29.0 bounds pingpp.scan/v1 upstream error diagnostic details to 1 KiB with
explicit truncation. Preserve terminal reader errors and inconclusive results;
oversized upstream errors must never produce targets. No throughput claim.
Live consumer persistence remains separate; Phase 3 stays paused.

v1.30.0 shares bounded pingpp diagnostic detail formatting for upstream errors
and unsupported schema strings. Bound before quoted formatting; preserve explicit
truncation, terminal reader failures and zero targets on errors. No performance
claim. Live consumer persistence remains separate; Phase 3 stays paused.

v1.31.0 measures the verified executed-Lua matrix across 1/2/4/8 workers,
module limits 0/1 and both selection paths. Preserve action output and terminal
count checks; report raw samples and distinguish batch latency from actions/s.
Shared-host scaling is not a before/after speedup claim. Phase 3 stays paused.

v1.32.0 shares the verified planner benchmark runner with a 100,000-addition
Lua workload and pins its one/eight-worker sums and unknown verdicts in the race
suite. Retain full terminal counts and raw samples; longer CPU scaling is local
measurement, not network or live consumer acceptance. Phase 3 stays paused.

v1.35.0 bounds pingpp JSON decoder diagnostics through the existing formatter.
Preserve terminal reader failures, zero targets and explicit truncation for
oversized numeric tokens. Live consumer acceptance remains separate; Phase 3 paused.

v1.36.0 retains TLS handshake observations when planner probes receive a banner.
Keep transport and pinned banner identity together; certificate observations do
not establish trust or vulnerability verdicts. Phase 3 stays paused.

v1.37.0 supplies CPE hints for pinned Caddy/OpenResty HTTP fingerprints through
the shared mapper. Preserve caller product authority, exact product skip reasons,
version sanitization and the CPE-only false-clean guard. No throughput claim;
live consumer persistence remains separate. Phase 3 stays paused.

v1.38.0 completes CPE hints for existing pinned Pure-FTPd/Sendmail banners via
the shared mapper and selection policy matrix. Preserve caller identity authority,
exact product skip reasons and CPE-only false-clean guards. No throughput claim;
live consumer persistence remains separate. Phase 3 stays paused.

v1.39.0 prepares nested banner regexes in index-owned matcher snapshots for
parallel selection. Keep direct Match evaluation safe for invalid expressions
and preserve banner-only unknown identification. Match now has private cache
state: external literals must use keyed fields. No measured speedup claim;
live consumer persistence remains separate and Phase 3 stays paused.

v1.40.0 reuses index-owned immutable selection metadata during selected engine
execution. Direct tasks retain metadata validation; evaluate endpoint matches and
clean gates per invocation. No measured throughput claim. Phase 3 stays paused.

v1.41.0 records the verified executed-Lua allocation baseline in docs/benchmarks.
Library initialization dominates sampled allocation bytes; cumulative profile
percentages overlap. Preserve invocation-owned tables and accounted SetEnv when
extending immutable builtin reuse. Allocation reduction remains unfinished;
shared-host measurements establish no speedup. Phase 3 stays paused.

v1.42.0 reuses immutable math/string builtin functions and string arithmetic
metamethods through the existing library snapshot pattern. Keep every library
table and string metatable invocation-owned, including __index, and populate
through accounted SetEnv calls. dump/random/randomseed remain disabled.
Raw before/after executed-Lua samples live under benchmarks/; allocation reduction
is measured, throughput speedup is not established. Phase 3 stays paused.

v1.43.0 reserves invocation library hash storage using the shared initializer.
Keep SetEnv accounting, invocation-owned mutable tables, normal growth and
third-party notices. Raw executed-Lua before/after samples under benchmarks/
establish allocation reduction only; no throughput speedup claim. Live consumer
persistence remains separate and Phase 3 stays paused.

v1.44.0 retains agreed pingpp product identity when accepted claims disagree
only on version; the version stays unknown regardless of claim order.
Different products remain unknown. Phase 3 stays paused.

v1.45.0 combines partial pingpp product-version evidence: absent versions do not
contradict a supplied version for an agreed product. Distinct nonempty versions
remain unknown regardless of empty/repeated claims or ordering. Preserve endpoint
isolation and accepted-claim filtering. Phase 3 stays paused.

v1.46.0 adds original pinned HAProxy HTTP Server identity and CPE hints through
existing fingerprint/planner paths. Preserve strict header boundaries, unknown
missing versions, caller identity authority and CPE-only false-clean guards.
No throughput claim; live consumer persistence remains separate. Phase 3 paused.

v1.47.0 makes on_unknown run respect observed contradictions across declarative
fields and nested all_of/any_of branches. Missing facts may allow execution but
never establish product identification or a clean verdict. Confidence/CPE gates
remain conservative. Phase 3 stays paused.

v1.48.0 adds original pinned Envoy HTTP Server identity and CPE hints through
the shared fingerprint/planner path. Preserve strict identity boundaries, unknown
missing versions, caller authority, exact product skip reasons and CPE-only
false-clean guards. No throughput claim; Phase 3 stays paused.

v1.49.0 maps accepted pingpp product identity confidence into planner facts:
strong is 0.8 and exact is 1, using the strongest accepted agreeing product
claim. Conflicting products retain zero confidence; service/TLS claims do not
establish product confidence. This is adapter policy, not calibrated probability.
Version conflicts remain unknown. Phase 3 stays paused.

v1.50.0 reuses immutable compiled default fingerprint rules across planner probes.
Keep custom matcher rule slices independent and default rules read-only; preserve
identity boundaries and conservative clean gates. Constructor microbenchmarks do
not establish executed-Lua throughput. Phase 3 stays paused.

v1.51.0 adds original pinned Varnish HTTP Server identity and CPE hints through
the shared fingerprint/planner mapper. Preserve strict identity boundaries,
unknown missing versions, caller authority, exact product skip reasons and
CPE-only false-clean guards. No throughput claim; live consumer persistence
remains separate and Phase 3 stays paused.

v1.52.0 adds original pinned Squid HTTP Server identity and CPE hints through
the shared fingerprint/planner mapper. Preserve strict identity boundaries,
unknown missing versions, caller authority, exact product skip reasons and
CPE-only false-clean guards. No throughput claim; live consumer persistence
remains separate and Phase 3 stays paused.

v1.53.0 adds original pinned Traefik HTTP Server identity and CPE hints through
existing fingerprint/planner paths. Preserve strict identity boundaries, unknown
missing versions, caller authority, exact product skip reasons and CPE-only
false-clean guards. No throughput claim; live consumer persistence remains
separate and Phase 3 stays paused.

v1.54.0 adds original pinned H2O HTTP Server identity and CPE hints through the
existing fingerprint/planner mapper. Preserve strict identity boundaries, unknown
missing versions, caller authority, exact product skip reasons and CPE-only
false-clean guards. No throughput claim; live consumer persistence remains
separate and Phase 3 stays paused.

v1.55.0 adds original pinned LiteSpeed HTTP Server identity and CPE hints through
the existing fingerprint/planner mapper. Preserve strict identity boundaries,
unknown missing versions, caller authority, exact product skip reasons and
CPE-only false-clean guards. No throughput claim; live consumer persistence
remains separate and Phase 3 stays paused.

v1.56.0 consumes upstream pingpp.scan/v1 product CPE hints through the existing
adapter. Accept only strong/exact uncontradicted endpoint product claims; omit
CPEs when product or version evidence conflicts. Sort and deduplicate hints.
CPE evidence never establishes a vulnerability verdict. Phase 3 stays paused.

v1.57.0 adds optional exact-length tcp.exchange reads (1..65536 bytes).
Preserve the default single-chunk behavior, verified TLS and shared five-second
deadline. Premature EOF is an execution error with no partial successful result.
Phase 3 stays paused.


v1.58.0 adds delimiter-framed tcp.exchange replies: a string second argument
reads through that delimiter (1..256 bytes), inclusive, within the existing 64 KiB
reply ceiling and five-second deadline. Missing delimiters and premature EOF are
errors without partial successful output. Connection setup and verified TLS use
the existing path. Multi-exchange sessions remain follow-up work; Phase 3 stays
paused. Controlled loopback evidence is separate from live consumer acceptance.

v1.59.0 adds bounded tcp.exchange sessions: one array of 1..16 argument arrays
runs on a single TCP/verified TLS connection with one five-second deadline.
Validate all steps before dialing; any failed step discards all successful output.
Phase 3 stays paused; local socket evidence is separate from consumer acceptance.


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

v1.62.0 makes nested planner skip reasons branch-aware. Failed required branches
supply their own reasons; failed alternatives supply a specific reason only when
all agree. Satisfied alternatives never contribute failure reasons. Preserve
applicability, product clean gates and unknown verdicts. Phase 3 stays paused.

v1.63.0 adds SDK ModuleInterval start pacing by exact dialect/script ID per run.
Zero disables it; negative intervals fail construction. Unrelated modules remain
eligible under existing host/global/concurrency policy. Expire pacing entries;
preserve cancellation terminal records and unknown verdicts. No throughput claim.
Phase 3 stays paused; local deployment is separate from consumer acceptance.

v1.64.0 exposes --module-interval and --module-concurrency through CLI and
POST /run using the existing engine options and shared runner. Exact dialect/script
keys, per-run scope, zero defaults and engine validation remain authoritative.
Transport tests require paced completed actions and complete JSONL EOF, and reject
negative intervals. No throughput claim; live consumer persistence remains separate.
Phase 3 stays paused.


v1.65.0 adds write-only tcp.exchange steps: integer read selector 0 sends the
payload and returns empty data with eof=false without reading. This supports
commands without replies within existing bounded TCP/verified TLS sessions.
Write failures still discard session output; all steps validate before dialing.
Existing deadlines, grants and reply limits apply. Phase 3 stays paused; local
transport evidence is separate from live consumer persistence acceptance.


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

v1.76.0 prepares direct execution metadata without copying source into a temporary
index. Public NewIndex and Select retain source ownership. Keep prepared metadata
independent of source bytes and endpoint verdict gates invocation-specific.
No measured throughput claim; live consumer persistence remains separate.
Phase 3 stays paused.

v1.77.0 exposes field-specific planner skip diagnostics for service, transport,
version, banner and CPE constraints through the shared nested matcher. Missing
facts remain distinct from observed mismatches; mixed alternative failures retain
the general reason. Selection and false-clean gates remain conservative. No public
API change or throughput claim. Live consumer persistence remains separate;
Phase 3 stays paused.

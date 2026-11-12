# Delivery roadmap

Each phase has its own evidence. A unit test, a CLI run, an installed Sirius
container, and an endpoint-agent job demonstrate different things.

## 0. Execution foundation

- Public Go SDK and thin CLI; explicit native/NSE dialects.
- Native API versioning, compiled Go capability registration, typed results, source
  digest, isolated state, and finite defaults.
- Original native and NSE-shaped fixtures; local HTTP service validation.
- Public MIT repository, dependency notices, and CI.

Acceptance: import the module from a separate Go program, execute the same script
through SDK and CLI on a controlled local service, compare structured output,
and test cancellation, rules, limits, and error propagation. A compiling in-repo
example is useful but is not the whole external-import acceptance gate. That
gate is the separate module in `examples/external` (a `replace` directive points
at this repository until a tagged release exists); `make acceptance`, part of
`make check` and CI, runs it. This is build/SDK evidence only, not Sirius
scanner or endpoint-agent integration acceptance.

## 1. Experimental NSE profile (coverage expansion deferred)

- Select exact Nmap version and external Sirius NSE corpus revision; audit their
  distribution constraints separately from the MIT engine.
- Enumerate direct and transitive module/function dependencies for selected
  vulnerability scripts. The existing 612-script catalog also contains discovery
  scripts; it is not automatically the product's full support target.
- Implement host/port tables, all selected rule phases, argument semantics,
  dependencies, nil/dual action outputs, and documented helper behavior.
- Add context-aware TCP/UDP/TLS sockets with faithful buffering, timeouts, EOF,
  cleanup, and scheduling behavior. Prioritize the selected corpus rather than
  guessing that a module name is enough.

Acceptance: machine-readable pass/fail/unsupported report, exact script digests,
local protocol fixtures, and differential comparison against the same pinned
Nmap version with equivalent supplied target facts. A module loading successfully
does not constitute a script passing.

The initial corpus dependency census prioritizes `stdnse`, `shortport`, `nmap`,
`http`, and `vulns`. The [research](research/sirius-integration.md#script-catalog)
records counts and their limits. Do not infer a percentage of compatible scripts
from that census.

Started: the machine-readable report harness (`compat` package,
`cmd/scribe-compat`, `make compat`) measures original MIT fixtures with pinned
digests and asserted outputs, and the first `stdnse`/`shortport` helper slice is
implemented against documented semantics with first-party fixtures; see
[compatibility](compatibility.md#measured-compatibility-harness). Selecting the
exact Nmap version and external corpus revision above is still open and is
recorded there as an explicit open item, so no upstream result exists yet.

## 2. Scanner orchestration adapter

- Add a Scribe strategy beside Nmap in app-scanner.
- Generalize hardcoded Nmap configuration injection and source attribution.
- Supply known ports and available service/version facts; keep discovery stages.
- Map native findings and recognized NSE vulnerability states into Sirius reports
  while preserving raw evidence and source digest.
- Keep content synchronization, RabbitMQ, run correlation, cancellation, Valkey,
  persistence, and enrichment in the adapter/orchestrator.

Acceptance: a real Sirius job selects Scribe explicitly, returns source-attributed
evidence, preserves cancellation and terminal run states, and records unsupported
coverage without reporting a clean assessment. Test controlled jobs alongside the
existing Nmap path before changing defaults.

## 3. Endpoint-agent embedding

- Register `internal:script-scan`; call the SDK directly inside the agent process.
- Define versioned request/result envelopes and per-job capability grants.
- Adapt the current template-specific coordinated-result merger and UI dispatch.
- Pin module versions and update engine/agent/container revisions together.
- Distinguish remote network checks from endpoint-local checks. Local process,
  registry, filesystem, and package inventory access need separate bounded Go
  capabilities; do not expose a shell as the base script API.

Acceptance: installed endpoint binary imports the tagged module, accepts a real
coordinated script job, produces the expected report, cancels correctly, and reports
its actual version. Cross-compilation alone is not installed-agent acceptance.

## 4. Wider coverage and operational hardening

- Define session-scoped NSE registries, cache ownership, selected-script ordering,
  script worker threads, mutexes, and condition variables.
- Evaluate native-module alternatives and privileged APIs only for required cases.
- Add signed/versioned script bundles, capability policy, audit records, and process
  isolation when needed for hostile-script containment.
- Benchmark representative jobs before VM pooling, compiler caches, or additional
  Go protocol acceleration. Preserve isolation when introducing caches.

Acceptance: agreed compatibility corpus, bounded stress/load tests, cross-platform
endpoint validation, fault recovery, and measured performance. Retire Nmap only for
jobs whose required semantics and operational behavior have passed these gates.

Phase 2 preparation: supplied endpoint facts now include product/version through
SDK, CLI and HTTP; batches cover the script/endpoint Cartesian product and retain
cancelled queued records. Package report provides a version 1 source-attributed
evidence envelope with conservative assessment mapping. Real app-scanner jobs,
persistence mapping and independent job cancellation remain consumer acceptance.

Phase 3 preparation: this repository now provides package job request/result
schema v1, caller-owned script resolution, existing Target facts and report
mapping, exact-name per-job capability grants, and tightening VM limits. Focused
fixtures cover grants, typed denial, cancellation, and limits. Agent registration,
coordinated merger/UI changes, pinned releases, and installed-agent acceptance
remain consumer work; no endpoint-agent repository is changed by this slice.

Phase 3/4 in-repo slice: capability/localcap registers opt-in, exact-name
local.file.stat, local.file.read, local.process.list and local.package.list.
File paths are confined with os.Root to a caller-selected directory, regular-file
reads are limited to 64 KiB, and inventory is limited to 1024 entries. Linux
process inventory provides PIDs from /proc; package inventory reads dpkg metadata
(up to 4 MiB). Other inventory platforms return explicit unsupported errors;
Windows and Darwin compilation does not establish native inventory support.
Callers own root lifetime and must choose trusted local filesystems: synchronous
kernel filesystem calls cannot guarantee prompt cancellation on stalled mounts.
No shell or subprocess is exposed. Runtime grant denial remains typed and missing
job grants deny all calls. SDK Version() exposes module version and commit when
available, with optional BuildVersion/BuildCommit linker values; consumer VCS
metadata is deliberately excluded. Local job benchmarks and bounded concurrent
execution/cancellation tests provide in-repo evidence only. Installed agent and
real Sirius workflow acceptance remain outstanding.

Smart-selection SDK slice: immutable source snapshots and cached JSON comment
hints feed the existing bounded batch runner. Optional caller-side banner/header
fingerprinting supplies conservative hints; ping++ remains the upstream fact
source. Local no-op scheduling benchmark (100 scripts, one endpoint, four workers)
measured 88.8 us/op without selection and 3.80 us/op with selection. These numbers
are local scheduling evidence only; actual Lua throughput and ping++ integration
acceptance remain consumer validation. `make check` and the CGO-disabled CLI build
passed for this slice.

Engine fault-recovery slice: original testdata/sirius verdict fixtures execute in
`make check` through the race suite. A bounded 576-execution matrix checks verdict
isolation and goroutine return to baseline. Mixed batches cover Lua errors,
capability panics, endpoint errors and CPU/I/O waits alongside healthy siblings.
Windows and Darwin amd64 CLI cross-builds are part of `make check`; these are
build evidence only. Actual platform runtime and Sirius integration acceptance
remain outstanding.

Next ordered backlog (supersedes the phase ordering above):

1. Declarative per-script match blocks: product/CPE, version range, protocol,
   minimum confidence, and `on_unknown = run|probe|skip`. A Go planner decides
   before building any Lua VM. Ports order work and never exclude scripts;
   every skip records a reason.
2. False-clean guard: `not_vulnerable` must cite product identification, enforced
   by `--check`. Add cheap cached fingerprint probes for unknown facts and an
   exhaustive mode that measures planner misses.
3. Benchmark-driven engine work: implemented in-repo with streaming targets,
   per-host concurrency/pacing/error budgets, bounded host-spray/script-spray,
   endpoint-partitioned HTTP reuse and bounded compiler/VM code-template caches.
   Declarative hint exclusions emit skipped/unknown records before VM creation
   and host admission. Dynamic Lua rules still require an isolated VM.
   See [measurement and operational contract](engine-throughput.md), including
   real Lua before/after results and remaining integration acceptance.
4. Adapt ping++ `pingpp.scan/v1` output (ping++ PR #1 branch) to Scribe facts.

Phase 3 endpoint-agent work is paused: the SDK side has landed; remaining work
belongs in app-agent.

Historical backlog 3 partial preparation (superseded by the completed slice below): `RunTargetStream` consumes a caller-owned target
producer with endpoint backpressure and retains only one endpoint's selected
matrix. `RunSelected` uses this path. A focused test checks producer backpressure.
This serializes endpoints; it does not implement host-spray/script-spray, host
rates/error budgets, connection reuse, compiler caches or VM caches. Those remain
open, as does VM-free declarative matching (backlog 1).

Local Go 1.24.13 linux/amd64 measurements, i9-13900H, existing
`go test -run '^$' -bench BenchmarkSelection -benchmem -count=3 .`:
selected scheduling before 4139–4461 ns/op, after 4422–4780 ns/op;
both 2344 B/op and 15 allocations/op. Unselected before 86179–94771 ns/op,
after 90419–123189 ns/op. This no-op runtime harness measures scheduling,
not Lua throughput; the change claims bounded target retention, not a speedup.
`GOTOOLCHAIN=go1.24.13 make check` passed (race suite, external SDK acceptance,
Windows/Darwin builds, vet, CGO-disabled CLI). This is in-repository evidence,
not scanner/agent integration acceptance.


Backlog 3 engine slice: `RunSelected` now shares the bounded streaming scheduler
rather than serializing endpoints or materializing their Cartesian product.
Per-run host limits span ports and retain budgets across windows. Known finite
batches retain cancellation terminal records; open target streams stop accepting
input and drain accepted pairs. Hint exclusions emit reasons without consuming
host admission slots. The CLI exposes host controls, both spray strategies and
bounded `--facts-jsonl` input. HTTP transports reuse connections only within the
same logical authority/fixed-IP/TLS identity; raw unframed TCP exchanges remain
isolated. The Lua runtime caches immutable compiler output and VM code templates
with bounded retention, binding fresh state for each invocation. This deliberately
preserves independent VM ownership rather than recycling live interpreter state.

Real Lua benchmarks, raw samples, interpretation, cache/transport controls and
verification evidence are recorded in [engine throughput](engine-throughput.md).
Richer declarative matching and false-clean identification gates (backlog 1/2)
remain open; this slice uses the existing selection hints. Scanner/agent workflow
and installed-platform acceptance remain separate consumer work.

Backlog 4 implemented in-repo: importable `adapter/pingpp` reads bounded
`pingpp.scan/v1` JSONL and exposes `Reader.Next` directly to `RunTargetStream`.
The CLI accepts `--pingpp-jsonl FILE` through the existing smart selection and
batch path (mutually exclusive with other facts inputs). Schema reviewed with
`gh` against SiriusScan/pingpp PR #1 at
`ff4085905039cbbc759a0a75fab897b49316ef1a`, specifically
`pkg/output/document.go` and `pkg/model/{asset,endpoint,claim,confidence}.go`.
The original fixture pins that wire shape; no upstream code is vendored.
Only attempted, confirmed-open endpoints are scheduled. Responsive, unknown,
closed, filtered and incomplete endpoints do not establish open facts. Endpoint
addresses supply connection identity; arbitrary asset hostnames are not assumed
to be TLS authorities. Strong/exact endpoint protocol/service and product claims
supply facts; conflicts remain unknown and product/version stay paired. Raw
observations, host claims, CPE and confidence are not representable in current
Scribe Target facts and are not promoted to verdicts. Target errors and malformed
or unsupported documents fail the stream; an empty stream is an error. A valid
scan with no eligible endpoints produces no execution records and is inconclusive.
Limits: 4 MiB per document and 65536 documents; caller owns reader interruption.
No ping++ schema change is required for these facts. Future confidence/CPE-aware
planning needs richer Scribe facts, rather than additional ping++ discovery.
Fixtures and CLI tests cover mapping, conservative omissions, errors, cancellation
and hint-based skips. `make check` provides in-repository build/test evidence;
real ping++ to Sirius workflow acceptance remains outstanding.

## v0.2.0 library polish

Delivered: root SDK options and Run/Batch/Stream entry points, context-aware
bounded scheduling, executable single/batch/selection examples, and ping++ JSONL
selection through parallel local HTTP fixtures. Unsupported API errors and
selection exclusions remain unknown with execution status preserved. Internal
selection metadata no longer expands the public API.

Next: extend native Sirius capabilities with pinned fixtures as scanner and agent
needs arise. Do not pursue NSE library coverage. Release checks and service smoke
tests establish build and local transport evidence only; full vGPT and endpoint
agent workflow acceptance remains a separate gate.

Backlog 1/2 initial declarative slice: optional `match` metadata combines service,
product, protocol, inclusive semantic version bounds and banner regex with nested
any_of/all_of. Ports in the new block are advisory. Required missing facts skip
conservatively before VM construction; clean results for these blocks additionally
require an exact declared product match. Legacy hints retain their existing
semantics. CPE/confidence, on_unknown probe policy, cached probes, exhaustive
measurement and universal legacy-script identification enforcement remain open.

Backlog 1/2 follow-up: opt-in SDK StrictIdentification and CLI
--strict-identification extend the clean-verdict product gate to legacy metadata.
Combined with --check this rejects missing product declarations; runtime matching
remains necessary. Default legacy fixture behavior is preserved. --exhaustive
executes planner exclusions and emits planner_miss for completed explicit verdicts;
clean verdicts still require identification. Match on_unknown accepts run, skip,
and probe. Probe performs one passive TCP banner read per endpoint per run,
including cached failures (250 ms, 8 KiB, cache bounded by MaxHosts); it fills
missing facts only. UDP, TLS and HTTP header probing remain unsupported and
unresolved facts remain inconclusive. Probing applies to selected/stream runs;
direct Run uses supplied facts. CPE/confidence and full integration acceptance
remain open. These checks establish repository evidence only.

Implemented: declarative exact CPE alternatives and minimum identification confidence
(0–1), HTTP HEAD header fingerprinting, TLS subject/ALPN/version facts, and opt-in
direct SDK planner probes. UDP and CPE inference remain outside probe coverage.

Planner probes use a 250 ms endpoint budget, an 8 KiB response header/banner limit, TLS detection on common HTTPS ports and a handshake attempt on silent TCP endpoints. Certificate subjects, TLS version and ALPN are observations without certificate trust validation. HTTP HEAD redirects allow at most three requests on the same host and port. Pinned nginx, Apache and OpenSSH fingerprints infer CPE hints; these are not vulnerability verdicts. CLI JSONL and POST /run expose facts and confidence under `target`, and planner skip reasons under `output.skip_reason`. Missing verdicts remain unknown. SNMP and arbitrary product inference remain unsupported.

Planner transport/load coverage slice (2026-11-11): local CLI JSONL and POST
/run fixtures assert completed unknown execution, TLS certificate/version facts,
HTTP nginx headers, same-endpoint redirects, OpenSSH TCP banners, inferred CPE
and confidence, and explicit planner skip reasons. Each transport must emit one
complete JSONL record. No runtime bugs were revealed by these fixtures.

Executed-run benchmark: Go linux/amd64, i9-13900H, four workers,
32 scripts × 16 endpoints, with 100 additions per Lua action. Unfiltered runs
execute 512 actions; selected runs execute 64 actions and emit 448 skipped
records. Every completed result must contain the calculated action output.
Three samples from
go test ./runtime/lua54 -run '^$' -bench BenchmarkPlannerExecution -benchmem -count=3:
unfiltered 12.011/10.406/11.679 ms/op, about 16.15 MB/op and 162125–162153
allocations/op; selected 1.492/1.565/1.397 ms/op, about 2.234 MB/op and
22309–22310 allocations/op. This measures local Lua execution and scheduling
with warm bounded caches, not network workload throughput or Sirius integration.

Validation: make check passed (race suite, external SDK acceptance, Windows/Darwin
cross-builds, vet and CGO-disabled CLI build). apps01 service reinstalled with
make install-service; make smoke-http passed all three verdicts and TCP banner.
These are local transport/build checks, not full vGPT workflow acceptance.
No production code changed, so no service-affecting release tag was created.

v0.4.0 slice: bounded UDP DNS/NTP planner identification with correlated response
fixtures; service facts only, no product or vulnerability inference. SNMP deferred
until callers can supply an explicit community policy. README and executable
godoc examples cover Run, Batch and selected Stream. Corpus metadata lint reports
legacy missing match blocks without changing compatibility fixtures.
Validation: make check passed (race, external SDK, cross-builds, vet, CGO-disabled
CLI). apps01 make install-service and make smoke-http passed all three verdicts
and TCP banner. This is local build/transport evidence, not vGPT acceptance.

## v0.5.0

Legacy vGPT scripts declare TCP/Apache matching; original Sirius verdict fixtures
use an explicit synthetic Scribe fixture product. Fixture callers supply matching
identities, preserving verdict expectations without bypassing the clean gate.
Corpus metadata lint now fails missing match blocks by default, including new
scripts. The CLI exposes caller-supplied product identity.

Opt-in SNMP v2c identification uses exactly one caller-supplied community through
Options.SNMPCommunity or --snmp-community. Empty policy disables requests.
It queries sysDescr.0, correlates version/community/request ID/OID and successful
response shape, and exposes service/confidence only. A 250 ms deadline and 8 KiB
response ceiling bound each probe; fake UDP responders cover success and wrong
request IDs. Existing selected-run caching retains failures. No community guessing,
product inference or vulnerability verdict is provided.

Package godoc documents pre-v1 versioning, independent schema versions and result
semantics; CHANGELOG.md records v0.1.0 through v0.5.0. No runtime API types changed.
Validation: make check passed (race suite, external SDK acceptance, Windows/Darwin
builds, vet and CGO-disabled CLI build). Service/HTTP evidence is recorded below;
Sirius scanner/agent and full vGPT workflow acceptance remain separate gates.
apps01 service installation with VERSION=v0.5.0 and make smoke-http passed:
completed vulnerable/not_vulnerable/unknown records and TCP banner output.
This establishes local service transport evidence only.

## v0.6.0

Expanded pinned product identification and CPE hints; planning uses the existing
selection path with unknown verdicts and explains would-run decisions without
Lua rule/action execution or network probes. Engine options add per-invocation
timeouts and per-run global start intervals alongside bounded concurrency.
Local build and service checks remain separate from scanner/agent acceptance.
Validation: make check passed, including race tests, external SDK acceptance,
Windows/Darwin builds, vet and CGO-disabled CLI build. apps01 installation with
VERSION=v0.6.0 and make smoke-http passed all three verdicts and TCP banner.

## v0.7.0

Mixed-corpus planner regression and benchmark share a 32-module × 16-target
harness. Original inline Sirius fixtures mix vulnerable, clean, unknown, nil
output, action errors and rule skips across matching, missing and conflicting
product identities. Selected and exhaustive paths require all 512 unique terminal
records, unknown verdicts on failures/skips, and nonempty skip reasons. Runtime
hint checks continue to exclude conflicting identities even in exhaustive mode.
The expected batch error must accompany failed actions while siblings complete.

Local Go 1.26.10 linux/amd64, i9-13900H, four workers, warm caches:
`go test ./runtime/lua54 -run '^$' -bench BenchmarkMixedCorpusPlanner -benchmem -count=3`.
Selected samples: 7.063/6.671/8.970 ms/op, 11.85 MB/op, 120826–120834 allocations.
Exhaustive samples: 9.422/8.792/10.663 ms/op, 12.42 MB/op, 127086–127121 allocations.
These include assertion overhead and measure local SDK/Lua/planner execution,
not network throughput, upstream corpus compatibility or scanner integration.
Skip reasons are counted by the shared harness and included in failure diagnostics.
`make check` passed race tests, external SDK acceptance, Windows/Darwin builds,
vet and the CGO-disabled CLI build. Phase 3 remains paused. Stable API/JSONL
expansion and structured SDK observability remain subsequent priorities.

Release evidence: v0.7.0 tagged and pushed after `make check`; apps01 service
reinstalled with VERSION=v0.7.0. `make smoke-http` passed completed vulnerable,
not_vulnerable and unknown records plus the TCP banner fixture. This is local
service transport evidence only, not full vGPT/scanner/agent acceptance.

## v0.8.0

Structured SDK OnEvent observations share terminal planning/skip evidence,
per-module elapsed time and conservative verdicts with opt-in --events JSONL
and POST /run. Planning events are retrospective at result delivery.
The versioned wire contract is documented in jsonl-v1.md and pinned by a golden
fixture. Phase 3 stays paused. Build and local service validation remain separate
from scanner/agent workflow acceptance.

## v0.9.0

SDK result deduplication preserves conflicting evidence and ignores only elapsed
timing. Incremental summaries count statuses, conservative verdicts and skip
reasons; CLI --summary and POST /run share the implementation. Summary counts
include duplicates unless SDK callers explicitly deduplicate. HTTP shutdown
cancels work and drains handlers for up to five seconds. Library quickstart and
compiling examples cover result processing. Phase 3 remains paused.
Build/service checks are repository and local transport evidence, not scanner,
agent or full vGPT acceptance.

## v1.0.0 preparation (in progress)

Module inventory and initial metadata/JSONL fuzz targets are implemented. A root
exported-symbol golden detects name removals; it does not yet pin signatures or
subpackage APIs. Full API documentation audit, expanded pinned Sirius corpus and
false-clean coverage remain release gates. Phase 3 stays paused. Do not interpret
this preparation as released v1.0.0 or scanner/agent acceptance.

Signature gate progress: exported declarations now have a separate golden across
all importable first-party packages, including receiver signatures, struct fields,
JSON tags and constant expressions. Platform source variants are included.
`make check` passed on apps01 on 2026-11-11. Full documentation audit and expanded
pinned fingerprint/false-clean corpus remain outstanding; v1.0.0 is not tagged.

Release audit progress (2026-11-11): added missing declaration godoc across
importable packages and corrected misplaced Limits, Verdict and Plan comments.
Expanded original pinned HTTP identity fixtures for IIS, lighttpd, Tomcat, Jetty,
Apache and nginx, plus unrecognized banner/header negatives. Signature golden
refresh contains formatting changes only; public declarations are unchanged.
`make check` passed (race suite, external SDK acceptance, Windows/Darwin builds,
vet and CGO-disabled build). Field-level documentation/behavior review and further
pinned Sirius false-clean execution cases remain open. v1.0.0 remains untagged;
Phase 3 stays paused.

## v0.9.1 release gate status (2026-11-11)

Expanded pinned Sirius clean execution coverage asserts unknown verdicts and exact
skip reasons for missing/mismatched products in selected and exhaustive runs.
Limits now documents VM CPU accounting, allocation bytes and tightening timeouts.
The complete field-level documentation and behavior audit of all exported types
(including Result, Target and match blocks) remains incomplete; v1.0.0 therefore
is not eligible. Release version is v0.9.1. Phase 3 stays paused.
`make check` passed race tests, external SDK acceptance, Windows/Darwin CLI
cross-compilation, vet and CGO-disabled CLI build on apps01. These checks are
build/local execution evidence, not scanner/agent or vGPT integration acceptance.

Field audit chunk 1 (2026-11-11): documented every Result field, including schema,
source digest, execution status versus verdict, planner misses, and elapsed
milliseconds/zero behavior. Added conservative summary coverage for uninitialized,
failed and cancelled records carrying explicit verdicts. The signature golden
change is whitespace only; declarations and JSON tags are unchanged.

Remaining release audit: complete (2026-11-11). All listed root and
subpackage exported fields now document meaning, units, defaults and zero
behavior beside their declarations. See [the audit inventory](api-field-audit.md)
for reviewed surfaces and behavioral evidence. Plan is Options.Plan, not a
separate exported type. Added focused defaults, invalid option, confidence,
inclusive version/advisory port, empty matcher and conservative report tests.
Signature golden review confirms unchanged field names/order/types/tags and
callable signatures; only documentation-driven formatting and grouped Facts
field spelling changed. v1.0.0 release validation uses make check and the installed
HTTP smoke fixtures. These checks establish local execution/build and service
transport evidence, not scanner/agent or full vGPT workflow acceptance.
Phase 3 stays paused.

Validation: `make check` passed on apps01 on 2026-11-11, including the race
suite, external SDK acceptance, Windows/Darwin cross-compilation, vet and
CGO-disabled CLI build.

## v1.0.1 post-release hardening (2026-11-11)

v1.0.0 is tagged and installed; earlier preparation status above is historical.
Phase 3 endpoint-agent work remains paused.

Extended the existing executed-Lua benchmark rather than adding a duplicate:
BenchmarkPlannerExecution now reports actions/s, with 32 original local modules
× 16 supplied endpoints, four workers, 100 additions per action and verified
5050 outputs. Unfiltered executes 512 actions; selection executes 64 and emits
448 skips. Warm bounded caches, Go 1.26.10 linux/amd64, i9-13900H.
Command: go test ./runtime/lua54 -run '^$' -bench BenchmarkPlannerExecution -benchmem -count=3.

CPU profiling attributed 13.55% cumulative samples to Engine.run. Its script-spray
admission scanned the entire pending window even after finding the first eligible
task. Stop immediately at that task; host-spray still scans for fairness.
Existing scheduling tests cover ordering and host constraints. This fixes redundant
scheduler work without sharing interpreter states or changing public declarations.
VM table initialization/allocation remains a larger runtime cost.

Unprofiled unfiltered before: 10.861/10.058/11.115 ms per 512 actions;
after: 12.931/11.393/11.160 ms, 39595/44938/45880 actions/s,
16.153–16.160 MB/op and 162165–162208 allocations/op.
Selected after: 1.304/1.788/1.248 ms, 49067/35795/51291 actions/s,
2.234 MB/op, 22308–22310 allocations/op. These samples do not establish
an end-to-end speedup. Earlier samples overlapped fuzzing and were discarded.
Further optimization needs allocation profiles and isolated repeat measurements;
do not introduce live VM pooling based on these results.

FuzzParallelPlanner bounds matrices to 16 × 16, executes real actions through
shared runtime caches and checks conservative verdicts, outputs, terminal counts,
skip reasons and cancellation. Its seeds run under make check's race suite.
A 10-second fuzz campaign passed 5394 executions; a race-instrumented five-second
campaign passed while processing the accumulated seed corpus.

Next unfinished work:
- Profile VM library/table initialization allocations and measure a safe reduction
  while retaining invocation isolation and finite accounting.
- Broaden planner/engine fuzzing to mixed errors, grants and sink failures, with
  longer scheduled campaigns.
- Validate real app-scanner/ping++/vGPT cancellation and report persistence.
  Local benchmarks, cross-builds and HTTP smoke checks do not establish this.
- Keep Phase 3 paused; extend native capabilities only for demonstrated needs.

Validation: make check passed, including go test -race ./..., external SDK
acceptance, Windows/Darwin cross-builds, go vet ./... and CGO-disabled CLI build.
Service installation and POST /run smoke results are reported with delivery.


## v1.0.2 (2026-11-11)

Allocation profile: BenchmarkPlannerExecution, alloc_space sampling attributed
52.95% cumulative bytes to loadLibraries, 45.85% flat to hashTable.grow and
10.27% flat to SetEnvGoFunc. Reuse the seven immutable table-library Go functions
initialized once, following the existing base builtin pattern. Every invocation
still creates and populates its own mutable table through accounted SetEnv;
no live VM pooling, shared mutable library table, or public API change.
Mutation/reexecution regression and race suite verify isolation.

Isolated sequential before/after runs (no fuzz/load/check overlap): Go 1.26.10,
linux/amd64, i9-13900H, four workers, existing verified 32 × 16 benchmark.
Command: go test ./runtime/lua54 -run '^$' -bench BenchmarkPlannerExecution -benchmem -count=3.
Before unfiltered: 11.412/12.849/12.761 ms, 44864/39848/40121 actions/s,
16154108/16154460/16155104 B/op, 162168/162208/162167 allocations/op.
After unfiltered: 11.852/10.569/12.574 ms, 43199/48444/40718 actions/s,
15988490/15983111/15984071 B/op, 158662/158621/158622 allocations/op.
Before selected: 1.438/1.583/1.913 ms, 44522/40432/33453 actions/s,
2233917/2233931/2233957 B/op, 22309/22309/22311 allocations/op.
After selected: 1.587/1.359/1.394 ms, 40337/47089/45897 actions/s,
2212531/2212305/2212171 B/op, 21862/21860/21860 allocations/op.
This supports a small allocation reduction; timing variation does not establish
an end-to-end speedup. Earlier overlapping check samples were discarded.

FuzzMixedFailures adds exact grant allow/deny, Lua errors and sink failure
propagation; seeds run under race checks. A 30-second campaign passed 194930
executions. Adapter FuzzReader passed 1007136 executions in a 15-second campaign.
Longer scheduled campaigns remain future operational work; none is scheduled.

The requested pingpp.scan/v1 Go adapter, docs and pinned tests already exist in
adapter/pingpp and README; extended reader fuzz coverage rather than duplicating
mapping. The schema remains pinned to ping++ PR #1 ff4085905039cbbc759a0a75fab897b49316ef1a.
No Sirius/ping++ repository extension is needed for this slice. Real scanner,
ping++ and vGPT cancellation/persistence acceptance remains outstanding.
Phase 3 remains paused.

Validation: make check passed race suite, external SDK acceptance, Windows/Darwin
builds, vet and CGO-disabled build. Local service smoke evidence follows release;
these checks do not establish scanner/agent integration acceptance.
apps01 VERSION=v1.0.2 installation and make smoke-http passed completed
vulnerable/not_vulnerable/unknown records plus TCP banner at POST :18081/run.
The tagged commit is reinstalled after publication to pin installed build metadata.

## v1.1.0 acceptance preparation (unreleased)

`make acceptance-local` composes the existing external SDK/CLI HTTP and
cancellation acceptance with HTTP/TLS fingerprint listeners, pingpp.scan/v1
fixture-to-SDK execution and CLI fixture selection. The SDK fixture now persists
all terminal records to a caller-owned JSONL file, syncs it, reopens it and
requires complete evidence-preserving records, including errors and skips.
This demonstrates local file persistence only, not Sirius report storage.

Validation on apps01: make acceptance-local and make check passed. The corpus
expansion, SSH listener acceptance and any harness-driven planner changes remain
unfinished. Real ping++ execution and vGPT/Sirius workflow cancellation and
persistence have not been exercised. Local vgpt and sirius-workspace directories
exist; access has not yet been audited, so lack of access is not established.
Still needed: identify the live scanner invocation and pinned ping++ binary,
submit a controlled correlated job through the actual vGPT workflow, cancel a
second job, and read terminal state and persisted evidence from its report store.
No live consumer acceptance or v1.1.0 release is claimed by this preparation.
Phase 3 remains paused.

### v1.1.0 local access audit and SSH acceptance — 2026-11-11

Added a controlled loopback SSH listener acceptance test requiring OpenSSH 9.0
service/product/version observations; included in acceptance-local. `make check`
passed (race suite, external SDK acceptance, cross builds, vet, CGO-disabled build).

Read-only access is available to /home/agi/Projects/vgpt (a540668) and
/home/agi/Projects/sirius-workspace (d68ef60). The nested
minor-projects/ping++ checkout is 9508a16c40a49746feb7cab4b8c1c358246169b0.
It has a library example but no scanner main beyond examples/simple/main.go,
and searching that checkout found no pingpp.scan/v1 emitter. No ping++/pingpp
binary was found on PATH or in /usr/local/bin, ~/.local/bin, or the Projects
tree through depth five. Thus an actual pinned scanner-to-Scribe run was not
performed: the accessible checkout lacks the pinned wire emitter and an installed
scanner binary was not found. This is a source/binary mismatch, not a directory
permission denial. No consumer files or services were changed.

Corpus expansion and real consumer workflow acceptance remain outstanding;
v1.1.0 is not tagged by this increment. Phase 3 remains paused.

Deployment of dd943b7: sudo noninteractive make install-service succeeded;
make smoke-http passed all three explicit verdict cases and the TCP banner case.
These are local service checks, not live consumer integration acceptance.

## v1.1.0 release — 2026-11-11

Expanded original pinned observations with Caddy/OpenResty HTTP headers and
Pure-FTPd/Sendmail banners alongside existing SSH, FTP, SMTP and database fixtures.
Anchored nginx recognition rejects proxy text containing a product mention.
Eleven real-service products exercise matching, absent and conflicting identities
with TLS-marked targets under normal and exhaustive clean-gate execution.
Existing controlled TLS and SSH listeners remain part of acceptance-local.

make check and make acceptance-local passed, including race, vet, external SDK,
Windows/Darwin cross-build and CGO-disabled build evidence. These are local checks.
The audited ping++ checkout lacks a scanner main/wire emitter; adding a new scanner
lifecycle is deferred rather than introducing a second unvalidated discovery path.
Follow-up: implement and pin an upstream pingpp.scan/v1 emitter, then exercise real
scanner cancellation and persisted consumer reports. The existing Scribe adapter
and CLI remain fixture-tested. Live Sirius/vGPT acceptance is outstanding and
does not block this release. Phase 3 remains paused.

## v1.2.0 preparation — 2026-11-11

Pushed pingpp branch scribe-v1.2.0-emitter at 2c397a1 and Scribe adapter acceptance at 7bd2f54. Minimal literal-IP TCP emitter bounds targets to 4096 and each connection to 250 ms; failures remain unknown and it emits no identity claims. Optional make acceptance-local check verifies complete adapter consumption from a controlled open socket. Full emitter-to-Lua execution, emitter behavioral tests and requested expanded fingerprint fixtures remain unfinished; no v1.2.0 tag yet. Phase 3 stays paused.

make check and make acceptance-local passed. Service reinstall and smoke-http passed. These are local evidence, not Sirius/vGPT acceptance.

Sequential benchmark after checks, Go linux/amd64 i9-13900H, existing verified 32 x 16 matrix, four workers, count=3:

```text
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerExecution/selected=false-4         	     121	  11260203 ns/op	     45470 actions/s	15978040 B/op	  158472 allocs/op
BenchmarkPlannerExecution/selected=false-4         	     100	  12703621 ns/op	     40303 actions/s	15983690 B/op	  158627 allocs/op
BenchmarkPlannerExecution/selected=false-4         	     104	   9690278 ns/op	     52836 actions/s	15983371 B/op	  158592 allocs/op
BenchmarkPlannerExecution/selected=true-4          	     858	   1686555 ns/op	     37947 actions/s	 2212343 B/op	   21861 allocs/op
BenchmarkPlannerExecution/selected=true-4          	     658	   1658055 ns/op	     38599 actions/s	 2212419 B/op	   21862 allocs/op
BenchmarkPlannerExecution/selected=true-4          	     793	   1356468 ns/op	     47181 actions/s	 2212399 B/op	   21861 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	11.400s
```
Previous v1.0.2 unfiltered 43199/48444/40718 actions/s and selected 40337/47089/45897 overlap these samples; no clear throughput regression established. Deployment started during benchmark completion, so repeat isolated samples before release performance conclusions.

## v1.2.0 validation — 2026-11-11

Emitter branch scribe-v1.2.0-emitter is pinned at 24ac3f2 (emitter implementation unchanged from 2c397a1). Behavioral tests cover open/refused sockets and rejected inputs. Required CLI acceptance consumes real emitter wire output and verifies one completed Lua action with explicit vulnerable fixture verdict. Expanded original observations and negative HTTP fixtures accompany four additional product clean gates. Phase 3 stays paused.

make check and make acceptance-local passed before benchmark; fingerprint-only additions passed their focused suite. Repeat samples below ran without overlapping Scribe tests, builds, fuzz or deployment. Other projects have active processes on this shared host, so machine-wide isolation was unavailable; these samples do not satisfy a strict idle-host performance gate and establish no performance claim.

```text
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerExecution/selected=false-4         	     100	  10768471 ns/op	     47546 actions/s	15983244 B/op	  158601 allocs/op
BenchmarkPlannerExecution/selected=false-4         	     120	   9649158 ns/op	     53062 actions/s	15979113 B/op	  158546 allocs/op
BenchmarkPlannerExecution/selected=false-4         	     127	  12144683 ns/op	     42159 actions/s	15980672 B/op	  158549 allocs/op
BenchmarkPlannerExecution/selected=true-4          	     728	   2808380 ns/op	     22789 actions/s	 2212545 B/op	   21864 allocs/op
BenchmarkPlannerExecution/selected=true-4          	     478	   2640414 ns/op	     24239 actions/s	 2212856 B/op	   21866 allocs/op
BenchmarkPlannerExecution/selected=true-4          	     433	   3102774 ns/op	     20627 actions/s	 2212988 B/op	   21868 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	11.108s
```

Final make check and make acceptance-local passed after all fixture edits. Noninteractive service reinstall and smoke-http passed all three verdict cases and TCP banner. Release tag withheld pending the requested idle-host benchmark; v1.3.0 has not started.

Release decision: v1.2.0 idle-host benchmark gate explicitly waived by the user
(shared host). Recorded samples remain shared-host evidence without performance
claims. Proceed with publication and installed-service smoke checks.

## v1.3.0 — planner identity evidence hardening (2026-11-11)

Probe merges now reject inferred CPE and confidence when the probe product
conflicts with the supplied product. Previously those fields could strengthen
an unrelated caller identity. Matching products retain enrichment; supplied
facts remain authoritative. Focused regression covers both paths. No public API
or wire schema changes, interpreter sharing, or NSE coverage expansion.

make check and make acceptance-local passed, covering race tests, vet,
CGO-disabled CLI, cross-builds, parallel engine fixtures and pinned real ping++
emitter-to-Lua execution. These establish repository/local transport evidence.
Real Sirius/vGPT cancellation and persisted report acceptance remain unfinished;
Phase 3 remains paused. Shared-host benchmark evidence and its v1.2.0 waiver
remain recorded above; this change makes no throughput claim.

v1.3.0 bounded planner fuzz campaign passed 11,505 executions in 10 seconds.
v1.2.0 installed-service smoke passed all three verdicts and TCP banner.

## v1.4.0 — local cancellation and persistence acceptance (2026-11-11)

Repeated cooperative mid-run cancellation now exercises active and queued tasks
through a fake consumer report store: sync, close, reopen, decode to EOF, require
all 12 unique terminal records with source digests and inconclusive assessments.
Twenty repetitions assert the runtime has exited before Run returns. Existing
real-Lua cancellation and load/goroutine-baseline fixtures remain in the race
suite; this fake runtime test does not prove arbitrary capabilities interruptible.
No engine behavior change was needed. Disk errors still propagate through the
existing sink-error tests. Live Sirius/vGPT report storage remains unvalidated;
this closes the locally testable substitute, not live workflow acceptance.

Planner product skips now distinguish missing identity from mismatched identity.
Focused applicability/identity tests retain the false-clean gate; new probe merge
fuzzing checks caller product/version authority (495714 executions in 10 seconds).
No public API/schema changes, NSE expansion or Phase 3 endpoint-agent work.

Release gates: make check and make acceptance-local passed, including the pinned
real ping++ emitter and emitter-to-Lua fixtures. Further live consumer acceptance
and longer fuzz campaigns remain follow-up work; no performance claim.

## v1.5.0 — module admission and embedder guidance (2026-11-11)

Added ModuleConcurrency, an additive SDK option capping active tasks by exact
script ID and dialect across hosts in each run. Zero preserves global worker
concurrency. Accounting retains only active module keys, bounded by workers;
the scheduler retains host fairness, pacing, cancellation and isolated VMs.
Focused cross-host regression verifies serialization. Existing host/global rate
and cooperative invocation timeout controls are reused rather than duplicated.

Combined declarative product/service/CPE/version fixture tests inclusive version
boundaries and advisory ports under normal and exhaustive execution, retaining
unknown verdicts and skip reasons for excluded versions. Existing matching
language already covers these fields; no new syntax or NSE coverage was needed.
examples/embed now compiles with host/module limits, rate and timeout options;
its README explains per-run limits, context and conservative result handling.
The public signature snapshot was reviewed for the additive option only.

make check and make acceptance-local passed. The embed example executed.
Sequential existing verified 32 × 16 executed-Lua benchmark on linux/amd64,
i9-13900H, four workers (shared host, no performance claim):
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerExecution/selected=false-4         	     100	  12017794 ns/op	     42604 actions/s	15985868 B/op	  158670 allocs/op
BenchmarkPlannerExecution/selected=true-4          	     988	   1376102 ns/op	     46508 actions/s	 2212305 B/op	   21860 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	2.700s

Remaining: broader combined matcher matrices, module-limit throughput comparisons,
longer bounded fuzz campaigns, and live Sirius/vGPT cancellation/persistence
acceptance. Phase 3 remains paused. Local checks do not establish live integration.

## v1.6.0 — matcher matrices and bounded measurements (2026-11-11)

Added a combined Cartesian matrix across product, service, CPE, inclusive and
excluded/missing versions, advisory matching/nonmatching ports, script dialect,
and exhaustive policy. Stub runtimes isolate planner/false-clean policy; the NSE
axis establishes conservative verdict handling, not upstream compatibility.
Skipped records require reasons; no runtime/API or NSE expansion.

Reused BenchmarkPlannerExecution with ModuleConcurrency=0 and 1, four workers,
32 scripts × 16 endpoints, verified action values and complete terminal counts.
Selected runs execute 64 actions and skip 448; unfiltered runs execute 512.
Go 1.26.10 linux/amd64, i9-13900H, shared apps01. Samples ran sequentially after
checks and fuzzing, without overlapping Scribe load. Other host activity remains
uncontrolled. Overlapping timing samples establish no speedup or regression;
this CPU fixture does not predict network workloads or module-limit fairness.

Command: go test ./runtime/lua54 -run '^$' -bench BenchmarkPlannerExecution -benchmem -count=3.

```text
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerExecution/module_limit=0/selected=false-4         	     100	  10377540 ns/op	     49337 actions/s	15986224 B/op	  158604 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=false-4         	     122	  11593530 ns/op	     44163 actions/s	15981293 B/op	  158512 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=false-4         	     100	  10491460 ns/op	     48802 actions/s	15983856 B/op	  158636 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=true-4          	     814	   1565394 ns/op	     40884 actions/s	 2212278 B/op	   21861 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=true-4          	     628	   1690638 ns/op	     37856 actions/s	 2212374 B/op	   21862 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=true-4          	     868	   1321300 ns/op	     48437 actions/s	 2212301 B/op	   21860 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=false-4         	     100	  13099761 ns/op	     39085 actions/s	15974292 B/op	  158424 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=false-4         	     100	  10294101 ns/op	     49737 actions/s	15972266 B/op	  158412 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=false-4         	     100	  10551238 ns/op	     48525 actions/s	15973002 B/op	  158412 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=true-4          	     885	   1704182 ns/op	     37555 actions/s	 2212367 B/op	   21861 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=true-4          	     849	   1497543 ns/op	     42737 actions/s	 2212322 B/op	   21860 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=true-4          	     842	   1627014 ns/op	     39336 actions/s	 2212359 B/op	   21860 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	19.259s
```

Longer bounded campaigns, sequential, each with -race -fuzztime=120s -parallel=4:
FuzzParallelPlanner passed 30,666 executions; FuzzMixedFailures passed 143,604.
These bounded campaigns do not establish absence of defects.

make check and make acceptance-local passed, including real pinned ping++
emitter-to-Lua execution over controlled sockets. Docker lists healthy local
Sirius databases/brokers and running API/UI containers, but the accessible
app-scanner-seams source has no Scribe execution path. No live correlated Sirius
job, cancellation, or report-store persistence acceptance is claimed. Those
require consumer wiring and a controlled workflow/report retrieval contract.
Local fake-store acceptance remains separate. Phase 3 stays paused.

Release deployment: reinstall tagged v1.6.0 on apps01 and require make smoke-http
for completed explicit three-verdict records and the TCP banner fixture.

## v1.7.0 — Lua transport edges and streaming guidance (2026-11-11)

Added controlled socket tests through the Lua tcp.exchange bridge for partial
reads, read deadlines, in-flight cancellation and invalid TLS handshakes.
Partial data completes with an explicit unknown verdict; transport failures
require error/cancelled terminal status and cannot establish a clean result.
Existing certificate verification fixtures reject untrusted TLS certificates.
These original fixtures do not establish upstream NSE compatibility.

Documented the existing Engine.Run callback contract: serialized completion-order
delivery, backpressure, sink error cancellation/draining and conservative verdict
handling. The runnable examples/embed JSONL callback reuses that API; existing
engine tests cover serialization and sink failure. HTTP inline scripts already
use runScripts with the same validation and JSONL path; existing POST tests cover
inline verdicts and conflicting source modes, so no second implementation was added.

make check, make acceptance-local and go run ./examples/embed passed. These are
local SDK/transport/build checks, not live Sirius/vGPT persistence acceptance.
Phase 3 remains paused. No performance claim.

## v1.8.0 — parallel diagnostic isolation (2026-11-11)

Selected the engine-hardening follow-up: 32 parallel Sirius invocations reuse
one runtime and script identity while asserting exact per-invocation logs and
independent action failure. Existing diagnostics truncation/failure fixtures,
static checks and CLI version implementation remain in place; no duplicate path
was added. No public API change or NSE coverage expansion.

make check and make acceptance-local passed, including race, vet, CGO-disabled
build, cross-builds and pinned emitter local acceptance. These are repository
and local transport evidence only. Real-script corpus growth, further verdict
and planner-reason coverage, and live Sirius cancellation/persistence remain
follow-up work. This release adds an original regression, not upstream corpus
compatibility. Phase 3 stays paused; no performance claim.

## v1.9.0 — verdict fields and executable corpus selection (2026-11-11)

Expanded Sirius verdict-field coverage for nil, explicit unknown, boolean, numeric,
table, case/whitespace-invalid values and nested data. Assertions require terminal
execution status as well as conservative verdicts. Added an original MIT HTTP
marker script with a pinned SHA-256 digest, exercising the actual http.get Lua
capability bridge against registered response fixtures. Its 18-case matrix covers
three response markers, matching/missing/conflicting products and normal/exhaustive
selection, with exact product skip reasons and false-clean guards. The fixture is
included in acceptance-local. No production bug was found; no API changes needed.

This grows the executable first-party corpus by one script; it is not an imported
real-world vulnerability corpus or upstream compatibility claim. Broader real-world
script acquisition and protocol acceptance remain unfinished, along with additional
nested matcher/reason cases and live Sirius/vGPT cancellation/report persistence.
Priority remains smart selection, parallel engine, then the existing ping++ adapter.
Phase 3 stays paused. No NSE expansion or performance claim.

Validation: make check and make acceptance-local passed, including race, vet,
cross-compilation, CGO-disabled build and pinned local emitter checks. Registered
HTTP responses establish Lua API behavior; controlled socket acceptance remains
separate from live consumer integration. Tagged service installation and /run smoke
are required as the final operational release step.

## v1.10.0 — nested selection and local acceptance (2026-11-11)

Added nested all_of/any_of product, service, version-boundary and banner cases
under normal/exhaustive execution. Rejected combinations require skipped status,
unknown verdict and a reason; accepted combinations require completed clean verdicts.
Two original MIT TCP/TLS marker scripts join the HTTP script with pinned SHA-256
digests and the shared three-marker/product/exhaustive matrix. These execute the
Lua capability bridge with registered responses; they are not real CVE checks
or additional controlled TLS socket acceptance. Existing socket tests remain separate.

acceptance-local now explicitly runs the repeated cooperative cancellation fake
consumer store gate: active/queued terminal records, synced disk, reopen and decode
to EOF, unique complete evidence and inconclusive assessments. This reuses existing
coverage rather than adding another store. No production bug or API change found.

make check and make acceptance-local passed, including race, vet, CGO-disabled
build, cross-builds and pinned ping++ emitter checks. Remaining: more executable
protocol checks over controlled sockets, exact nested skip-reason distinctions,
and live Sirius/vGPT report persistence. Existing ping++ adapter remains the path;
no NSE expansion. Phase 3 stays paused. No performance claim.

## v1.11.0 — exact reasons and socket corpus (2026-11-11)

Nested matcher exclusions now pin the exact generic declarative reason in normal
runs and the clean identity gate in exhaustive runs. Original pinned HTTP/TCP
marker scripts execute all three markers through real loopback transports.
TLS corpus attempts use untrusted local certificates and require failed/unknown
terminal records; successful trusted TLS corpus execution remains unfinished.
The existing acceptance-local TestMarkerCorpus selector includes these sockets.

make check and make acceptance-local passed. The next repository hardening item
uses a sequential 30-second race-instrumented FuzzProbeIdentityAuthority campaign
with four workers. Local evidence does not establish live Sirius/vGPT cancellation
or persisted reports. Those consumer gates, trusted TLS corpus success and broader
real-world corpus acquisition remain open. No NSE expansion or performance claim;
Phase 3 stays paused.

The bounded identity-authority fuzz campaign passed 18,577 executions.

## v1.12.0 — trusted TLS corpus and adapter conflict coverage (2026-11-12)

The pinned TLS marker script now executes against a loopback TLS listener using
an ephemeral locally generated CA certificate. An isolated test process trusts
that CA through the system root configuration used by the existing TCP capability;
certificate verification stays enabled. Shared socket assertions require completed
vulnerable, not_vulnerable and unknown marker results, while existing untrusted
TLS cases still require failed/unknown records. No production API was needed.

The existing pingpp.scan/v1 adapter now has regression coverage for contradictory
versions of the same product in both claim orders. Product/version remain unknown
while independent HTTP and TLS observations survive. No second mapper or upstream
schema change, NSE expansion, or performance claim. Phase 3 stays paused.

Validation: make check and make acceptance-local passed. These establish local
transport, SDK, race, static and cross-build evidence, separate from live
Sirius/vGPT cancellation and persisted-report acceptance. Broader real-world
corpus acquisition and live consumer acceptance remain open.

## v1.13.0 — configuration corpus and limiter measurements (2026-11-12)

Added an original MIT pinned HTTP CSP/nosniff configuration script with explicit
match and verdict blocks. The existing corpus matrix checks missing headers,
present headers and non-200 unknown results across product identity and exhaustive
policy. This is a practical configuration check using registered responses, not
a CVE claim or acquired upstream corpus. Broader real-world corpus acquisition
remains open. Nested matcher tests now pin missing version, banner and service
skip reasons under both policies. README refresh links the existing embed example
and explains grants, stream completeness and admission limits.

make check and make acceptance-local passed. Reused BenchmarkPlannerExecution,
Go 1.26.10 linux/amd64 on shared apps01, i9-13900H, four workers, three sequential
samples after validation with no overlapping Scribe load/fuzz run. Each batch has
512 terminal records; unfiltered executes 512 actions, selected executes 64 and
skips 448. actions/s divides verified completed actions by elapsed batch time;
selection therefore changes both numerator and work. ns/op measures whole batches,
not individual actions. ModuleConcurrency 0 resolves to four; 1 caps each exact
dialect/script key. Scheduler review confirms module/host caps precede admission
and GlobalInterval/HostInterval pace starts; both intervals are zero here. These
CPU fixtures do not measure network rate limiting or prove throughput improvements.
Shared-host variation prevents a speedup claim.

Command: go test ./runtime/lua54 -run '^$' -bench '^BenchmarkPlannerExecution$' -benchmem -count=3

```text
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerExecution/module_limit=0/selected=false-4         	     100	  10287142 ns/op	     49771 actions/s	15982916 B/op	  158610 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=false-4         	     100	  10715554 ns/op	     47781 actions/s	15982235 B/op	  158630 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=false-4         	      98	  10796543 ns/op	     47423 actions/s	15982471 B/op	  158588 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=true-4          	     993	   1841220 ns/op	     34760 actions/s	 2212416 B/op	   21861 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=true-4          	     982	   1381095 ns/op	     46340 actions/s	 2212326 B/op	   21860 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=true-4          	     902	   1483526 ns/op	     43141 actions/s	 2212376 B/op	   21861 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=false-4         	      94	  10788757 ns/op	     47457 actions/s	15975412 B/op	  158423 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=false-4         	      78	  13390126 ns/op	     38237 actions/s	15978810 B/op	  158467 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=false-4         	     102	  11730529 ns/op	     43647 actions/s	15974908 B/op	  158414 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=true-4          	     694	   1553472 ns/op	     41198 actions/s	 2212417 B/op	   21861 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=true-4          	     669	   1508143 ns/op	     42436 actions/s	 2212413 B/op	   21861 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=true-4          	     883	   2044292 ns/op	     31307 actions/s	 2212449 B/op	   21862 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	16.755s
```

Live Sirius/vGPT persisted-report acceptance remains separate and unfinished.
No NSE expansion; Phase 3 remains paused.

## v1.14.0 — fixture-to-store acceptance (2026-11-12)

Added a local pingpp.scan/v1 fixture → existing adapter → strict planner → Lua
engine → report.Map → synced JSONL file → reopened EOF round trip. It preserves
canonical report evidence, caller product and source digest for completed clean,
product-skipped and Lua action-error cases. Noncompleted evidence must remain
inconclusive. The existing acceptance-local TestMarkerCorpus selector runs it.
This fake consumer store establishes local persistence only; live correlated
Sirius/vGPT report retrieval, cancellation and storage wiring remain unfinished.

Added an original MIT SHA-256-pinned HTTP session-cookie configuration check.
The shared corpus matrix covers missing Secure/HttpOnly flags, both flags,
unrecognized cookies, product mismatch/missing identity and exhaustive policy.
This is registered-response configuration evidence, not a CVE or upstream corpus
claim. Broader HTTP/TCP/TLS practical corpus growth remains open; this slice adds
one HTTP script and reuses existing TCP/TLS socket coverage. No production API
change or NSE expansion. Phase 3 remains paused.

Validation: make check and make acceptance-local passed. Release operations
reinstall the tagged systemd service and smoke the trusted POST :18081/run path.

## v1.15.0 — configuration corpus and deadline isolation (2026-11-12)

Three original MIT SHA-256-pinned fixtures extend the shared normal/exhaustive,
matching/missing/conflicting product and three-verdict matrix: FTP anonymous USER
policy response, legacy TLS version observation, and HTTP directory-index response.
The FTP fixture observes the USER policy response, not successful anonymous login;
the HTTP fixture recognizes an exact index title, not arbitrary directory listings.
These registered responses establish Lua bridge and conservative verdict behavior,
not general protocol interoperability or CVE coverage. Existing trusted/untrusted
TLS and TCP socket corpus acceptance remains in place. Broader practical socket
corpus growth remains open. No NSE expansion; Phase 3 stays paused.

A focused engine regression requires invocation deadline isolation, aggregated
execution error, unknown timeout verdict and complete sibling terminal delivery.
Existing cancellation/drain, sink-error and fake-store completeness gates are reused.
make check and make acceptance-local passed. BenchmarkPlannerExecution ran after
these gates without overlapping Scribe fuzz/load work; it verifies 512 terminal
records, 512 unfiltered or 64 selected actions (448 skips), with module limits 0/1.
Single shared-host samples are sanity evidence and support no speedup claim.

Consumer audit: apps01 has running Sirius API/UI and storage containers; the local
vGPT services/agent-api.py references the trusted Scribe HTTP endpoint. This does
not establish a reachable controlled correlated job/report retrieval contract.
Live Sirius/vGPT cancellation and persisted-report acceptance remains open; no new
infrastructure was introduced. Local fake-store evidence is separate.

Benchmark raw sample (linux/amd64, Go toolchain on apps01, i9-13900H, four workers):

```text
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerExecution/module_limit=0/selected=false-4         	     116	   9710503 ns/op	     52726 actions/s	15982138 B/op	  158611 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=true-4          	     854	   1329825 ns/op	     48127 actions/s	 2212370 B/op	   21861 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=false-4         	     100	  10507545 ns/op	     48727 actions/s	15974506 B/op	  158414 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=true-4          	     772	   1762090 ns/op	     36321 actions/s	 2212493 B/op	   21862 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	5.873s
```

## v1.16.0 — socket identity matrices and live correlated retrieval (2026-11-12)

The original digest-pinned HTTP/TCP/TLS marker corpus now runs its real socket
three-verdict cases across matching, missing and conflicting product facts and
normal/exhaustive selection. Exact skip reasons, unknown skipped verdicts and
untrusted TLS failures are asserted through the existing selected runner. The
trusted TLS child retains certificate verification. This broadens socket policy
coverage; it does not add CVE or upstream corpus claims.

Live apps01 → vGPT agent-api 192.168.123.43:8090 /agent/run-script → installed
Scribe POST :18081/run → vGPT /runs/8aca19e11e8e retrieval succeeded. Committed
acceptance/v1.16.0-vgpt.json contains the response and independently retrieved
run record, source digest and explicit completed/unknown evidence. The controlled
script performs no target I/O; its correlation marker survives retrieval. The
consumer source stores runs in /srv/vgpt/agent-api/runs.json. This is live vGPT
run-record persistence evidence, not Sirius report-envelope storage acceptance.
The tested service was the previously installed release; the v1.16.0 service is
separately reinstalled and smoke-tested at release.

Still blocked/open: Sirius report-store ingestion/retrieval has no established
controlled job submission and report correlation contract in this checkout;
no Sirius storage acceptance is claimed. Live vGPT cancellation is also open:
the inspected agent-api routes provide synchronous execution and run retrieval,
but no cancellation route. Disk durability/restart recovery and concurrent
run-store integrity are unverified (consumer save_run rewrites JSON without an
atomic transaction). These require consumer work, not another Scribe mapper.
Broader practical TCP/TLS scripts remain open. No NSE expansion; Phase 3 stays paused.

Validation: make check and make acceptance-local; release service smoke recorded
separately from consumer acceptance. No performance claim.

## v1.17.0 — concurrent local persistence and SMTP policy corpus (2026-11-12)

Eight parallel independent SDK consumer stores reuse the existing pingpp → strict
planner → Lua → report envelope round trip. Each syncs, closes and independently
reopens its file to EOF and compares canonical evidence for completed, skipped
and failed execution. This is concurrent store isolation and synced readback
coverage, not shared-file transaction, crash recovery or power-loss durability.

Two original MIT SHA-256-pinned TCP/TLS SMTP VRFY policy fixtures extend the shared
three-verdict, product identity and exhaustive policy matrix. Exact `250 root`
responses expose the controlled account; exact `502 Command not implemented`
responses indicate disabled VRFY; other responses remain unknown. TLS requires
TLS evidence. Registered responses establish API/verdict behavior, not SMTP socket
interoperability, general account enumeration or CVE coverage. Broader practical
socket corpus remains open; existing trusted/untrusted TLS socket gates are reused.

Consumer source reinspection: vGPT services/agent-api.py still implements save_run
as load/filter plus direct runs.json rewrite, without atomic replacement or a
transaction. Its synchronous run-script route has no cancellation route. No live
cancellation, restart durability or concurrent shared-store safety is claimed.
Sirius report-envelope submission/correlation remains unestablished; the adjacent
workspace's generic API/database acceptance does not establish Scribe report
storage. Those consumer changes and live acceptance remain open rather than
introducing storage into Scribe or another mapper.

Validation: make check and make acceptance-local passed, including race, vet,
CGO-disabled build and platform cross-build gates. Service release smoke is
separate from consumer acceptance. No NSE expansion or performance claim;
Phase 3 stays paused.


## v1.18.0 — Redis TCP/TLS authentication policy corpus (2026-11-12)

Two original MIT SHA-256-pinned fixtures send a Redis RESP PING request.
Exact PONG indicates unauthenticated command access; exact NOAUTH indicates
authentication is required for this command. Other responses remain unknown.
The TLS variant requires TLS response evidence before either explicit verdict.
These registered-response checks establish Lua bridge and policy behavior, not
Redis socket interoperability, comprehensive authorization security or CVE coverage.

The shared corpus harness retains normal/exhaustive product matching, missing
and conflicting identity skips, exact skip reasons and unknown skipped verdicts.
New cases assert the exact outbound request and missing TLS evidence false-clean
guard. No runtime API, dependency or NSE expansion. Broader practical socket
corpus and consumer-side persistence/cancellation work remain open; Phase 3 stays
paused.

Validation: make check and make acceptance-local passed. BenchmarkPlannerExecution
ran sequentially afterward without overlapping Scribe fuzz/load work, Go 1.26.10
linux/amd64, shared apps01 i9-13900H, four workers. Each batch verifies 512 terminal
records, 512 unfiltered actions or 64 selected actions with 448 skips; module
limits are 0/1. Raw single samples below support no speedup claim.

Command: go test ./runtime/lua54 -run '^$' -bench '^BenchmarkPlannerExecution$' -benchmem -count=1

```text
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerExecution/module_limit=0/selected=false-4         	     123	   9395141 ns/op	     54496 actions/s	15980772 B/op	  158586 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=true-4          	     706	   1654508 ns/op	     38682 actions/s	 2212473 B/op	   21863 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=false-4         	     123	  12262802 ns/op	     41752 actions/s	15974280 B/op	  158399 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=true-4          	     762	   1420527 ns/op	     45054 actions/s	 2212378 B/op	   21860 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	8.065s
```

## v1.19.0 — bounded failure batches and UTF-8 initialization (2026-11-12)

Allocation sampling of the verified planner benchmark attributed 46.70% of bytes
cumulatively to loadLibraries and 31.55% to SetEnvGoFunc. UTF-8's five immutable,
capture-free Go functions and constant charpattern now follow the table builtin
pattern. Mutable tables remain invocation-owned, populated with accounted SetEnv;
no VM pooling or public API change. Mutation/reexecution checks cover UTF-8.

FuzzMixedFailures now exercises eight-task concurrent engine batches, mixed exact
grants and near-match denials, Lua errors and sink failures. Ten-second bounded
race campaigns passed 5993 mixed-failure and 10352 planner executions. These are
finite local campaigns; longer scheduled campaigns remain follow-up work.

Original SHA-256-pinned TCP/TLS POP3 USER fixtures extend the shared corpus matrix.
Only exact controlled login/authentication-required responses establish verdicts;
missing TLS evidence, unexpected replies and mismatched products stay inconclusive.
This is registered-response policy evidence, not POP3 socket or CVE acceptance.

One-iteration before/after benchmark samples were exploratory and included cold
initialization; they establish no throughput claim. Profile and raw samples are
retained in /tmp/scribe-before.mem and /tmp/scribe-{before,after}.txt for this run.
Phase 3 stays paused. Live consumer cancellation and durable report persistence,
broader socket corpus and longer fuzz campaigns remain unfinished.

Validation: make check and make acceptance-local passed, including race tests,
vet, CGO-disabled build, cross-builds and local persistence/socket gates.
A repeated planner fuzz run spent its budget processing 347 accumulated seeds
and passed; it does not represent 347 new mutations. Shared-host benchmark
timings remain unsuitable for a speedup claim.

## v1.20.0 — bounded long fuzz target and socket false-clean guards (2026-11-12)

`make fuzz-long` runs planner, mixed engine failure and pingpp reader campaigns
sequentially under the race detector, defaulting to five minutes each and two
workers. Override FUZZ_TIME and FUZZ_WORKERS for the available host budget.
For a caller-owned nightly schedule, run `make fuzz-long` from this checkout
and retain stdout/stderr and the exit status. No scheduler is installed by this
release. Go retains discovered failures in testdata/fuzz; review and commit useful
regressions. Avoid overlapping campaigns with throughput measurements.

The existing real TCP and isolated trusted TLS marker matrix now includes trailing
clean-like data, uppercase CLEAN and empty responses alongside all three verdicts.
These must complete with unknown verdicts, including exhaustive selection. Missing
and conflicting product facts still skip; untrusted TLS still fails unknown.
This extends original marker socket evidence, not real POP3/Redis/SMTP coverage.

Local vGPT source reinspection still finds load/filter/direct runs.json rewrite
in services/agent-api.py save_run, without atomic replacement or sync, and no
cancellation endpoint. Live cancellation and durable consumer report acceptance
remain infeasible without consumer changes; local fake-store acceptance remains
separate evidence. No consumer repository was modified. Phase 3 stays paused.

Validation: make check and make acceptance-local passed, plus explicit
CGO_ENABLED=0 go build ./cmd/scribe. make fuzz-long FUZZ_TIME=60s passed all
three sequential race campaigns with two workers (including baseline replay).
Logs for this host run: /tmp/scribe120-{check,acceptance,fuzz}.log.
The new cases exposed an unanchored trusted-TLS child test selector; anchoring
each path component prevents prefix matches from sharing cached certificate roots.

## v1.21.0 — Redis socket policy acceptance (2026-11-12)

The existing socket corpus harness now executes the pinned original Redis PING
scripts over real loopback TCP and certificate-verified TLS. It checks the exact
RESP request and completed vulnerable, authentication-required and unknown results,
including trailing clean-like data, uppercase and empty replies. Matching, missing
and conflicting caller products run under normal and exhaustive selection with
exact skip reasons and unknown skipped verdicts. The isolated local CA child and
bounded listener are reused; no production API or second runner was added.

This is controlled Redis command-policy socket evidence, not comprehensive Redis
authorization, CVE coverage or live consumer persistence acceptance. Broader
POP3/SMTP socket coverage remains open. Phase 3 stays paused.

Validation: make check and make acceptance-local; release installation and POST
:18081/run smoke are separate operational evidence. No throughput claim.

## v1.22.0 — POP3 socket policy acceptance (2026-11-12)

The existing socket matrix now executes the original pinned POP3 USER scripts
over loopback TCP and certificate-verified TLS. Protocol parameters share one
request/response matrix with the existing fixtures, avoiding a second runner.
Exact USER root requests, three verdicts, trailing clean-like data, uppercase
and empty replies retain conservative results. Missing/conflicting products
skip under normal and exhaustive selection with exact reasons.

This closes the POP3 socket gap identified above. It is controlled USER-response
policy evidence, not full POP3 session/login interoperability or CVE coverage.
SMTP socket coverage, live consumer cancellation and durable report persistence
remain unfinished. Phase 3 stays paused. No production API or dependency changes.

Validation: make check and make acceptance-local; service reinstall and POST
:18081/run smoke are separate operational evidence.

## v1.23.0 — SMTP socket policy acceptance (2026-11-12)

The shared socket matrix executes the pinned original SMTP VRFY fixtures over
loopback TCP and certificate-verified TLS. Exact VRFY root requests, three
verdicts, malformed/trailing/empty responses and normal/exhaustive product gates
reuse the existing bounded listener and isolated CA child. The fixtures retain
their historical http service hint; this is controlled single-exchange policy
evidence, not SMTP greeting/session interoperability or general enumeration.

Consumer reinspection: local vgpt/services/agent-api.py still directly rewrites
runs.json and exposes synchronous run-script/retrieval without cancellation.
The live :8090 endpoint responds (GET /health returns 404), but no controlled
cancellation contract exists. Live cancellation and durable consumer persistence
acceptance remain blocked on consumer implementation; no acceptance is claimed
from local fake stores. No consumer code or Phase 3 work was changed.

Validation: make check and make acceptance-local. Release installation and the
complete POST :18081/run smoke stream are separate operational checks.

## v1.24.0 — linear pending-queue retirement (2026-11-12)

Priority review selected engine scheduling hardening after the completed planner
policy matrices. Cancellation and exhausted host budgets previously removed each
pending task with a slice shift, causing quadratic copying within the bounded
window. A stable in-place pass now retains eligible tasks and emits terminal
records in the same order with linear copying. Removed slots are cleared both
on compaction and normal admission to release stale script/target references.
Worker isolation, host/module admission and fairness policy remain unchanged.

A 4096-task regression checks cancellation completeness, exact queued order,
unique terminal records and unknown verdicts; existing budget/strategy tests cover
mixed retirement. SMTP/POP3/Redis socket corpora are complete for this priority
pass; no further socket fixtures were added. Live consumer cancellation remains
blocked and Phase 3 stays paused. Shared-host executed-Lua samples below are
throughput evidence only, with no before/after speedup claim.

Validation: make check and make acceptance-local passed; the new large-window
regression also passed ten race-enabled repetitions. Sequential make fuzz-long
FUZZ_TIME=10s passed planner, mixed-failure and adapter campaigns.
Benchmark environment: Go 1.26.10 linux/amd64, apps01 shared i9-13900H,
four workers; 512 terminal records, 512 unfiltered or 64 selected verified actions.
ModuleConcurrency 0/1; no overlapping Scribe fuzz/load work.

```text
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerExecution/module_limit=0/selected=false-4         	      99	  11642598 ns/op	     43976 actions/s	15857708 B/op	  156008 allocs/op
BenchmarkPlannerExecution/module_limit=0/selected=true-4          	    1059	   1755500 ns/op	     36457 actions/s	 2196979 B/op	   21541 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=false-4         	     100	  10937823 ns/op	     46810 actions/s	15851163 B/op	  155849 allocs/op
BenchmarkPlannerExecution/module_limit=1/selected=true-4          	     747	   1922628 ns/op	     33288 actions/s	 2197087 B/op	   21542 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	6.814s
```

## v1.25.0 — branch-aware planner identification (2026-11-12)

Satisfied any_of alternatives now suppress requests for missing facts in sibling
branches, including nested all_of groups. This lets selected runs reuse supplied
service identification without an unnecessary passive probe for an alternative
product. Unresolved alternatives still request identification; all_of requirements
remain mandatory. Existing applicability and explicit product clean gates remain
in force. Focused tests cover satisfied, unresolved and required branches.

Validation: make check and make acceptance-local. Service reinstall and complete
POST :18081/run smoke are operational evidence, separate from consumer persistence.
Live consumer cancellation remains blocked; Phase 3 stays paused.

Both required targets passed. Sequential make fuzz-long FUZZ_TIME=15s passed;
planner budget covered partial baseline replay, mixed failures reached 1997
executions. An earlier five-second mixed-failure attempt exhausted its deadline
during baseline replay; the longer retry passed. No throughput claim.

## v1.26.0 — endpoint-indexed ping++ identity claims (2026-11-12)

The next adapter throughput slice indexes pingpp.scan/v1 claims by exact endpoint
subject once per document. Endpoint conversion now visits only that endpoint's
claims instead of rescanning the full claim collection for every endpoint.
Existing confidence, contradiction, product conflict and TLS rules are reused.
A focused regression pins endpoint isolation and preserves original fixture facts.
No public API or wire schema changes; no measured throughput claim.

Validation: make check and make acceptance-local. This is local adapter/build
acceptance; live consumer cancellation and durable persistence remain blocked.
Phase 3 stays paused. Service reinstall and POST smoke are operational evidence.

## v1.27.0 — ping++ reader queue retention (2026-11-12)

The existing pingpp.scan/v1 reader now clears each consumed pending target and
releases the backing array when drained. This closes a memory-retention gap in
the streaming adapter without changing wire mapping, endpoint order or public
API. A focused regression retains the backing slice and verifies slots are
cleared while returned target facts and order remain intact.

Validation: make check and make acceptance-local. This is local adapter/build
acceptance, with no measured throughput claim. Live consumer cancellation and
durable persistence remain blocked on the consumer contract. Phase 3 stays paused.
Service reinstall and complete POST smoke are separate operational evidence.

## v1.28.0 — planner alternative evaluation (2026-11-12)

Priority review selected the planner's any_of evaluation loop. Once applicability
and positive product identification are both established, remaining alternatives
cannot change the result and are no longer evaluated. Service-only matches still
visit later alternatives to collect product evidence for the existing clean gate.
Focused regressions pin later/earlier matching products and mismatched products.
No public API, identity authority or verdict policy changes; no throughput claim.
Live consumer persistence remains blocked; Phase 3 stays paused.

Validation logs: /tmp/scribe128-check.log, /tmp/scribe128-acceptance.log and
/tmp/scribe128-fuzz.log. Service installation and complete HTTP smoke are
operational evidence, separate from consumer workflow acceptance.

Both required targets passed. The initial ten-second planner fuzz budget expired
in baseline replay; the 45-second retry passed with 7,106 executions. No measured
speedup is claimed. Retry log: /tmp/scribe128-fuzz-retry.log.

## v1.29.0 — bounded ping++ error diagnostics (2026-11-12)

Priority review selected the existing adapter's upstream error propagation.
Previously an error payload could be copied in full into downstream diagnostics,
including direct SDK documents beyond the JSONL reader's document ceiling.
Error details now retain at most 1 KiB with an explicit truncation marker.
Small diagnostics remain intact; upstream failures still return no targets.
Focused regressions cover the boundary, oversized payloads and sticky terminal
reader errors. No public API or wire schema change and no throughput claim.

Validation: make check and make acceptance-local; logs in
/tmp/scribe129-check.log and /tmp/scribe129-acceptance.log.
The sequential bounded adapter race fuzz campaign passed 33,927 executions
(/tmp/scribe129-fuzz.log). Service reinstall and complete HTTP smoke are
operational evidence only. Live consumer cancellation/persistence remains
blocked on the consumer contract; Phase 3 stays paused.

## v1.30.0 — bounded ping++ schema diagnostics (2026-11-12)

Adapter hardening continues with unsupported schema diagnostics: caller-supplied
schema strings previously bypassed the upstream error detail limit. A shared
helper now caps both details at 1 KiB before formatting, with explicit truncation.
Quoted control bytes can expand within a finite formatted bound. Focused tests
cover boundary lengths, oversized direct SDK input, escaped control bytes and
sticky terminal streaming errors; failures never produce targets.

No public API or wire schema change and no performance claim. Live consumer
cancellation/persistence remains blocked on the consumer contract; Phase 3 stays
paused. Validation logs: /tmp/scribe130-{check,acceptance,fuzz}.log. Service
reinstallation and complete HTTP smoke are separate operational evidence.

make check, make acceptance-local and the explicit CGO-disabled CLI build passed.
The bounded reader race fuzz campaign passed 13,502 executions with two workers.

## v1.31.0 — measured worker scaling (2026-11-12)

Extended the existing verified executed-Lua benchmark across 1, 2, 4 and 8
workers, retaining module limits 0/1 and selected/unfiltered paths. This closes
the fixed-four-worker measurement gap without introducing another benchmark
runner or changing production scheduling. Each iteration requires 512 terminal
records and checks every completed action returns 5050. Unfiltered runs execute
512 actions; selected runs execute 64 and skip 448.

Environment: apps01 shared i9-13900H, Go 1.26.10 linux/amd64, GOMAXPROCS=8.
Command: go test ./runtime/lua54 -run '^$' -bench '^BenchmarkPlannerExecution$'
-benchtime=500ms -count=3 -cpu=8. No overlapping Scribe tests/fuzz/load.
Medians below are verified actions/s across three samples, not endpoint or
terminal-record throughput. Module limit zero uses the worker count.

| Workers | Module limit | Unfiltered actions/s | Selected actions/s |
| --- | --- | --- | --- |
| 1 | 0 | 17,528 | 18,078 |
| 1 | 1 | 16,912 | 17,659 |
| 2 | 0 | 11,556 | 14,869 |
| 2 | 1 | 14,826 | 12,206 |
| 4 | 0 | 14,905 | 14,500 |
| 4 | 1 | 12,186 | 16,827 |
| 8 | 0 | 17,008 | 23,001 |
| 8 | 1 | 19,412 | 15,900 |

Selection reduces executed work eightfold, so compare elapsed ns/op in the raw
samples when assessing batch latency. It does not imply an eightfold increase
in actions/s. These short CPU actions include Lua setup, compilation, scheduling,
output conversion and serialized sink checks; worker overhead and shared-host
variation limit scaling. These are current-path measurements, not a before/after
speedup claim or a model for network-bound scripts.

Raw samples:

```text
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerExecution/workers=1/module_limit=0/selected=false-8         	      26	  25460905 ns/op	     20109 actions/s	15885368 B/op	  156274 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=0/selected=false-8         	      26	  29210261 ns/op	     17528 actions/s	15887935 B/op	  156282 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=0/selected=false-8         	      20	  31788274 ns/op	     16107 actions/s	15898029 B/op	  156445 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=0/selected=true-8          	     156	   3870309 ns/op	     16536 actions/s	 2197615 B/op	   21556 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=0/selected=true-8          	     204	   2704116 ns/op	     23668 actions/s	 2197146 B/op	   21551 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=0/selected=true-8          	     180	   3540295 ns/op	     18078 actions/s	 2197360 B/op	   21553 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=1/selected=false-8         	      24	  30104317 ns/op	     17008 actions/s	15885516 B/op	  156333 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=1/selected=false-8         	      19	  36925117 ns/op	     13866 actions/s	15904308 B/op	  156478 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=1/selected=false-8         	      21	  30274544 ns/op	     16912 actions/s	15895685 B/op	  156408 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=1/selected=true-8          	     169	   3223700 ns/op	     19853 actions/s	 2197425 B/op	   21554 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=1/selected=true-8          	     165	   4331990 ns/op	     14774 actions/s	 2197610 B/op	   21555 allocs/op
BenchmarkPlannerExecution/workers=1/module_limit=1/selected=true-8          	     160	   3624305 ns/op	     17659 actions/s	 2197515 B/op	   21555 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=0/selected=false-8         	      14	  44307685 ns/op	     11556 actions/s	15985116 B/op	  157294 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=0/selected=false-8         	      10	  71517659 ns/op	      7159 actions/s	16005122 B/op	  157385 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=0/selected=false-8         	      19	  35559814 ns/op	     14398 actions/s	15930316 B/op	  156679 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=0/selected=true-8          	     152	   3593038 ns/op	     17812 actions/s	 2198979 B/op	   21566 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=0/selected=true-8          	     181	   4304234 ns/op	     14869 actions/s	 2198898 B/op	   21564 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=0/selected=true-8          	     172	   4343371 ns/op	     14735 actions/s	 2199182 B/op	   21565 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=1/selected=false-8         	      16	  38236732 ns/op	     13390 actions/s	15941356 B/op	  156700 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=1/selected=false-8         	      22	  34533610 ns/op	     14826 actions/s	15920442 B/op	  156470 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=1/selected=false-8         	      20	  27806218 ns/op	     18413 actions/s	15927610 B/op	  156546 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=1/selected=true-8          	     144	   3893405 ns/op	     16438 actions/s	 2199637 B/op	   21567 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=1/selected=true-8          	     187	   5243260 ns/op	     12206 actions/s	 2199003 B/op	   21563 allocs/op
BenchmarkPlannerExecution/workers=2/module_limit=1/selected=true-8          	     100	   6749001 ns/op	      9483 actions/s	 2199227 B/op	   21568 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=0/selected=false-8         	      15	  34351480 ns/op	     14905 actions/s	15963747 B/op	  156991 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=0/selected=false-8         	      19	  31180957 ns/op	     16420 actions/s	15976081 B/op	  157217 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=0/selected=false-8         	      21	  35367358 ns/op	     14477 actions/s	15951910 B/op	  156887 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=0/selected=true-8          	     144	   4413694 ns/op	     14500 actions/s	 2200147 B/op	   21567 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=0/selected=true-8          	     100	   7024680 ns/op	      9111 actions/s	 2200748 B/op	   21570 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=0/selected=true-8          	     169	   3078632 ns/op	     20788 actions/s	 2200237 B/op	   21568 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=1/selected=false-8         	      15	  52427970 ns/op	      9766 actions/s	15953431 B/op	  156770 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=1/selected=false-8         	      14	  42013813 ns/op	     12186 actions/s	15958207 B/op	  156849 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=1/selected=false-8         	      19	  26322318 ns/op	     19451 actions/s	15937018 B/op	  156622 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=1/selected=true-8          	     100	   5307918 ns/op	     12057 actions/s	 2201726 B/op	   21573 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=1/selected=true-8          	     186	   3803345 ns/op	     16827 actions/s	 2200549 B/op	   21567 allocs/op
BenchmarkPlannerExecution/workers=4/module_limit=1/selected=true-8          	     170	   3397818 ns/op	     18836 actions/s	 2200725 B/op	   21569 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=0/selected=false-8         	      22	  23355825 ns/op	     21922 actions/s	15972747 B/op	  157188 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=0/selected=false-8         	      32	  30102920 ns/op	     17008 actions/s	15931995 B/op	  156600 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=0/selected=false-8         	      15	  40324397 ns/op	     12697 actions/s	15987268 B/op	  157152 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=0/selected=true-8          	     222	   2782473 ns/op	     23001 actions/s	 2202856 B/op	   21571 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=0/selected=true-8          	     183	   3350407 ns/op	     19102 actions/s	 2203035 B/op	   21572 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=0/selected=true-8          	     241	   2599849 ns/op	     24617 actions/s	 2202522 B/op	   21571 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=1/selected=false-8         	      40	  19720766 ns/op	     25962 actions/s	15902320 B/op	  156254 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=1/selected=false-8         	      30	  26374809 ns/op	     19412 actions/s	15908227 B/op	  156356 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=1/selected=false-8         	      31	  30854878 ns/op	     16594 actions/s	15910668 B/op	  156335 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=1/selected=true-8          	     188	   3389513 ns/op	     18882 actions/s	 2202853 B/op	   21570 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=1/selected=true-8          	     188	   4430246 ns/op	     14446 actions/s	 2202977 B/op	   21571 allocs/op
BenchmarkPlannerExecution/workers=8/module_limit=1/selected=true-8          	     211	   4025112 ns/op	     15900 actions/s	 2202066 B/op	   21565 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	49.837s
```

Validation: make check passed (race suite, external SDK acceptance, vet,
CGO-disabled CLI build and Windows/Darwin cross-compilation). No public API,
wire schema or runtime policy changed. Live consumer cancellation/persistence
remains separate and blocked on its contract. Phase 3 stays paused.

## v1.32.0 — longer executed-Lua worker matrix (2026-11-12)

Priority review selected the remaining workload-duration measurement gap in the
parallel engine. The existing planner benchmark now shares its runner and source
builder with BenchmarkPlannerLongExecution: 100,000 additions per action rather
than 100. Both retain 32 scripts × 16 targets, workers 1/2/4/8, module limits
0/1, and selected/unfiltered paths. Every action sum and all 512 terminal records
are checked; selected runs complete 64 actions. A race-suite regression executes
the same longer source at one and eight workers and checks explicit unknown
verdicts, sums and complete records. Production scheduling and public APIs do
not change.

Environment: apps01 shared i9-13900H, Go 1.26.10 linux/amd64, GOMAXPROCS=8.
Command: go test ./runtime/lua54 -run '^$' -bench
'^BenchmarkPlannerLongExecution$' -benchtime=1x -count=3 -cpu=8.
Samples ran without overlapping Scribe test/fuzz/load work. Longer CPU work
shows useful parallel execution in this controlled workload; this is neither a
before/after engine speedup nor network-bound throughput evidence. ns/op is
batch latency; actions/s counts verified completed actions, excluding skips.
One iteration per sample limits statistical confidence; shared-host variation
remains. Raw samples follow.

```text
goos: linux
goarch: amd64
pkg: github.com/SiriusScan/scribe/runtime/lua54
cpu: 13th Gen Intel(R) Core(TM) i9-13900H
BenchmarkPlannerLongExecution/workers=1/module_limit=0/selected=false-8         	       1	2651972837 ns/op	       193.1 actions/s	17148040 B/op	  170968 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=0/selected=false-8         	       1	2493481129 ns/op	       205.3 actions/s	16885744 B/op	  170546 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=0/selected=false-8         	       1	2391529978 ns/op	       214.1 actions/s	16816744 B/op	  170539 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=0/selected=true-8          	       1	 306805524 ns/op	       208.6 actions/s	 2339736 B/op	   23439 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=0/selected=true-8          	       1	 330864694 ns/op	       193.4 actions/s	 2339096 B/op	   23436 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=0/selected=true-8          	       1	 318042211 ns/op	       201.2 actions/s	 2339576 B/op	   23437 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=1/selected=false-8         	       1	2554064050 ns/op	       200.5 actions/s	16929704 B/op	  170580 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=1/selected=false-8         	       1	2513548492 ns/op	       203.7 actions/s	16960672 B/op	  170570 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=1/selected=false-8         	       1	2513193321 ns/op	       203.7 actions/s	16886656 B/op	  170548 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=1/selected=true-8          	       1	 311095297 ns/op	       205.7 actions/s	 2339832 B/op	   23446 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=1/selected=true-8          	       1	 283176910 ns/op	       226.0 actions/s	 2339576 B/op	   23437 allocs/op
BenchmarkPlannerLongExecution/workers=1/module_limit=1/selected=true-8          	       1	 312331735 ns/op	       204.9 actions/s	 2339608 B/op	   23444 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=0/selected=false-8         	       1	1326673605 ns/op	       385.9 actions/s	17149048 B/op	  171146 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=0/selected=false-8         	       1	1261888061 ns/op	       405.7 actions/s	17054424 B/op	  171493 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=0/selected=false-8         	       1	1258762707 ns/op	       406.7 actions/s	17189584 B/op	  171936 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=0/selected=true-8          	       1	 153223796 ns/op	       417.7 actions/s	 2340472 B/op	   23442 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=0/selected=true-8          	       1	 164565580 ns/op	       388.9 actions/s	 2341448 B/op	   23451 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=0/selected=true-8          	       1	 164497597 ns/op	       389.1 actions/s	 2303032 B/op	   23437 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=1/selected=false-8         	       1	1482141688 ns/op	       345.4 actions/s	17200880 B/op	  170736 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=1/selected=false-8         	       1	1427020821 ns/op	       358.8 actions/s	17122864 B/op	  170699 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=1/selected=false-8         	       1	1408075861 ns/op	       363.6 actions/s	17386032 B/op	  170791 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=1/selected=true-8          	       1	 167437474 ns/op	       382.2 actions/s	 2381008 B/op	   23468 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=1/selected=true-8          	       1	 173073896 ns/op	       369.8 actions/s	 2381392 B/op	   23469 allocs/op
BenchmarkPlannerLongExecution/workers=2/module_limit=1/selected=true-8          	       1	 172544260 ns/op	       370.9 actions/s	 2378216 B/op	   23458 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=0/selected=false-8         	       1	 896837459 ns/op	       570.9 actions/s	17721224 B/op	  171811 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=0/selected=false-8         	       1	1191895907 ns/op	       429.6 actions/s	17809016 B/op	  172722 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=0/selected=false-8         	       1	1332683267 ns/op	       384.2 actions/s	17793152 B/op	  173056 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=0/selected=true-8          	       1	 153258145 ns/op	       417.6 actions/s	 2460512 B/op	   23527 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=0/selected=true-8          	       1	 144247629 ns/op	       443.7 actions/s	 2457248 B/op	   23501 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=0/selected=true-8          	       1	 128698463 ns/op	       497.3 actions/s	 2421648 B/op	   23513 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=1/selected=false-8         	       1	1037927264 ns/op	       493.3 actions/s	17665432 B/op	  170883 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=1/selected=false-8         	       1	1202296994 ns/op	       425.9 actions/s	17631064 B/op	  170908 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=1/selected=false-8         	       1	1307615883 ns/op	       391.6 actions/s	17480264 B/op	  170883 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=1/selected=true-8          	       1	 146466960 ns/op	       437.0 actions/s	 2458784 B/op	   23512 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=1/selected=true-8          	       1	 144147901 ns/op	       444.0 actions/s	 2458032 B/op	   23512 allocs/op
BenchmarkPlannerLongExecution/workers=4/module_limit=1/selected=true-8          	       1	 145455552 ns/op	       440.0 actions/s	 2456112 B/op	   23477 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=0/selected=false-8         	       1	1584413662 ns/op	       323.1 actions/s	17897456 B/op	  173373 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=0/selected=false-8         	       1	1600694092 ns/op	       319.9 actions/s	17721864 B/op	  171637 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=0/selected=false-8         	       1	1433445693 ns/op	       357.2 actions/s	17702144 B/op	  171985 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=0/selected=true-8          	       1	 178535823 ns/op	       358.5 actions/s	 2426408 B/op	   23495 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=0/selected=true-8          	       1	 145087833 ns/op	       441.1 actions/s	 2462056 B/op	   23512 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=0/selected=true-8          	       1	 149906761 ns/op	       426.9 actions/s	 2461336 B/op	   23462 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=1/selected=false-8         	       1	 943264683 ns/op	       542.8 actions/s	17552024 B/op	  170735 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=1/selected=false-8         	       1	1200597496 ns/op	       426.5 actions/s	17664056 B/op	  170746 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=1/selected=false-8         	       1	1043386598 ns/op	       490.7 actions/s	17671024 B/op	  170839 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=1/selected=true-8          	       1	 124256253 ns/op	       515.1 actions/s	 2458768 B/op	   23493 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=1/selected=true-8          	       1	 108831157 ns/op	       588.1 actions/s	 2460144 B/op	   23508 allocs/op
BenchmarkPlannerLongExecution/workers=8/module_limit=1/selected=true-8          	       1	 100405299 ns/op	       637.4 actions/s	 2462112 B/op	   23527 allocs/op
PASS
ok  	github.com/SiriusScan/scribe/runtime/lua54	42.654s
```

Validation: make check and make acceptance-local; logs at
/tmp/scribe132-check.log and /tmp/scribe132-acceptance.log. Service reinstall
and HTTP smoke are operational evidence, separate from live consumer durable
persistence/cancellation acceptance, which remains blocked on its contract.
Phase 3 stays paused; no NSE coverage expansion.

## v1.33.0 — stop CPE selection after an accepted fact (2026-11-12)

Priority review returns to smart target selection: the Go match evaluator now
stops scanning endpoint CPE facts at the first accepted alternative. This follows
the existing any_of short-circuit policy without changing applicability or
positive product evidence. Focused fixtures cover first/last/absent CPE matches,
missing facts, mismatched products and exact product skip reasons. CPE alone
continues to supply no explicit product identification for the clean gate.
No public API or wire changes; no measured throughput claim.

Validation: make check (race suite, external SDK, vet, static CLI and platform
cross-builds), with log /tmp/scribe133-check.log. A bounded race planner fuzz
invocation passed (/tmp/scribe133-fuzz.log); its five-second budget exercised
188 cached baseline seeds and did not complete baseline coverage or begin a new
mutation campaign. Service reinstall and HTTP smoke are operational evidence,
separate from live consumer durable persistence/cancellation acceptance.
Phase 3 stays paused. Follow-ups retain measured engine scheduling and existing
pingpp.scan/v1 adapter priorities; no NSE expansion.

## v1.34.0 — bounded invalid-endpoint adapter diagnostics (2026-11-12)

The existing pingpp.scan/v1 adapter now reuses boundedDiagnostic for invalid
endpoint addresses, transports and states, bounding each untrusted field before
quoted formatting. Invalid endpoints no longer dump the entire endpoint struct.
Focused reader regressions use oversized quote-heavy values for all three fields,
require explicit truncation and bounded errors, and preserve terminal failures
with zero emitted targets. Public APIs, selection and false-clean policy are
unchanged. No throughput claim or NSE expansion. Phase 3 stays paused.

Validation: make check (race suite, external SDK acceptance, vet, CGO-disabled
CLI build and Windows/Darwin cross-builds), log /tmp/scribe134-check.log.
Service reinstall and POST /run smoke are operational evidence only; live
consumer cancellation and durable persistence remain separate and blocked on
the consumer contract.

## v1.35.0 — bounded pingpp decoder diagnostics (2026-11-12)

The existing reader applies boundedDiagnostic to decoder failures as well as
adapter validation errors. Overflowing numeric JSON tokens can otherwise echo
nearly an entire bounded input line into an error. The regression requires
explicit truncation, a bounded diagnostic, zero targets and a stable terminal
error on repeated reads. No public API or wire changes and no throughput claim.

Validation: make check, log /tmp/scribe135-check.log; bounded race FuzzReader
campaign passed with 12,597 executions, log /tmp/scribe135-fuzz.log. Service
reinstall and POST /run smoke provide operational evidence only. Live consumer
persistence/cancellation remains blocked on its route/store contract; Phase 3
stays paused.

## v1.36.0 — retain TLS banner identification for selection (2026-11-12)

Planner priority: TLS endpoints that immediately send a protocol banner now retain
TLS, TLS version, certificate subject and negotiated ALPN alongside fingerprinted
service/product/version, banner and CPE facts. Previously the banner return path
replaced the handshake observations, preventing downstream rules and consumers from
using the observed transport. The probe reuses its existing facts accumulator;
no API, limits, trust policy or verdict policy changes. A controlled TLS listener
sends a pinned OpenSSH banner and requires both transport and product observations.
This is planner socket evidence, not SSH session or live consumer acceptance.
No throughput claim, NSE expansion or diagnostic-bounding work. Phase 3 stays paused.

Bounded race planner fuzz passed, covering 294/796 cached baseline seeds in
its five-second budget; it did not finish baseline coverage or start mutations
(/tmp/scribe136-fuzz.log).

Validation: make check passed (race suite, external SDK acceptance, vet,
CGO-disabled CLI build and Windows/Darwin cross-builds), log
/tmp/scribe136-check.log. Service reinstall and complete POST /run smoke remain
operational evidence only; live consumer persistence/cancellation is separate.

## v1.37.0 — CPE selection for pinned HTTP products (2026-11-12)

Caddy and OpenResty probe fingerprints now supply CPE hints through the existing
inferredCPE mapper, enabling CPE match rules for these already pinned products.
Focused original header fixtures pin versioned and versionless CPEs, matching
selection, exact missing/mismatched product skip reasons, caller identity
conflicts and the CPE-only false-clean guard. Invalid version components remain
rejected. No API change or throughput claim; Phase 3 stays paused.

Validation: make check, log /tmp/scribe137-check.log. Bounded race planner fuzz
passed with 283/796 baseline seeds in its five-second budget; no mutation campaign
began (/tmp/scribe137-fuzz.log). Service reinstall and POST /run smoke are
operational evidence only; live consumer persistence remains separate.

## v1.38.0 — CPE selection for pinned FTP/SMTP products (2026-11-12)

Extend the shared inferredCPE mapper to Pure-FTPd and Sendmail, closing the
remaining mapping gap for existing pinned banner identities. Reuse the HTTP
selection policy matrix for original FTP/SMTP banners, wildcard/versioned CPEs,
caller identity authority, exact product skip reasons and the CPE-only clean
gate. No API change or throughput claim. Phase 3 stays paused.

Validation: make check (/tmp/scribe138-check.log). Bounded race planner fuzz
passed with 272/796 baseline seeds in five seconds; baseline coverage remained
incomplete and mutations did not begin (/tmp/scribe138-fuzz.log). Service
reinstall and complete POST /run smoke are operational evidence only; live
consumer persistence/cancellation remains separate.

## v1.39.0 — prepared banner selection (2026-11-12)

The planner now prepares banner regular expressions once per indexed match tree,
including all_of/any_of children, and reuses immutable Go regexes during parallel
endpoint selection. This removes repeated regex compilation from indexed banner
selection. Direct Match evaluation retains a safe compile fallback, including
invalid patterns returning no match. Concurrent behavioral tests pin nested
positive/negative selection and absence of product identification.

Compatibility review: JSON and keyed Match literals retain their shape. Match
now contains private cache state, so external unkeyed literals must migrate to
keyed fields; the API fixture records this limitation. No measured throughput
claim. Engine per-task metadata parsing remains a follow-up optimization.

Validation: make check (/tmp/scribe139-check.log) and bounded race planner fuzz
(/tmp/scribe139-fuzz.log; 233/796 cached baseline seeds, no mutations). Service reinstall and complete POST /run smoke are
operational evidence only. Live consumer persistence remains separate; Phase 3
stays paused.

## v1.40.0 — reuse prepared selection metadata (2026-11-12)

Selected engine tasks now retain their index-owned immutable hints, avoiding
per-endpoint metadata JSON parsing and banner regex compilation. Direct SDK tasks
retain the existing validation path. Endpoint matching and explicit product clean
gates still run per invocation; exhaustive regression coverage pins matching,
mismatched and absent products with complete terminal delivery. Private Task
state already prevented external unkeyed literals; exported API stays unchanged.
No measured throughput claim. Phase 3 stays paused; live consumer persistence
remains separate.

Validation: make check (/tmp/scribe140-check.log), plus bounded race planner fuzz
(/tmp/scribe140-fuzz.log; 259/796 baseline seeds, no mutations). Service reinstall and complete POST /run smoke provide
operational evidence only.

## v1.41.0 — executed-engine allocation baseline (2026-11-12)

Takes the profiling portion of the unfinished VM initialization allocation slice.
Reuses BenchmarkPlannerExecution with four workers, module limit zero and both
selection paths. Go 1.26.10 linux/amd64, i9-13900H, GOMAXPROCS=4 (benchmark suffix).
No concurrent Scribe checks, fuzzing or deployment ran during measurement; other
projects share this host. Warm runtime caches; 100 Lua additions per action.

Command: `go test ./runtime/lua54 -run '^$' -bench '^BenchmarkPlannerExecution/workers=4/module_limit=0/' -benchmem -count=3 -memprofile=/tmp/scribe141.mem`.
Raw samples: [planner](benchmarks/v1.41.0-planner.txt),
[allocation profile](benchmarks/v1.41.0-allocations.txt).

Unfiltered batches execute 512 actions and emit 512 terminal records: 10.51–14.79
ms/batch, 34,623–48,724 actions/s, approximately 15.87 MB/batch. Selected batches
execute 64 actions and emit 448 skips: 1.38–2.45 ms/batch, 26,116–46,387 actions/s,
approximately 2.09 MB/batch. Actions/s divides executed actions by batch seconds,
not total records. Every batch verifies action sums and terminal counts. Selection
reduces work; its batch latency must not be interpreted as a throughput speedup.

Sampled alloc_space attributes 56.37% flat bytes to hashTable.grow, 62.20%
cumulative to loadLibraries, and 39.95% cumulative to SetEnvGoFunc. Cumulative
percentages overlap and must not be added. This measures allocated bytes, not
retained heap or CPU time. The next implementation candidate is immutable math/
string builtin function reuse following the existing table-library pattern, while
keeping mutable tables invocation-owned and SetEnv accounting intact. That
reduction remains unfinished; this release makes no optimization/speedup claim.

Validation: make check passed (/tmp/scribe141-check.log). Service reinstall and
complete POST /run smoke are operational evidence only. Live consumer persistence
remains separate; Phase 3 stays paused.

## v1.42.0 — immutable math/string builtin reuse (2026-11-12)

Math/string Go functions and string arithmetic metamethods now follow the table
library snapshot pattern. Library tables and the string metatable remain
invocation-owned; all entries are installed through accounted SetEnv calls.
String __index points to the invocation's string table. dump/random/randomseed
remain unavailable. Shared helpers also populate table/utf8 without duplicate loops.
The isolation fixture covers mutations, string methods/arithmetic and disabled APIs.

Raw samples: [before](../benchmarks/v1.42.0-before.txt) and
[after](../benchmarks/v1.42.0-after.txt). Go 1.26.10 linux/amd64,
i9-13900H, GOMAXPROCS=4. Before command:
GOMAXPROCS=4 go test ./runtime/lua54 -run '^$' -bench '^BenchmarkPlannerExecution$' -benchmem -count=3.
After restricts -bench to '^BenchmarkPlannerExecution/workers=4/module_limit=0/'.
Compare only that shared subset: 512 executed actions unfiltered; 64 actions and
448 skips selected, with verified sums and terminal counts.
Unfiltered bytes/batch fall from 15.87–15.88 MB to 13.60–13.61 MB
(about 14.3%); allocations fall from 157,060–157,218 to 128,972–129,114.
Selected bytes/batch fall from 2.092 MB to 1.807 MB (about 13.6%);
allocations fall from 20,585–20,588 to 17,063–17,064.
Unfiltered latency ranges are 17.72–23.48 ms before and 16.97–25.45 ms
after; selected ranges are 2.48–2.76 and 2.39–2.73 ms.
These shared-host samples establish allocation reduction, not a throughput
speedup or retained-heap reduction. No Scribe checks/fuzz/deployment overlapped
measurement. Live consumer persistence remains separate; Phase 3 stays paused.

Validation: make check passed (/tmp/scribe142-check.log): race suite, external
SDK acceptance, Windows/Darwin cross-compilation, vet and CGO-disabled CLI build.
Build evidence is separate from scanner/agent integration acceptance.

## v1.43.0 — reserve invocation library storage (2026-11-12)

Continues the unfinished VM initialization allocation slice. A shared library
initializer reserves hash storage from the known entry count, including room
for string __index. Every table remains invocation-owned and populated through
accounted SetEnv calls. The internal golua constructor preserves normal table
writes and growth; a focused test covers empty, non-power-of-two and growing
tables. Existing isolation fixtures remain the behavioral gate. Third-party
license notices and the Lua baseline remain unchanged.

Raw executed-Lua samples: [before](../benchmarks/v1.43.0-before.txt),
[after](../benchmarks/v1.43.0-after.txt). Go 1.26.10 linux/amd64, i9-13900H,
GOMAXPROCS=4. Sequential command for each revision:
`GOMAXPROCS=4 go test ./runtime/lua54 -run '^$' -bench '^BenchmarkPlannerExecution/workers=4/module_limit=0/' -benchmem -count=3`.
No Scribe checks, fuzz or deployment overlapped measurement. Each batch verifies
512 executed actions unfiltered, or 64 actions plus 448 skips selected, including
Lua sums and terminal counts. Unfiltered allocation bytes fall from
13.61–13.64 MB to 11.88–11.89 MB; selected from 1.807 MB to 1.592–1.593 MB,
roughly 12–13%. Raw timing ranges overlap substantially; no throughput speedup
or retained-heap claim. Further VM allocation work remains open.

Validation: make check (race suite, external SDK, cross-builds, vet and static
CLI build). Service reinstall and complete POST /run smoke are operational
evidence only. Live consumer persistence remains separate; Phase 3 stays paused.

## v1.44.0 — retain agreed adapter product identity (2026-11-12)

The existing pingpp.scan/v1 mapper now preserves an agreed product when accepted
endpoint claims disagree only about its version. Version remains unknown; a later
repeated version cannot erase the conflict. Different product claims still leave
identity unknown. This enables product selection without asserting a disputed
version. Order regressions cover both directions and repeated claims. No wire or
public API change, throughput claim, or live consumer acceptance. Phase 3 stays paused.

Validation: make check (/tmp/scribe144-check.log); bounded race FuzzReader passed
with 2,591 executions (/tmp/scribe144-fuzz.log). Service reinstall and POST /run
smoke are operational evidence, separate from live consumer persistence.

## v1.45.0 — combine partial adapter version evidence (2026-11-12)

Continues the pingpp.scan/v1 adapter capability backlog: accepted claims agreeing
on product now retain a supplied version when sibling claims omit their version.
Missing evidence does not contradict a known version; two different nonempty
versions still leave the version unknown, including after later empty claims.
Existing endpoint isolation, confidence and contradiction filters remain intact.
Focused order and conflict regressions accompany the shared mapper change.
No public API or wire change, throughput claim or live consumer acceptance.
Phase 3 stays paused.

Validation: make check (/tmp/scribe145-check.log) and bounded race FuzzReader
(/tmp/scribe145-fuzz.log). Service reinstall and complete POST /run smoke provide
operational evidence only, separate from live consumer persistence acceptance.

## v1.46.0 — HAProxy planner identity (2026-11-12)

Continues the unfinished expanded fingerprint capability slice: original pinned
HAProxy Server observations now supply HTTP product/version identity and CPE hints
through the existing matcher and mapper. Product, version and CPE selection can
use these observations without adding another planner path. Versionless headers
retain unknown versions; misleading prefixes and malformed versions stay unknown.
Shared selection tests preserve caller identity authority, exact product skip
reasons and the CPE-only false-clean gate. No public API change or throughput
claim. Phase 3 stays paused; live consumer persistence remains separate.

Validation: make check (/tmp/scribe146-check.log) and bounded race planner fuzz
(/tmp/scribe146-fuzz.log; 288/796 baseline seeds, no mutations). Service reinstall and complete POST /run smoke are
operational evidence only, not live workflow acceptance.

## v1.47.0 — partial-fact declarative selection (2026-11-12)

The planner's on_unknown run policy now evaluates known facts before admitting
partially identified endpoints. A missing version no longer bypasses a known
product mismatch. The shared evaluator reuses existing field predicates and
recurses through required and alternative branches: every required branch must
remain possible, and at least one alternative must remain possible. Missing facts
permit execution without positive product identification. Confidence and CPE
gates retain their existing conservative behavior. No public API or wire change,
throughput claim or live consumer acceptance. Phase 3 stays paused.

Validation: focused partial-fact policy regressions and make check (race suite,
external SDK, vet, static CLI and platform cross-builds), logged in
/tmp/scribe147-check.log; bounded race planner fuzz in /tmp/scribe147-fuzz.log (310/796 cached baseline
seeds covered in five seconds; mutations did not begin).
Service reinstall and complete POST /run smoke are operational evidence only;
live consumer persistence remains separate.

## v1.48.0 — Envoy planner identity (2026-11-12)

Continues the expanded fingerprint capability backlog in priority one. Original
pinned Envoy Server observations now supply HTTP product/version and CPE hints
through the existing planner. Versionless headers identify the product with an
unknown version; malformed versions and misleading prefixes remain unknown.
Shared selection fixtures pin caller authority, missing/mismatched product skip
reasons and the CPE-only false-clean guard. No API or wire change, throughput
claim or live consumer acceptance. Phase 3 stays paused.

Validation: make check (/tmp/scribe148-check.log). Bounded race planner fuzz
passed with 312/796 cached baseline seeds covered in five seconds; baseline
coverage remained incomplete and mutations did not begin (/tmp/scribe148-fuzz.log).
Service reinstall and complete POST /run smoke are operational evidence only;
live consumer persistence remains separate.

## v1.49.0 — adapter confidence for planner selection (2026-11-12)

Closes an existing pingpp adapter/planner capability gap: accepted product claims
now carry confidence into target facts, enabling minimum-confidence selection.
Adapter policy maps strong to 0.8 and exact to 1 and uses the strongest accepted
claim for an agreed product. These scores are policy levels, not calibrated
probabilities. Conflicting products, weak and contradicted claims supply no
product confidence. Service/TLS evidence cannot raise it. Existing version conflict
and endpoint isolation semantics remain intact. Focused fixtures cover confidence
levels, combined evidence, conflicts and rejected claims. No public API change or
throughput claim. Live consumer persistence remains separate; Phase 3 stays paused.

Validation: make check (/tmp/scribe149-check.log). Service reinstall and complete
POST /run smoke are operational evidence only, not live workflow acceptance.

## v1.50.0 — reuse compiled planner fingerprints (2026-11-12)

Default fingerprint construction now reuses an immutable compiled rule snapshot.
Planner probes avoid compiling the complete regex corpus for each observation;
custom matchers still copy their supplied rule slices. Parallel isolation tests
pin unchanged OpenSSH identity and independent custom matcher behavior.

Local Go 1.26.10 linux/amd64, i9-13900H, GOMAXPROCS=4 microbenchmark
(Default plus verified OpenSSH Match), three samples: baseline 46220/50590/60516
ns/op, 88465/88512/88471 B/op, 721 allocs/op; shared snapshot
1353/1290/1313 ns/op, 32 B/op, 1 alloc/op. Baseline samples are retained under
benchmarks/v1.50.0; the baseline used the previous constructor verbatim.
These shared-host samples overlapped checks and establish eliminated repeated
compilation allocations, not executed-Lua or end-to-end throughput speedup.
Phase 3 stays paused; live consumer persistence remains separate.

Validation: make check passed (race suite, external SDK checks, Windows/Darwin
cross-builds, vet and static CLI build). Build evidence remains separate from
Sirius integration acceptance.

## v1.51.0 — Varnish planner identity (2026-11-12)

Continues the expanded fingerprint capability backlog: original pinned Varnish
HTTP Server observations now supply product/version and CPE hints through the
existing planner mapper. Versionless headers retain unknown versions; misleading
prefixes and malformed versions remain unknown. Shared selection fixtures preserve
caller authority, exact missing/mismatched product skip reasons and the CPE-only
false-clean guard. No public API change or throughput claim. Live consumer
persistence remains separate; Phase 3 stays paused.

Validation: make check (race suite, external SDK checks, platform cross-builds,
vet and static CLI build), /tmp/scribe151-check.log. Bounded race planner fuzz
passed with 220/796 baseline seeds covered in five seconds; mutations did not
begin (/tmp/scribe151-fuzz.log). Service reinstall and complete POST /run smoke
provide operational evidence only, separate from live workflow acceptance.

## v1.52.0 — Squid planner identity (2026-11-12)

Original pinned Squid HTTP Server observations now supply product/version and
CPE hints through the existing fingerprint and planner mapper. This extends
product-aware target selection without a new execution path. Versionless headers
retain unknown versions; misleading prefixes and malformed versions remain
unknown. Shared selection fixtures preserve caller authority, exact missing and
mismatched product skip reasons and the CPE-only false-clean gate. No public API
change or throughput claim. Live consumer persistence remains separate;
Phase 3 stays paused.

Validation: make check logged in /tmp/scribe152-check.log. Bounded race planner
fuzz passed with 225/796 baseline seeds covered in five seconds; mutations did
not begin (/tmp/scribe152-fuzz.log). Service reinstall and complete POST /run
smoke are operational evidence only, separate from live workflow acceptance.

## v1.53.0 — Traefik planner identity (2026-11-12)

Original pinned Traefik HTTP Server observations now supply product/version and
CPE hints through the shared fingerprint/planner mapper. Versionless headers
identify the product without inventing a version. Boundary fixtures reject
misleading prefixes and malformed versions. Shared selection fixtures preserve
caller identity authority, exact missing/mismatched product skip reasons and the
CPE-only false-clean gate. No public API change or throughput claim; live consumer
persistence remains separate and Phase 3 stays paused.

Validation: make check logged in /tmp/scribe153-check.log. Bounded race planner
fuzz passed with 298/796 baseline seeds covered in six seconds; mutations did
not begin (/tmp/scribe153-fuzz.log). Service reinstall and complete POST /run
smoke provide operational evidence only, separate from live workflow acceptance.

## v1.54.0 — H2O planner identity (2026-11-12)

Continues the unfinished expanded fingerprint capability backlog. Original pinned
H2O HTTP Server observations supply product/version and CPE hints through the
existing mapper and planner selection path. Versionless headers retain unknown
versions; boundary fixtures reject misleading prefixes and malformed versions.
Shared policy fixtures preserve caller authority, exact product skip reasons and
the CPE-only false-clean gate. No public API change or throughput claim.
Live consumer persistence remains separate; Phase 3 stays paused.

Validation: make check logged in /tmp/scribe154-check.log. Bounded race planner
fuzz passed with 216/796 baseline seeds covered in six seconds; mutations did
not begin (/tmp/scribe154-fuzz.log). Service reinstall and complete POST /run
smoke provide operational evidence only, separate from live workflow acceptance.

## v1.55.0 — LiteSpeed planner identity (2026-11-12)

Extends the common HTTP product identification backlog with original pinned
LiteSpeed Server observations and CPE hints through the shared mapper. Versionless
headers retain unknown versions; misleading prefixes and malformed versions are
rejected. Reuses the shared selection policy matrix for caller authority, exact
missing/mismatched product skip reasons and the CPE-only false-clean guard.
No public API change or throughput claim. Live consumer persistence remains
separate; Phase 3 stays paused.

Validation: make check logged in /tmp/scribe155-check.log. Bounded race planner
fuzz passed with 287/796 baseline seeds covered in six seconds; mutations did
not begin (/tmp/scribe155-fuzz.log). Service reinstall and complete POST /run
smoke provide operational evidence only, separate from live workflow acceptance.

## v1.56.0 — enumeration CPE planner input (2026-11-12)

Returns to the unfinished richer-facts adapter item instead of expanding HTTP
fingerprints. The existing pingpp.scan/v1 mapper now carries product CPE hints
into planner Target.CPE. The upstream field was verified in pkg/model/claim.go
at pinned commit ff4085905039cbbc759a0a75fab897b49316ef1a via GitHub API.
Only strong/exact, uncontradicted claims for the exact endpoint and an agreed
product qualify. Version conflicts suppress all CPE hints conservatively; hints
are sorted and deduplicated. Service, host, weak and contradicted claims cannot
supply CPEs. This enables existing CPE selection without another mapper, wire
schema changes, or new fingerprints. Additive Claim.CPE API fixture reviewed;
external Claim literals should use keyed fields. No performance claim.

Validation: make check (/tmp/scribe156-check.log), including race tests, external
SDK, cross-builds, vet and static CLI build. Reader regressions require complete
streams and conservative conflict/filter behavior. Service reinstall and POST
/run smoke provide operational evidence only; live consumer persistence remains
separate. Phase 3 stays paused.
Bounded race FuzzReader also passed: 5,730 executions in seven seconds
(/tmp/scribe156-fuzz.log).

## v1.57.0 — bounded fixed-length TCP/TLS replies (2026-11-12)

Selected the raw transport capability gap: tcp.exchange now optionally accepts a
second integer byte count, reading across fragmented replies through the existing
TCP/verified-TLS stream. Reuses connection setup, cancellation and the shared
five-second deadline; reads remain bounded at 64 KiB. Default single-chunk
semantics remain compatible. Premature EOF returns an error without partial
successful output. Focused loopback tests cover fragmented completion, truncated
responses and invalid bounds/types. No public Go signature change. Multi-exchange
sessions remain follow-up work; Phase 3 stays paused. Local protocol evidence
does not establish live consumer persistence or general protocol acceptance.

Validation: make check logged in /tmp/scribe157-check.log. Deployment and complete
POST /run smoke are operational evidence only, separate from workflow acceptance.

## v1.58.0 — bounded delimiter TCP replies (2026-11-12)


v1.58.0 adds delimiter-framed tcp.exchange replies: a string second argument
reads through that delimiter (1..256 bytes), inclusive, within the existing 64 KiB
reply ceiling and five-second deadline. Missing delimiters and premature EOF are
errors without partial successful output. Connection setup and verified TLS use
the existing path. Multi-exchange sessions remain follow-up work; Phase 3 stays
paused. Controlled loopback evidence is separate from live consumer acceptance.

Validation: `make check` evidence is recorded in /tmp/scribe158-check.log;
focused delimiter tests cover fragmented completion, EOF, reply bounds and invalid
delimiter lengths. Service smoke evidence is recorded in /tmp/scribe158-smoke.log.

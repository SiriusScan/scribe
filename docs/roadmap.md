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

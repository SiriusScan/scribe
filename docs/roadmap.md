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

## 1. Measured NSE compatibility

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
3. Benchmark-driven engine work: streaming targets, per-host concurrency/rates,
   host error budgets, host-spray/script-spray strategies, connection reuse, and
   compile/VM caching. Skipped pairs currently cost 34–53 us because each builds
   a VM; use the benchmark harness to guide changes.
4. Adapt ping++ `pingpp.scan/v1` output (ping++ PR #1 branch) to Scribe facts.

Phase 3 endpoint-agent work is paused: the SDK side has landed; remaining work
belongs in app-agent.

Backlog 3 partial preparation: `RunTargetStream` consumes a caller-owned target
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

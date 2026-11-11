# Architecture and decisions

Status: initial architecture, 2026-11-10. Public API is pre-1.0 and may change.

## Product boundary

Sirius Scribe is a vulnerability-script executor. A caller resolves an immutable
script selection, supplies known host/port/service facts and arguments, selects a
dialect, and receives execution results plus affirmative findings. No discovery
stage runs implicitly. Knowing that a TCP port is open does not imply a service
identity; omitted facts remain unknown.

The standalone CLI and an embedded endpoint-agent invocation share the same
execution path. Flags, signals, script file reading, and JSONL encoding belong to
the CLI. Queue delivery, scan lifecycle, result storage, vulnerability enrichment,
and aggregate scan status belong to Sirius adapters.

## Public module and runtime boundary

The root `github.com/SiriusScan/scribe` package owns `Task`, `Script`, `Target`,
`Finding`, `Output`, `Result`, `Runtime`, and `Engine`. It imports no interpreter or
Sirius database package. `Runtime` is an explicit extension seam with a dialect
identity and context-aware `Execute` method.

`runtime/lua54` constructs native and NSE runtimes. Sharing the Lua implementation
does not merge the script contracts: each dialect has its own entry points,
capability surface, and output handling. VM-specific types stay within that
package. A future reference-C-Lua backend can implement `Runtime` without changing
normal consumers, but it is not required for endpoint deployment.

Use one module initially. Avoid a speculative plugin ecosystem, reflection-based
Go imports, or separate modules for every protocol. Add public packages only for
intentional embedding surfaces. The target-bound HTTP capability is one such
surface; an embedder may omit it entirely.

## Scheduling and ownership

`Engine.Run` validates the entire task list before starting work. Dialect selection
is explicit, and a missing runtime is an error. A bounded worker pool executes one
script/target pair per task. Each runtime invocation owns a fresh Lua state; no
goroutine enters another invocation's VM. Registered runtimes must support
concurrent `Execute` calls.

Results arrive in completion order. The callback is serial within one `Run` and
may stop delivery by returning an error; the engine cancels pending work and drains
active work before returning. Separate concurrent `Run` calls have independent
worker limits and independent callbacks. Embedders must impose a global admission
limit if they accept many simultaneous jobs.

Inputs remain caller-owned and must not be mutated while executing. Script IDs are
caller descriptors; SHA-256 of the exact source is included in every result to
identify the executed artifact. This digest is provenance, not a signature or a
trust decision. Catalog resolution, content signatures, publisher policies, and
transitive bundle digests belong to a later catalog layer.

## Lua baseline

Use the Lua 5.4 implementation from `github.com/arnodel/golua v0.1.2`, commit
`ebe9f094210ac365f1cd4043e8aa6b99e2135a69`, in pure Go. Newer upstream
releases target Lua 5.5, so dependency upgrades require an intentional language
baseline review. Current Nmap NSE requires Lua 5.4 or newer. GopherLua's Lua 5.1
implementation therefore does not meet that language baseline.

The upstream v0.1.2 release failed to link on the development host's Go 1.27
because it references private Go runtime hash symbols. Scribe therefore bundles
the required Apache-licensed source subset internally with rewritten import paths
and a portable hashing patch. This is an explicit maintenance commitment, recorded
in the [patch manifest](../third_party/golua-PATCHES.md). It works when Scribe is
imported by another module; a local `replace` directive would not provide that
guarantee. Do not solve this with disabled linker checks or an accidental Lua 5.5
upgrade. Reevaluate the fork when upstream offers a compatible maintained baseline.

Pure Go supports the existing Sirius endpoint build's `CGO_ENABLED=0` model.
Reference Lua through cgo remains an option if real corpus tests demonstrate a
necessary semantic/native-module gap. No speed improvement is assumed: benchmark
complete jobs, VM startup, allocations, and representative protocols before
optimizing. Calling compiled Go protocol functions is an extension mechanism,
not a performance claim.

See the [runtime research](research/nse-runtime.md) for primary sources and tradeoffs.

## Capabilities and resource boundaries

The native API invokes registered `scribe.Function` values directly in-process.
Capabilities receive the Go context and the exact supplied target. They validate
arguments and bound I/O, allocations, and returned data. The script cannot import
arbitrary Go packages, spawn processes, or access host files through this API.
An embedder can deliberately grant additional capabilities; those Go functions
execute with the process's authority and must be reviewed accordingly.

The HTTP capability uses the supplied host/IP/port, preserves the logical Host and
TLS server name, disables ambient proxy use, declines redirects, and bounds body
size. It does not accept arbitrary absolute URLs. These restrictions are the
native capability's contract, not an attempted emulation of NSE's HTTP library.

Finite VM CPU, memory-accounting, and wall-time budgets cover source loading,
rules, actions, and conversion. Source bytes and returned values need additional
bounds. Go I/O honors context cancellation. CPU-only Lua cancellation completes
within runtime budgets rather than an unsafe cross-goroutine VM interrupt.
Runtime accounting is not a process RSS limit, and trusted native functions can
allocate outside the VM. Hard containment of hostile scripts is a separate
process-isolation milestone.

## Result semantics

`Result.Status` describes execution: `completed`, `skipped`, or `error`.
`Output.Findings` contains only structured affirmative native findings.
`Output.Data` preserves observations, including raw NSE action output. No keyword
search for `VULNERABLE` or `CVE-` creates findings in the engine.

Errors clear output, so a partially failed script cannot emit an apparent clean
result or incomplete positive finding. The run returns a non-nil summary error if
any script failed. Cancellation and callback failures return their own errors.
Consumers must preserve partial-result/error distinctions and must not interpret
an empty finding list as successful coverage of unimplemented APIs.

Schema version 1 identifies the initial result envelope. Future richer NSE
vulnerability states, CVSS, confidence, and dual textual/structured output require
versioned additions and explicit adapter behavior. Unknown severity or confidence
must stay unknown; do not invent scores from keywords.

## NSE is a compatibility program

NSE includes host APIs, asynchronous socket semantics, shared registries,
coroutines, scheduler behavior, libraries, and scanner state. Parsing `.nse` Lua
does not establish compatibility. The initial profile intentionally supports a
small set of original rule/action fixtures and helpers, with explicit errors for
unsupported behavior. It neither invokes Nmap as a fallback nor vendors its code.

The [support matrix](compatibility.md) states implemented behavior. The next gate
is a pinned external corpus and deterministic differential fixtures against the
same Nmap version. Support claims must name both script revision and tested
semantics. Shared NSE registry/cache semantics cannot be inferred from isolated
per-task VMs; add them only after choosing explicit run/session ownership.

## Licensing and distribution

The new implementation and original examples are MIT. GoLua is Apache-2.0 and
retains its notices. Nmap's implementation, libraries, and script corpus have
their own licenses, including NPSL; Lua itself being MIT does not change those.
Keep any future approved script distribution separate from the engine and audit
the exact scripts plus transitive libraries before bundling them. Independent
implementation is an engineering boundary, not a legal compatibility guarantee.

## Deliberate deferrals

This bootstrap does not modify Sirius services, replace Nmap, publish a stable
module tag, add a remote plugin protocol, or claim complete NSE support. It creates
the executable/library foundation and makes the remaining acceptance work concrete.
See the [roadmap](roadmap.md) and [integration plan](integration.md).

Script selection is opt-in through `NewIndex` and `Engine.RunSelected`. Build an
index once per script bundle and reuse it across batches. Scripts declare a
single JSON comment line, for example:

```lua
-- scribe: {"services":["http"],"products":["nginx"],"ports":[80,443],"protocols":["tcp"]}
```

Service, product and port hints are alternatives; protocol is a constraint when
known. Names match case-insensitively and exactly. Missing facts for any declared
category retain the script conservatively. Scripts without hints always remain
eligible. Version and banner do not exclude scripts: runtime rules still make the
final applicability decision. Selection exclusions provide no execution record
or negative verdict. The index caches metadata without evaluating Lua. Rebuild it
when source changes. Caller-owned argument values must remain immutable.

The optional `fingerprint` SDK package matches supplied TCP banners or HTTP
headers with an ordered table of regular expressions. It performs no network I/O;
inputs are bounded to 8 KiB each. `Default()` recognizes OpenSSH, nginx and Apache;
`New(rules...)` accepts caller rules, with first match winning and capture one
providing version. An unmatched input returns empty facts. ping++ is the expected
upstream endpoint fact source; callers decide whether inferred hints should fill
missing fields and should preserve authoritative supplied facts. No other
repository or scanner integration is changed here.

`go test -run '^$' -bench BenchmarkSelection -benchmem .` compares 100 scripts
against one endpoint with and without selection using a no-op runtime. This
measures scheduling overhead, not Lua throughput or scanner acceptance.

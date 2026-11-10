# NSE compatibility and Lua runtime research

Research date: 2026-11-10. This memo separates a proposed implementation from compatibility that has actually been demonstrated.

## Recommendation

Build one reusable Go execution core with two explicit script profiles: `sirius` for a versioned, capability-based native API, and `nse` for a separately documented compatibility surface. Use a Lua 5.4 runtime for both initially. Keep runtime-specific types inside the implementation so a later C Lua adapter can be evaluated without changing the embedding API.

For the initial pure Go implementation, evaluate and pin `github.com/arnodel/golua v0.1.2`. This is the immutable tag at `ebe9f094210ac365f1cd4043e8aa6b99e2135a69`, currently the `lua5.4` branch. Verified with `go list -m -json github.com/arnodel/golua@ebe9f094210ac365f1cd4043e8aa6b99e2135a69`. Its module requires Go 1.17. The upstream default branch and latest releases have moved to Lua 5.5; an unqualified upgrade changes the language baseline. Its Apache-2.0 license can remain a third-party dependency of MIT first-party code, with the applicable distribution notices retained. [Runtime source and embedding examples](https://github.com/arnodel/golua/tree/ebe9f094210ac365f1cd4043e8aa6b99e2135a69), [license](https://github.com/arnodel/golua/blob/ebe9f094210ac365f1cd4043e8aa6b99e2135a69/LICENSE).

This choice is a portability and implementation recommendation, not a claim that arbitrary upstream NSE scripts already work.

Implementation finding from this session: unmodified v0.1.2 failed to link on
Go 1.27 (`invalid reference to runtime.memhash64`). Its Lua 5.4 branch has no newer
fix; upstream's fixed newer release targets Lua 5.5. The implementation therefore
bundles the required Apache-licensed v0.1.2 packages under an internal import path
and patches hashing to use supported Go APIs. This preserves the language baseline
and external-module embedding without consumer linker overrides or ignored module
`replace` directives. See [the patch manifest](../../third_party/golua-PATCHES.md).

## Current NSE baseline

The official changelog lists Nmap 7.993, released 2026-10-23. The inspected development revision was `4394ae5c1f5ca46725e13dcde5690258c1ab3d92` from 2026-11-09. Its `nse_main.lua` explicitly requires Lua 5.4 or newer. Record the selected Nmap release and exact script corpus revision in the compatibility manifest. A host's older Nmap installation is a separate reference cohort, not proof of current compatibility. [Changelog](https://nmap.org/changelog.html), [version check](https://github.com/nmap/nmap/blob/4394ae5c1f5ca46725e13dcde5690258c1ab3d92/nse_main.lua#L35-L40).

NSE is a host runtime, not just a Lua parser. Compatibility includes:

- Metadata fields, categories, script arguments, script names, script environment globals, and Lua module loading.
- The `prerule`, `hostrule`, `portrule`, and `postrule` lifecycle, including scripts with several rules.
- Accurate caller-supplied host and port tables, service/version metadata, registries, and selected-script dependency ordering. A dependency changes ordering only when it is also selected; it does not automatically select another script.
- String, table, nil, and dual structured/unstructured action results. An NSE result is not automatically a vulnerability finding.
- TCP, UDP, TLS, buffered reads, timeouts, certificates, and socket cleanup through Nsock-shaped APIs.
- Cooperative coroutine scheduling, worker threads, mutexes, condition variables, and registry/cache visibility.
- Lua libraries plus native dependencies. Upstream initializes `nmap`, database facilities, LuaFileSystem, LPeg, libssh2, OpenSSL, and zlib modules; availability can be build-dependent.
- Scanner-state-dependent behavior such as port-state mutation, version updates, interface data, and target additions. For a script-only engine, these become explicit supplied data or result events. Unsupported scanner behavior must be rejected or documented, not fabricated.

[Script format and dependencies](https://nmap.org/book/nse-script-format.html), [host/port and networking API](https://nmap.org/book/nse-api.html), [parallel execution](https://nmap.org/book/nse-parallelism.html), [native library registration](https://github.com/nmap/nmap/blob/4394ae5c1f5ca46725e13dcde5690258c1ab3d92/nse_main.cc), [socket methods](https://github.com/nmap/nmap/blob/4394ae5c1f5ca46725e13dcde5690258c1ab3d92/nse_nsock.cc).

Even `http-title.nse` depends on `http`, `shortport`, and `stdnse`. Replacing each with a minimally similar function can run one example while diverging from normal NSE HTTP redirects, header normalization, TLS probing, caching, and output behavior. A support matrix must list functions and semantics, not only module names. [Example dependency and output surface](https://github.com/nmap/nmap/blob/4394ae5c1f5ca46725e13dcde5690258c1ab3d92/scripts/http-title.nse), [HTTP library contract](https://github.com/nmap/nmap/blob/4394ae5c1f5ca46725e13dcde5690258c1ab3d92/nselib/http.lua).

## Runtime options

| Option | Evidence | Fit |
| --- | --- | --- |
| GopherLua | Pure Go; Lua 5.1 plus `goto`; Go context cancellation and ergonomic callbacks. | Good for an intentionally older custom dialect, but does not satisfy current NSE language compatibility. Modern bitwise operators, integer behavior, `_ENV`, and standard-library differences matter. Avoid two unrelated Lua versions unless an explicit product requirement emerges. |
| arnodel/golua v0.1.2 | Pure Go Lua 5.4, coroutines, Go callbacks, CPU/memory/time quotas. Standard library mostly implemented; native Lua C modules are not supported. | Best initial candidate for portable embedding. Validate selected NSE corpus and interruption semantics before promising compatibility. |
| C Lua 5.4 through a Go wrapper | Reference language implementation and native-module ecosystem; requires cgo/build toolchains and platform-specific packaging. | Keep as a future adapter option if required by compatibility or measured performance. The wrapper must prove safe Go callbacks, error unwinding, coroutine yield/resume, and cancellation. |

Sources: [GopherLua README](https://github.com/yuin/gopher-lua/blob/master/README.md), [golua Lua 5.4 README](https://github.com/arnodel/golua/blob/ebe9f094210ac365f1cd4043e8aa6b99e2135a69/README.md), [aarzilli C wrapper caveats](https://github.com/aarzilli/golua/blob/master/README.md), [Lua's MIT license](https://www.lua.org/license.html).

The aarzilli wrapper explicitly warns about exceptions crossing Go callbacks and untested coroutine behavior; selecting C Lua alone does not resolve those integration risks. Benchmark native Go protocol work and whole script jobs before claiming performance improvements. Prefer small, typed Go module bindings registered at build time over subprocesses, Go `plugin`, or arbitrary dynamic Go imports.

## Resource limits and cancellation in golua v0.1.2

The actual API is `RuntimeContextDef{HardLimits: RuntimeResources{Cpu, Memory, Millis}}`, with unsigned resource counts. Zero means unlimited. `MainThread().CallContext(def, func() error { ... })` catches a `ContextTerminationError` raised by quota termination. Put script compilation/loading, top-level execution, rule evaluation, and action execution under budgets; do not limit only the action body. Time is checked periodically through VM resource accounting, not by forcibly interrupting every Go call. [Definitions](https://github.com/arnodel/golua/blob/v0.1.2/runtime/runtimecontext.go), [accounting and termination](https://github.com/arnodel/golua/blob/v0.1.2/runtime/runtimecontextmanager.go), [protected call](https://github.com/arnodel/golua/blob/v0.1.2/runtime/thread.go).

Important implementation boundaries:

- `SetStopLevel` mutates unsynchronized runtime fields and can panic immediately in its caller. Do not invoke it from a cancellation goroutine against a concurrently executing VM.
- Count-hook flags exist, but the inspected interpreter has no working recurring count hook. Line hooks run when source line changes; a single-line infinite loop does not provide recurring cancellation checks. Hard CPU and time limits remain necessary. [Hooks](https://github.com/arnodel/golua/blob/v0.1.2/runtime/debughooks.go), [interpreter](https://github.com/arnodel/golua/blob/v0.1.2/runtime/luacont.go).
- Go callbacks must check the job's `context.Context`, propagate deadlines to HTTP/network calls, and bound allocations and output. Quota compliance declarations are assertions by callback authors, not automatic enforcement around arbitrary Go code. [Quota design](https://github.com/arnodel/golua/blob/v0.1.2/quotas.md).
- Runtime allocation accounting is not a process RSS ceiling. Compiler/source size, Go callback buffers, concurrency, decompression, and emitted results need separate limits. A process boundary is still required if the product promises hard containment of hostile scripts.
- Use one owned VM per execution initially; never enter it concurrently. Dispose of job state and close sockets deterministically. Shared NSE registries and cross-script cache semantics need a deliberate later design.

Document initial cancellation as context-aware I/O plus bounded VM work. Do not promise immediate cancellation of a CPU loop or arbitrary native callback until a focused experiment demonstrates it.

## MIT licensing boundary

Implement Sirius code and example scripts independently and license them MIT. Nmap source, its script corpus, and its libraries cannot all be relabeled MIT. The inspected Nmap `LICENSE` is NPSL 0.95 with broad integration and derivative-work provisions; individual script/library notices can differ. Lua's own MIT license is separate from Nmap's license. Preserve independent implementation provenance and record every dependency's license. Do not copy or automatically download the upstream corpus into the initial public repository. User-supplied script loading does not by itself settle all distribution questions. Review the exact upstream script and dependency licenses before shipping a supported corpus. [Nmap license](https://github.com/nmap/nmap/blob/4394ae5c1f5ca46725e13dcde5690258c1ab3d92/LICENSE), [script licensing metadata](https://nmap.org/book/nse-script-format.html#nse-script-format-license), [Nmap licensing overview](https://nmap.org/npsl/).

## Delivery and validation phases

1. Establish the library/CLI split, immutable script inputs, explicit supplied targets, isolated per-job state, native API version, typed results, error classes, and finite defaults. Execute original native and NSE-shaped fixtures without claiming upstream compatibility.
2. Add NSE metadata, lifecycle, argument, output, and common helper semantics. Reject unsupported APIs with actionable diagnostics. Prove false rules, load failures, nil results, dual results, cancellation, quotas, cleanup, and isolation.
3. Select a legally distributable or externally supplied pinned corpus. Measure transitive dependencies. Implement network APIs and common protocol modules against local deterministic services, including TLS, redirects, malformed responses, timeouts, partial reads, EOF, and binary data. Record pass/fail/unsupported per script and test case.
4. Add selected-script ordering, shared registry semantics, worker threads, locks, condition variables, and resource cleanup. Differentially compare outcomes with the same pinned Nmap version and supplied host/port state on controlled local services. Separate language tests, API tests, corpus tests, and full Sirius integration evidence.
5. Consider privileged/raw packet APIs, native C modules, wider protocol support, process isolation, and performance optimizations only as explicit later milestones.

The highest-value first acceptance gate is a Sirius agent importing the public Go module and executing the same original script as the CLI against a local test service, producing equivalent structured results with bounded resource use. This demonstrates the intended embedding model without overstating NSE coverage.

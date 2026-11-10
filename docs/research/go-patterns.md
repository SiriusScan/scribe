# Go library and CLI patterns for Sirius Scribe

Research date: 2026-11-10. Upstream references below are pinned to the default-branch revisions returned by GitHub during this session. All three repositories currently use `dev` as their default branch and identify the repository license as MIT. These are research baselines, not dependency recommendations.

| Project | Default-branch revision | Observed pattern |
| --- | --- | --- |
| httpx | `9b6d8077ef7afa119dd6d28eeaf78a6556557acc` | Public `runner` package, shared options, callback results |
| naabu | `9678e5ba172784207da7525ed2381ce149d953bb` | Public `v2/pkg/runner`, context-aware enumeration, two callback timings |
| nuclei | `437698c0218d83400ac314c804741910e8ef7e80` | Public `v3/lib` SDK over core packages; CLI uses its own internal runner |

## What to adopt

**httpx shows the minimal embedding path.** Its maintained library example constructs `runner.Options`, supplies `OnResult`, calls `ValidateOptions`, creates a runner, defers `Close`, and calls `RunEnumeration`. Results carry their own `Err`. The CLI lives under `cmd/httpx` and owns process signal handling, profiling, and optional upload/database wiring. This establishes the desired importable-library-plus-installable-command delivery model. Its enumeration API currently has no caller context argument; do not copy that limitation into a new endpoint-agent library.

Sources: [library example](https://github.com/projectdiscovery/httpx/blob/9b6d8077ef7afa119dd6d28eeaf78a6556557acc/examples/simple/main.go#L16), [CLI entry point](https://github.com/projectdiscovery/httpx/blob/9b6d8077ef7afa119dd6d28eeaf78a6556557acc/cmd/httpx/httpx.go#L21), [runner lifecycle](https://github.com/projectdiscovery/httpx/blob/9b6d8077ef7afa119dd6d28eeaf78a6556557acc/runner/runner.go#L985).

**naabu makes result timing explicit.** Its public embedding path is `github.com/projectdiscovery/naabu/v2/pkg/runner`. `NewRunner` accepts options, `RunEnumeration(ctx)` accepts cancellation, and `Close` releases resources. `OnResult` means final aggregated host results; `OnReceive` means discovery-time delivery. The README explicitly distinguishes those from `Stream`, which controls input loading. Its `DisableStdout` option exists for embedding. For Scribe, make the library silent by default and define callback ordering, concurrency, and partial-result behavior as API contracts.

Sources: [library example and callback semantics](https://github.com/projectdiscovery/naabu/blob/9678e5ba172784207da7525ed2381ce149d953bb/README.md#L447), [runner execution](https://github.com/projectdiscovery/naabu/blob/9678e5ba172784207da7525ed2381ce149d953bb/pkg/runner/runner.go#L487), [embedding options](https://github.com/projectdiscovery/naabu/blob/9678e5ba172784207da7525ed2381ce149d953bb/pkg/runner/options.go#L34).

**Nuclei has the closest public engine facade.** Its dedicated `lib` package exports functional options, `NewNucleiEngineCtx`, target loading, typed `output.ResultEvent` callbacks, `ExecuteCallbackWithCtx`, and `Close`. It also has a separate thread-safe engine with per-call options and context. The older context-free entry points are deprecated in implementation even though parts of the README still use them. The CLI imports `internal/runner`, so it is inaccurate to say the Nuclei command directly wraps the public SDK; they share lower-level engine packages. For Scribe, a single public facade used by both CLI and agent will reduce behavioral drift.

Sources: [SDK implementation](https://github.com/projectdiscovery/nuclei/blob/437698c0218d83400ac314c804741910e8ef7e80/lib/sdk.go#L38), [context-aware execution](https://github.com/projectdiscovery/nuclei/blob/437698c0218d83400ac314c804741910e8ef7e80/lib/sdk.go#L304), [thread-safe SDK](https://github.com/projectdiscovery/nuclei/blob/437698c0218d83400ac314c804741910e8ef7e80/lib/multi.go#L140), [CLI runner import](https://github.com/projectdiscovery/nuclei/blob/437698c0218d83400ac314c804741910e8ef7e80/cmd/nuclei/main.go#L30).

## Dependency scope

Do not import the complete ProjectDiscovery scanner engines merely to follow their layout. Their scope is materially broader than a Lua runtime. Inspection of the pinned `go.mod` files found the following declared requirements:

| Project | `go` directive | Direct requirements | Indirect requirements |
| --- | --- | ---: | ---: |
| httpx | `1.27` | 51 | 107 |
| naabu | `1.26.10` | 30 | 77 |
| nuclei | `1.27.3` | 138 | 323 |

Counts are tab-indented module requirements, including test requirements; they do not measure the dependencies linked into an individual binary. They are evidence to inspect dependency scope, not a performance benchmark. Nuclei's module includes headless/browser, cloud, database, and many protocol integrations. Keep the Scribe core on the standard library plus the chosen Lua runtime. Add protocol libraries only when a concrete script requires them. Choose Scribe's Go floor from actual agent/toolchain support, independently of these upstream versions.

Sources: [httpx module](https://github.com/projectdiscovery/httpx/blob/9b6d8077ef7afa119dd6d28eeaf78a6556557acc/go.mod), [naabu module](https://github.com/projectdiscovery/naabu/blob/9678e5ba172784207da7525ed2381ce149d953bb/go.mod), [nuclei module](https://github.com/projectdiscovery/nuclei/blob/437698c0218d83400ac314c804741910e8ef7e80/go.mod).

## Recommended initial structure

This is a design recommendation based on the inspected projects and [Go's module-layout guidance](https://go.dev/doc/modules/layout#packages-and-commands-in-the-same-repository), not an upstream API requirement.

```text
go.mod                    # github.com/SiriusScan/scribe
engine.go                 # public library facade and lifecycle
types.go                  # request, supplied target facts, results, dialect
options.go                # validated runtime configuration
cmd/scribe/main.go        # flags, signals, exit status, JSONL output
internal/luavm/           # chosen interpreter adapter
internal/dialects/nse/    # compatibility behavior and Nmap API adapters
internal/dialects/sirius/ # native behavior and modules
examples/embed/           # compiles against the public API
examples/scripts/         # original scripts with explicit licenses
testdata/                 # hermetic fixtures and compatibility cases
docs/                     # architecture, compatibility matrix, script API
```

Start with one module. A public root package and `cmd/scribe` are sufficient; a `pkg` directory is not required for importability. Keep implementation packages under `internal` until there is an intentional external extension contract. Keep VM types out of the ordinary embedding API so the interpreter can change without rewriting the agent. A separate advanced binding package can expose VM-specific integration later if needed.

The public contract should:

- Accept `context.Context` per execution; propagate it into every host binding and network operation.
- Accept an explicit dialect and caller-supplied target/service facts. The engine executes selected scripts; it does not silently perform port discovery, service probing, or target expansion.
- Return structured execution outcomes separately from findings. An error, timeout, unsupported module, or script with no finding must not imply a clean vulnerability assessment.
- Define whether a runner permits concurrent calls, whether callbacks can run concurrently, and how caller cancellation preserves partial results.
- Keep CLI parsing, global logging configuration, filesystem conventions, queue delivery, and persistence outside the core.
- Register Go-backed Lua modules in-process through bounded host functions, rather than shell commands or unrestricted reflection. Share network/policy primitives under the two dialects while preserving their distinct script contracts.

For the first implementation, prefer a working small vertical slice over compatibility stubs: native Lua execution, an original sample script, typed output, cancellation, and an embedding example. Expose NSE as unavailable or experimental until real NSE fixtures pass; a dialect enum alone is not compatibility.

## Name candidates

| Name | Repository candidate | Assessment |
| --- | --- | --- |
| **Sirius Scribe** | `SiriusScan/scribe` | Recommended: emphasizes executable scripts and reads well as `scribe` in Go and CLI usage. Use the subtitle “Lua vulnerability script runtime.” |
| Sirius Vela | `SiriusScan/vela` | Short and fits the astronomical brand, but the purpose needs a subtitle. |
| Sirius VulnScript | `SiriusScan/vulnscript` | Most literal; less distinctive but immediately identifies scope. |
| Sirius Vesper | `SiriusScan/vesper` | Distinctive sound; less direct relationship to scripts. |
| Sirius Vigil | `SiriusScan/vigil` | Security association, but may imply continuous monitoring. |

On 2026-11-10, all five exact repository lookups returned GitHub API 404 through the current connector. This means no visible repository was found; it does not prove availability against private repositories or reserve the name. Exact-name web searches found no clear “Sirius Scribe” vulnerability-runtime collision. “Scribe” is used by unrelated software, so do not imply trademark clearance. Keep the Sirius prefix in product prose and use the scoped GitHub module path.

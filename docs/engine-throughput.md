# Engine throughput and scheduling

Measured 2026-11-11. This slice measures the native Sirius runtime on Go 1.24.13, linux/amd64, an
Intel Core i9-13900H, with the benchmark process using four Go execution threads
(the `-4` benchmark suffix). These are local engine and loopback HTTP results,
not Sirius scanner, endpoint-agent or vGPT workflow acceptance. The fixtures are
original MIT scripts. They do not establish upstream NSE compatibility.

## Runtime ownership and caches

`lua54.Options` defaults to 128 cached entries and 16 MiB of retained-template
accounting per runtime. `CacheEntries: -1` disables caching; `CacheBytes` tightens
the retained accounting ceiling. Entries use the script ID and SHA-256 of source;
the dialect is fixed by the runtime. FIFO eviction bounds retention. Accounting
is conservative allocation estimation, not an RSS guarantee. Oversized programs
still execute within runtime quotas, but are not retained. Concurrent cold misses
may compile independently; no global compilation lock serializes unrelated work.

The cache retains parsed selection metadata, compiler-produced code and the
immutable VM `Code` graph. A hit avoids parsing, compilation and VM code loading.
It binds fresh closures and environment cells to the cached code and charges
retained code memory to the invocation. There is no reuse of a live Lua state:
every invocation owns a new runtime, globals, module tables, closures and
upvalues. Grants, arguments, logs, target facts and results remain per invocation.
CPU, allocation, time, I/O and conversion bounds continue to apply. Metadata
retention includes a conservative 32x source allowance for dense JSON hint arrays. Compilation
misses run inside the existing VM quotas. Golua remains pinned to v0.1.2 / Lua 5.4;
the local `BindCode` extension is documented in the third-party patch notice.

Existing `-- scribe:` hints are checked before constructing a VM. An excluded
pair emits `status: skipped`, `verdict: unknown` and `output.skip_reason`. The
SDK index snapshots source and caches these hints. Direct `Execute` calls use
the same hints through the runtime cache. Unknown endpoint facts retain the
existing conservative matching rules. This does not implement backlog 1's richer
product/CPE/version matching language or backlog 2's identification requirements.
Arbitrary Lua rules still execute in a bounded VM; their false result cannot be
predicted safely from a previous invocation. A rule skip never becomes a verdict.

## Scheduling and streaming contract

The importable root SDK has no CLI flags or interpreter types. `Options` adds:

- `HostConcurrency`: active invocations per host, defaulting to global concurrency.
- `HostInterval`: minimum spacing between invocation admissions per host; zero
  disables pacing. For example, 100 ms permits at most ten starts per second
  without an initial burst. This limits script starts, not individual capability
  calls within an action.
- `HostErrorBudget`: execution errors before remaining host work is skipped;
  zero disables the budget. Already active actions finish, so concurrent failures
  can exceed the threshold. Unknown verdicts, rule skips and empty output are not
  execution errors or evidence of a healthy host.
- `Strategy`: `script-spray` preserves input order, normally trying scripts for
  each endpoint. `host-spray` prioritizes hosts with fewer starts across the
  current lookahead window, spreading each wave of scripts across those hosts.
  Both use available slots when an earlier host is paced or at its concurrency
  limit; neither guarantees completion order.
- `Window`: pending plus active pairs, default 256, maximum 65536. A smaller window
  trades lookahead/fairness for memory. `MaxHosts` bounds retained host accounting
  (default 65536); exhaustion returns an error rather than resetting budgets.

Host identity is the canonical fixed IP when supplied, otherwise the logical
hostname (case insensitive), shared across ports and protocols. These controls
are per run; callers coordinate limits across concurrent runs if needed. Budgets
persist across streaming windows. Declarative exclusions emit their records
before host admission and consume no concurrency, pacing or error-budget slots.

`RunSelected` no longer materializes the script/target Cartesian product or
serializes whole endpoints. It emits a record for every pair, including excluded
pairs that were previously omitted. Cancellation drains terminal records for all
pairs in its known target slice while the sink remains available. `Run` retains
that guarantee for its task slice. `RunTargetStream` pulls from a context-aware
producer with bounded lookahead. It stops pulling on cancellation and emits
terminal records for accepted pairs; unread pairs have never been submitted.
Input errors may follow earlier completed records. A sink error stops delivery,
cancels active work and waits for invocations to finish. Missing records remain
inconclusive. Producers execute synchronously and must honor their context.

The CLI and HTTP CLI-argument path use this scheduler, including
`--host-concurrency`, `--host-interval`, `--host-error-budget` and `--strategy`.
`--facts` retains its bounded JSON-array contract. `--facts-jsonl FILE` streams
one endpoint object per line from a server-local regular file, limited to 65536
records of 64 KiB each. It is mutually exclusive with `--facts`. Parsing errors
fail the invocation; a partial result stream is inconclusive. As with other local
file input, callers must use trusted filesystems; kernel file reads are not
context-interruptible. HTTP status/result/verdict semantics are unchanged.

## Connection reuse

`httpcap.Client` now reuses HTTP connections, partitioning transports by scheme,
logical authority (hostname and port) and actual connection host/fixed IP. This
retains logical Host and TLS server-name verification without ever reusing a
connection from another fixed IP under the same name. There are at most 64
endpoint pools per client, two idle connections and 32 connections per pool.
Idle connections expire at the configured finite request timeout. Idle pools
can be evicted; active pools are not evicted, and full active admission fails.
`Close` releases idle resources and prevents new requests. The no-proxy,
no-cookie, no-redirect and bounded-response rules remain in force.
`DisableReuse: true` provides the fresh-connection comparison/control.

Raw TCP banner/exchange calls deliberately keep one connection per invocation:
they expose one unframed receive chunk, so reusing a socket could consume another
script's bytes or retain protocol/authentication state. HTTP framing and complete
bounded body consumption provide the safe reuse boundary in this slice.

## Measurements

Each row uses the median of five runs. Raw output is retained alongside this
report: [before Lua](benchmarks/lua-before-go1.24.13.txt),
[before batch](benchmarks/batch-before-go1.24.13.txt), and
[after](benchmarks/lua-after-go1.24.13.txt). Benchmarks fail on execution errors;
each batch asserts all 128 records.
Warm-cache runs include one cold invocation amortized over the benchmark loop.
The batch contains eight distinct script IDs and sixteen endpoints, returning
structured Lua data for every pair. It includes planning, execution, scheduling,
source hashes, conversion and callbacks, without network I/O.

| Fixture | Before µs/op | After µs/op | Time reduction | B/op before → after | Allocations before → after |
|---|---:|---:|---:|---:|---:|
| Lua action | 35.874 | 19.486 | 45.7% | 50,937 → 30,911 | 708 → 328 |
| Dynamic rule skip (VM required) | 32.933 | 18.310 | 44.4% | 49,026 → 29,377 | 666 → 304 |
| Declarative hint skip (VM avoided) | 32.862 | 0.599 | 98.2% | 48,997 → 272 | 656 → 4 |
| 128-pair Lua batch | 3554.941 | 1943.216 | 45.3% | 6,345,008 → 4,068,579 | 84,739 → 41,390 |

| Final-engine control | Disabled µs/op | Enabled µs/op | B/op disabled → enabled | Allocations disabled → enabled |
|---|---:|---:|---:|---:|
| Code/template cache | 35.544 | 20.775 | 49,091 → 30,767 | 670 → 325 |
| HTTP reuse with real Lua action | 142.579 | 65.339 | 51,945 → 39,070 | 511 → 448 |

| Strategy, 128 real Lua executions with host concurrency 2 | Median µs/batch | Range µs/batch |
|---|---:|---:|
| script-spray | 2048.419 | 1946.406–2462.625 |
| host-spray | 2210.117 | 1932.009–2349.460 |

The before Lua microbenchmarks ran on `8bc7506`, before implementation. Their
fixture source and invocation loop are unchanged in `BenchmarkLuaThroughput`.
For the batch comparison an isolated `git archive 8bc7506` source copy receives
only `runtime/lua54/batch_benchmark_test.go`, which deliberately uses the old SDK
surface. The working tree at `400db6c` runs the identical benchmark after
implementation. The HTTP and cache-mode controls run on the final engine, toggling only reuse or
cache admission respectively, so they isolate those features from other changes.

Reproduce the final results with:

```sh
GOTOOLCHAIN=go1.24.13 go test ./runtime/lua54 -run '^$' \
  -bench 'BenchmarkLua(Throughput|HTTPReuse|CacheModes|EngineMatrix|Batch)$' \
  -benchmem -count=5
```

The complete batch drops from 3.555 to 1.943 ms
(36,006 to 65,870 pairs/second), with
35.9% fewer allocated bytes and
51.2% fewer allocations. Before batch times range from
3.276–3.825 ms; after times range from
1.795–2.432 ms. These are descriptive local measurements,
not statistical confidence bounds or a promise for network-bound scans.

The action improvement comes from bypassing compilation and loading immutable
VM code on cache hits; fresh VM/library initialization and conversion still cost
allocations. Dynamic rule skips retain that VM cost. Declarative hint skips avoid
all interpreter construction, leaving source hashing, selection and context
bookkeeping. The runtime tests assert that hint skips leave no compiled code and
succeed even with a one-byte VM memory ceiling.

The separate cache control uses a smaller action fixture; its disabled mode also
pays metadata parsing, so it is a control of cache behavior rather than a byte-for-
byte substitute for the old runtime. The HTTP control runs the same Lua/capability
path on both sides; the improvement comes from reusing framed connections rather
than dialing for every request. It measures loopback GETs, not remote latency.
Host spray prioritizes distribution and has additional scheduling cost on this
CPU-only fixture. The two strategies are policy choices, not a claim that host
spray always improves throughput. The default keeps script-spray ordering.

The previous no-op `BenchmarkSelection` is not evidence of Lua throughput and is
not directly comparable after this slice: indexed runs now emit explicit records
for excluded pairs rather than silently omitting them.

## Verification

`GOTOOLCHAIN=go1.24.13 make check` covers `go test -race ./...`, the external SDK
acceptance module, `go vet ./...`, CGO-disabled CLI build, and Windows/Darwin amd64
cross-compilation. Focused additions cover per-host limits and pacing, strategy
order, budgets and conservative skipped records, cancellation terminal records,
stream backpressure, JSONL facts, code/global/upvalue/module isolation, source
changes, cache limits, grants and tightened quotas, HTTP reuse, fixed-IP
partitioning, pool admission and close behavior. Platform builds remain build
evidence; real Sirius scanner/agent/workflow acceptance is separate.

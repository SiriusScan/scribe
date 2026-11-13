Executed Lua and synchronous JSONL handoff matrix

Environment: apps01, Linux amd64 6.1.0-54-cloud-amd64, Go 1.26.10,
GOMAXPROCS=4. Three samples of three batches per setting; benchmarks ran before
make check, without concurrent fuzz/load work initiated by this release.

Command:
GOMAXPROCS=4 go test ./runtime/lua54 -run '^$' -bench '^BenchmarkPlanner(Execution|JSONLHandoff)$' -benchtime=3x -count=3 -benchmem

Each batch verifies all 512 terminal records and every completed Lua sum.
Selected batches execute 64 actions and emit 448 skips; unfiltered execute 512.
All envelope verdicts must remain unknown. The handoff variant encodes every
record with encoding/json to io.Discard inside the serialized sink callback.
This measures encoding/backpressure cost, not disk persistence or network I/O.
The shared runner now additionally reports records/s; the raw initial samples
predate that metric (derive it as 512 / batch seconds).

Unfiltered module-limit-zero handoff: one worker 24,191–36,530 actions/s,
eight workers 70,456–77,620 actions/s. Baseline ranges: 24,884–35,781 and
88,436–97,176 respectively. Short shared-host samples do not establish a
before/after speedup or general scaling guarantee. Selected timings must not
be compared as though they executed 512 actions. Live consumer persistence
and cancellation acceptance remain outstanding.

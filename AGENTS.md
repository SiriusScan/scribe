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

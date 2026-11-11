# Changelog

## v1.0.0 — 2026-11-11

- Complete the exported-field audit across the SDK, adapters, capabilities, jobs, reports, compatibility tools and Lua runtime; document units, defaults and zero behavior.
- Add focused validation for orchestration/runtime defaults, invalid options, confidence bounds, inclusive version matching, advisory ports and empty/conservative evidence.
- Preserve existing API signatures and runtime behavior. Phase 3 remains paused; local build/service checks do not establish scanner/agent or full vGPT acceptance.

## v0.9.0

- Add SDK evidence deduplication and conservative summary counts; expose --summary in CLI and /run.
- Drain HTTP handlers during bounded graceful shutdown.
- Refresh library result-processing quickstart and executable examples.

## v0.8.0

- Add structured SDK lifecycle observations and versioned event JSONL.

## v0.7.0

- Add mixed-corpus planner regression and execution benchmarks.

## v0.6.0

- Extend identification, planning and bounded execution controls.

## v0.5.0

- Require match metadata in corpus lint; declare products for legacy fixtures.
- Add opt-in SNMP v2c planner service identification with an explicit community,
  correlated responses, a 250 ms budget and an 8 KiB response ceiling.
- Document library versioning and independent execution/verdict semantics.

## v0.4.0

- Add bounded, correlated DNS/NTP UDP planner probes.
- Add library quickstart examples and corpus metadata lint.

## v0.3.0

- Extend planner identification with TLS, HTTP headers, CPE and confidence.
- Add strict identification, exhaustive execution and cached planner probes.

## v0.2.0

- Polish SDK Run, Batch and Stream entry points and examples.
- Add bounded scheduling, immutable compiler caches and ping++ facts adapter.

## v0.1.0

- Introduce importable SDK, explicit Sirius/NSE dialects and isolated Lua execution.
- Add bounded capabilities, CLI/HTTP execution, conservative report envelopes,
  embedded jobs and opt-in endpoint-local capabilities.

Build, fixture and local transport checks do not establish compatibility with
an upstream NSE corpus or Sirius scanner/agent integration acceptance.

## v0.6.0

- Expand product fingerprint and CPE hints across HTTP, mail, FTP, database,
  Redis and SSH identities; identification never supplies vulnerability verdicts.
- Add CLI/HTTP --plan and library Options.Plan without actions or planner probes.
- Add per-run global start pacing and SDK per-script timeout; preserve existing
  concurrency and CLI/HTTP timeout controls.

## v0.7.0

- Add a shared mixed-corpus planner regression and executed benchmark across 512
  script/target pairs, including failures, missing identities and explicit verdicts.
- Assert complete unique terminal records, conservative verdicts and skip reasons;
  record selected and exhaustive benchmark samples in the roadmap.

## v0.8.0

- Add SDK Event/Options.OnEvent callbacks for terminal planning decisions, skip
  reasons, module timing and verdicts.
- Share opt-in --events JSONL across CLI and streaming POST /run.
- Document schema v1, callback ownership and compatibility; pin a golden fixture.

## Unreleased — v1.0.0 preparation

- Add JSONL module metadata inventory with `--list-modules`.
- Add match metadata and inventory JSONL fuzz targets and a root exported-symbol golden.

- Fill missing public declaration godoc and correct misplaced option/type comments.
- Expand original pinned HTTP fingerprints and unknown-identity negative fixtures.
- Preserve public API declarations; refresh signature-golden formatting only.

## v0.9.1

- Pin false-clean behavior and exact skip reasons for unknown and mismatched
  identities in selected and exhaustive Sirius execution.
- Document Limits accounting units and task ceiling semantics.
- Defer v1.0.0 pending the complete exported-field documentation/behavior audit.
  Phase 3 remains paused.

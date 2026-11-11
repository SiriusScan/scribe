# Changelog

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

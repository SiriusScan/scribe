# Integration with Sirius

This is a proposed integration, based on pinned public sources inspected on
2026-11-10. This repository does not change or deploy Sirius services.

## app-scanner becomes the orchestration host

The current scanner already separates fingerprinting, port discovery, and
vulnerability execution. Its `ScanStrategy.ExecuteWithContext(ctx, target)` returns
`sirius.Host`, and its factory selects Nmap for vulnerability jobs. The manager
then type-asserts `*NmapStrategy` to inject script/port options and hardcodes `nmap`
in source attribution. These are concrete seams to generalize.

Add a Scribe-backed strategy beside Nmap, selected explicitly by a job or template.
Give strategies a typed request and source identity instead of mutating one
concrete Nmap implementation. Resolve script IDs and content through the current
catalog adapter, verify the chosen revisions, and construct `scribe.Task` values.
Supply only the known ports and their actual protocol/state/service metadata.

Nmap currently runs with `-sV`, which contributes service and version facts.
Removing it from a job without providing an alternative removes those facts.
Keep Nmap's service detection or another explicit discovery stage until a separate
component provides the required input. Scribe should neither guess service names
from port numbers nor invent version evidence.

The strategy consumes results as they complete, maps native findings into Sirius
transport types, and preserves the full result as evidence. Keep the script ID,
source digest, dialect, target, execution status, and error alongside the finding.
Use a distinct source name such as `scribe`, with engine version and nonsecret
configuration. Do not treat raw NSE output or a textual CVE mention as a positive
vulnerability finding. A future `vulns` adapter needs explicit state semantics.

Preserve run correlation, exact scan-ID cancellation, terminal-state protection,
and current transactional report ingestion. RabbitMQ, Valkey, `currentScan`,
template synchronization, database access, and NVD enrichment remain outside the
engine. An unsupported script is missing coverage, even if other scripts succeed.

Primary source:
[strategy interface](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/internal/scan/strategies.go),
[Nmap coupling](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/internal/scan/manager.go#L827-L930),
[service discovery](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/modules/nmap/nmap.go#L145-L206).

## Endpoint agents import the module

The agent's command registry already accepts context-aware internal commands.
Register a separate `internal:script-scan` command and invoke Scribe directly.
The Go API grants a chosen function registry, so the endpoint can expose bounded
local inventory checks without shelling out or granting all scripts filesystem
and process access. A network job and a local inventory job may use different
registries over the same native script contract.

Use a versioned command envelope containing run ID, selected script descriptors,
content digests, target facts, arguments, and capability policy. Validate it before
execution. Avoid sending a Lua script through the existing unknown-command shell
fallback. Keep secrets out of source, results, and ordinary arguments; any future
credential capability needs its own explicit interface and redaction contract.

The current coordinated-result merger expects a template-specific JSON shape.
Adding an import alone is insufficient: dispatch on a versioned result kind and
map Scribe results while retaining scan-ID and lifecycle checks. Update UI command
generation, server dispatch, endpoint registration, and result merging together.

Acceptance requires an actual installed endpoint running a real coordinated job.
A successful library test or cross-compiled binary establishes only that stage.

Primary source:
[command registry](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/commands/registry.go#L115-L141),
[existing template command](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/commands/templatescan/scan_command.go),
[coordinated merger](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/server/server.go#L1154-L1183).

## Source and deployment pins

The inspected source baselines are recorded in
[the research memo](research/sirius-integration.md#source-revisions). The main
Sirius Dockerfile pins component SHAs that differ from current repository heads.
Before an integration release, verify the intended module tag, consumer commits,
Docker build arguments, installed binary versions, and actual job behavior.

The endpoint build uses `CGO_ENABLED=0`, which supports the initial pure-Go Lua
choice. Add no dependency on scanner executables or libpcap to the core. Keep
runtime-specific packages optional so consumers can build only the dialects and
capabilities they enable.

Primary source:
[Sirius build pins and endpoint build](https://github.com/SiriusScan/Sirius/blob/823a80f663e585db775da4ce58b27ac0e5dcfbd2/sirius-engine/Dockerfile#L163-L220),
[transactional report shape](https://github.com/SiriusScan/go-api/blob/4ef20d34a5d98244869caaca3461233d0ecba556/sirius/host/report.go).

### Version 1 embedded jobs

`job.Run` accepts a `job.Request` with schema_version 1, a correlation ID,
script ID, explicit dialect, inline source (or a caller-owned resolver), args,
SDK Target facts, SDK Limits, and capability grants. Source is a JSON string;
timeout uses Go duration nanoseconds. Results carry the same correlation ID and
existing version 1 Sirius report envelope. Check both the returned error and
execution evidence; absent evidence is inconclusive.

Grants are exact registered function names (for example `tcp`); omitted or empty
job grants deny all capability calls. Register protocol functions with separate
names to grant them separately. Denial returns `scribe.CapabilityDeniedError`
from the runtime, fails execution even if Lua catches it, and never establishes a
verdict. Engine results retain its diagnostic text. Legacy Task calls with nil
grants preserve their existing authority; explicit empty Task grants deny all.
Per-job CPU, memory, and timeout limits only tighten runtime ceilings; zero uses
those finite ceilings. Trusted Go functions must honor cancellation and bound
I/O themselves. This is an embedding contract, not endpoint-agent acceptance.

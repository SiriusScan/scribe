# Sirius integration research

Verified 2026-11-10 from read-only shallow clones of the public `SiriusScan` organization. These are repository source observations, not verification of installed containers or live scan behavior.

## Source revisions

| Repository | Default branch | Inspected HEAD |
|---|---|---|
| [Sirius](https://github.com/SiriusScan/Sirius) | main | `823a80f663e585db775da4ce58b27ac0e5dcfbd2` |
| [app-scanner](https://github.com/SiriusScan/app-scanner) | main | `e3b4333b66c3744732c194994be65e46e533fa66` |
| [app-agent](https://github.com/SiriusScan/app-agent) | main | `004dadf3ae3a685724f3049befb9193524ec01d3` |
| [go-api](https://github.com/SiriusScan/go-api) | main | `4ef20d34a5d98244869caaca3461233d0ecba556` |
| [sirius-nse](https://github.com/SiriusScan/sirius-nse) | main | `a58e8c5330b49bd8f4e93c27e340c43c1fa89fa9` |
| [sirius-agent-modules](https://github.com/SiriusScan/sirius-agent-modules) | main | `15d56a6e391c6b4520ad3b4e82c5352fdfa513ba` |

GitHub's connected repository search returned an incomplete organization inventory; `gh repo list SiriusScan` and authenticated `gh repo clone` supplied the complete sources. No upstream repository was changed.

## Existing scanner is already close to an orchestration layer

The concrete pipeline is fingerprinting through ping++, enumeration through Naabu, then Nmap vulnerability scripts against discovered or explicitly configured ports. The README calls ping++ a placeholder, but the current factory constructs a real `PingPlusPlusAdapter`; prefer source to that older prose.

- The current import boundary is `ScanStrategy.ExecuteWithContext(ctx, target string) (sirius.Host, error)`, with a convenience non-context method. [strategies.go:17–30](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/internal/scan/strategies.go#L17-L30)
- `ScanToolFactory.CreateTool` maps `enumeration`/`port_scan` to Naabu and `vulnerability` to Nmap. Fingerprinting has a separate interface. [factory.go:21–83](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/internal/scan/factory.go#L21-L83)
- The manager resolves template scripts, creates the strategy, type-asserts `*NmapStrategy` to inject scripts and ports, executes it, logs tool name `nmap`, and submits source-attributed host data. This coupling is the principal integration seam to generalize. [manager.go:827–930](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/internal/scan/manager.go#L827-L930)
- The Nmap module executes `exec.CommandContext(..., "nmap", ...)` with `-sV`, explicit ports, scripts, and XML output. Thus removing Nmap also removes its service/version enrichment; a script-only engine must receive service facts from another component or document reduced rule applicability. [nmap.go:145–206](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/modules/nmap/nmap.go#L145-L206)

Recommendation: keep app-scanner as the initial orchestration host. Add a library-backed script strategy alongside Nmap, with explicit engine selection. Replace hardcoded Nmap option mutation and source labeling with a typed execution request plus strategy identity. Do not silently fall back from unsupported NSE behavior to a different script set or report no findings as success.

## Job and lifecycle contracts

`ScanMessage` uses JSON `{id, targets, options, priority, callback_url}`. Targets have `{value,type,timeout}`; options contain template ID, port range, scan types, retries, parallelism, exclusions, and fingerprint controls. [manager.go:33–74](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/internal/scan/manager.go#L33-L74)

The manager synchronizes the NSE catalog and initializes templates before listening to RabbitMQ queue `scan`. It validates messages before creating a new run. Cancellation uses `scan_control` with an exact `scan_id`. Current lifecycle code binds queued work to its originating run, uses compare-and-set writes, preserves terminal states, and distinguishes completion from success. [manager.go:339–378](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/internal/scan/manager.go#L339-L378), [scan-lifecycle.md](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/documentation/scan-lifecycle.md)

Recommendation: preserve these lifecycle invariants in adapters. The new library should accept `context.Context`, per-run immutable options, known hosts/ports/services, and script source descriptors. It should return per-script outcomes (`executed`, `skipped`, `unsupported`, `error`, `cancelled`) separately from vulnerability findings. Queue listeners, `currentScan`, Valkey, API persistence, NVD enrichment, target discovery, and aggregate run status belong outside the library.

## Finding shape and evidence

The legacy SDK transport type is `sirius.Host` with IP, hostname, OS, ports, services, CPEs, and `[]sirius.Vulnerability`. Vulnerabilities include VID, title, description, risk score, CVE, CVSS, severity, remediation, tags, confidence, and arbitrary metadata. [sirius.go:45–62](https://github.com/SiriusScan/go-api/blob/4ef20d34a5d98244869caaca3461233d0ecba556/sirius/sirius.go#L45-L62), [sirius.go:150–175](https://github.com/SiriusScan/go-api/blob/4ef20d34a5d98244869caaca3461233d0ecba556/sirius/sirius.go#L150-L175)

Current SDK source provides transactional `host.AddReport`, which validates all evidence first, keeps original scanner evidence separate from optional catalog enrichment, and atomically persists host observations and scan history. Source fields are `{name,version,config}`. Per-host vulnerability records retain the full finding as JSONB, confidence, and optional port/service information. [report.go:20–70](https://github.com/SiriusScan/go-api/blob/4ef20d34a5d98244869caaca3461233d0ecba556/sirius/host/report.go#L20-L70), [host.go:130–144](https://github.com/SiriusScan/go-api/blob/4ef20d34a5d98244869caaca3461233d0ecba556/sirius/postgres/models/host.go#L130-L144), [scan_source.go:12–17](https://github.com/SiriusScan/go-api/blob/4ef20d34a5d98244869caaca3461233d0ecba556/sirius/postgres/models/scan_source.go#L12-L17)

The existing Nmap extraction searches output text for CVEs and words such as `VULNERABLE`; it assigns default scores (including 5.0 and 7.5). This is an integration behavior to improve rather than copy into the new engine. [nmap.go:383–447](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/modules/nmap/nmap.go#L383-L447)

Recommendation: engine-native findings should preserve script ID/revision/digest, dialect, host, port/protocol, execution ID, timestamps, structured evidence, vulnerability state, optional severity/CVSS/confidence, and references. Keep absent scores/confidence distinguishable from explicit zero. NSE textual output alone is not proof of vulnerability; map recognized `vulns` state structurally and preserve unknown output as script evidence. A thin Sirius adapter can populate the SDK transport and retain the full engine result under metadata. Avoid importing the database-heavy go-api module into the engine core.

## Endpoint-agent embedding

Both `app-agent/go.mod` and `app-scanner/go.mod` declare **Go 1.24.0** with `toolchain go1.24.1`. Using a Go 1.24 floor for the new module matches both current consumers. [agent go.mod](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/go.mod#L1-L5), [scanner go.mod](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/go.mod#L1-L5)

The agent already has a context-aware internal command registry. A `commands.Command` implements `Execute(context.Context, AgentInfo, commandString, args) (string,error)`. [command.go](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/commands/command.go), [registry.go:115–141](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/commands/registry.go#L115-L141)

`internal:template-scan` is registered at initialization and executes local YAML detection templates through a worker pool with the command context and per-template timeout. It is a different format from the proposed Lua dialect. [scan_command.go:28–40](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/commands/templatescan/scan_command.go#L28-L40), [scan_command.go:126–173](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/commands/templatescan/scan_command.go#L126-L173)

Commands arrive via RabbitMQ `agent_commands` to the agent server, which sends gRPC `CommandRequest` strings to the endpoint. The agent calls `commands.Dispatch`; unknown commands currently fall back to PowerShell. A new registered `internal:script-scan` command should call the library directly, preventing Lua scripts from traveling through that shell fallback. [server.go:30–70](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/server/server.go#L30-L70), [server.go:1030–1067](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/server/server.go#L1030-L1067), [agent.go:323–382](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/agent/agent.go#L323-L382)

Coordinated results are recognized by `--scan-id`; the server currently decodes a template-specific `{summary,results}` output shape before merging to `currentScan`. Adding Lua is not just adding an import: add a versioned script-job/result envelope or an explicit adapter and dispatcher in this merger, retaining run ID checks. [server.go:465–470](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/server/server.go#L465-L470), [server.go:1154–1183](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/server/server.go#L1154-L1183), [scan_state.go:128–153](https://github.com/SiriusScan/app-agent/blob/004dadf3ae3a685724f3049befb9193524ec01d3/internal/server/scan_state.go#L128-L153)

The main Sirius UI also has an older `agentScan` dispatch router that builds `internal:template-scan --all --scan-id=... --workers=... --timeout=...` strings. Treat deployed UI/API source pins as a separate compatibility check. [agentScan.ts:83–119](https://github.com/SiriusScan/Sirius/blob/823a80f663e585db775da4ce58b27ac0e5dcfbd2/sirius-ui/src/server/api/routers/agentScan.ts#L83-L119)

## Script catalog

At the inspected Sirius NSE revision, both the manifest and disk contain **612 `.nse` scripts**. A static regex census of direct `require` calls finds:

| Module | Scripts directly requiring it |
|---|---:|
| stdnse | 562 |
| shortport | 451 |
| nmap | 371 |
| http | 158 |
| creds | 79 |
| vulns | 72 |
| ipOps | 69 |
| brute | 64 |
| comm | 60 |
| io | 60 |
| target | 45 |
| smb | 40 |

These counts are prioritization evidence, not compatibility coverage. They exclude transitive dependencies and dynamic requires. Some scripts have more than one rule; static rule assignments found 463 portrules, 73 hostrules, 69 prerules, and 11 postrules. The corpus includes discovery and other NSE categories as well as vulnerability checks. Script licensing is mixed and generally references the Nmap license; do not relabel this corpus MIT.

Catalog source: [manifest.json](https://github.com/SiriusScan/sirius-nse/blob/a58e8c5330b49bd8f4e93c27e340c43c1fa89fa9/manifest.json), [scripts](https://github.com/SiriusScan/sirius-nse/tree/a58e8c5330b49bd8f4e93c27e340c43c1fa89fa9/scripts).

app-scanner currently synchronizes repositories and content through shared `go-api/sirius/store/templates` key contracts (`nse:script:<canonical-id>`, `nse:manifest`, `nse:repo-manifest`), with UI-owned content preservation. Reuse this in an outside-the-engine catalog adapter; the execution library should consume an already-resolved immutable script bundle. [types.go:12–38](https://github.com/SiriusScan/app-scanner/blob/e3b4333b66c3744732c194994be65e46e533fa66/internal/nse/types.go#L12-L38), [keys.go:36–52](https://github.com/SiriusScan/go-api/blob/4ef20d34a5d98244869caaca3461233d0ecba556/sirius/store/templates/keys.go#L36-L52)

## Deployment and version skew

The main Sirius engine Dockerfile builds Nmap **7.95** from source and clones independent component repos at explicit SHA arguments. Its current pins differ from the current scanner/agent/SDK heads inspected above:

- `GO_API_COMMIT_SHA=ebd42f4239ec2d0c99e3e7c463a5fc181f57737f`
- `APP_SCANNER_COMMIT_SHA=a031480cc7e0dc4a1cb09bdcfafedd89fbc61dfd`
- `APP_AGENT_COMMIT_SHA=9311f3805db9cc08740f1b588b6f3bff9191c9dd`
- `SIRIUS_NSE_COMMIT_SHA=a58e8c5330b49bd8f4e93c27e340c43c1fa89fa9`

Scanner is built with CGO/libpcap; agent and server are built with `CGO_ENABLED=0`. The latter is a strong reason to keep a pure-Go execution option. [Dockerfile:38–67](https://github.com/SiriusScan/Sirius/blob/823a80f663e585db775da4ce58b27ac0e5dcfbd2/sirius-engine/Dockerfile#L38-L67), [Dockerfile:163–220](https://github.com/SiriusScan/Sirius/blob/823a80f663e585db775da4ce58b27ac0e5dcfbd2/sirius-engine/Dockerfile#L163-L220)

Production copies the scanner/agent binaries and the NSE repository into the runtime image and replaces Nmap's script directory with a symlink to `/sirius-nse/scripts`. [Dockerfile:304–337](https://github.com/SiriusScan/Sirius/blob/823a80f663e585db775da4ce58b27ac0e5dcfbd2/sirius-engine/Dockerfile#L304-L337)

Recommendation: release/pin a library tag in each consumer, then update Sirius Dockerfile and CI pins consistently in a separate integration change. Building the new repository alone does not deploy it into Sirius or any endpoint agent.

## Proposed adoption sequence

1. Standalone, importable Go engine and thin CLI; independent target/service inputs and typed results; two explicit dialects; MIT-owned implementation only.
2. Local fixture acceptance of native Lua and a declared, measured NSE compatibility subset. Unsupported modules/APIs produce explicit unsupported outcomes.
3. app-scanner strategy adapter alongside Nmap; compare a pinned script corpus against Nmap on lab fixtures, then select per job/script. Keep discovery separate.
4. app-agent registered script command, with versioned results and explicit enabled capabilities for network versus local checks. Integrate run correlation and cancellation before enabling coordinated scans.
5. Incrementally move remaining scanner responsibilities behind orchestration interfaces. Retire Nmap only after compatibility and operational acceptance gates pass for the desired corpus.

Existing organization names include `Procyon`, `pingpp`, `sirius-nse`, and `sirius-agent-modules`; avoid colliding with those. Do not name this engine `app-scanner`, since that obscures the execution-only role.

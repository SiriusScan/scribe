# Experimental NSE profile

The `nse` dialect is an initial compatibility profile. **No upstream Nmap or
Sirius NSE corpus compatibility has been validated.** The current tests exercise
original MIT fixtures and selected helper semantics. Do not replace an existing
Nmap vulnerability job with this profile based on file extension or Lua version.

## Language and implemented surface

Lua 5.4 is provided by an internally bundled GoLua v0.1.2 source subset with a
declared Go-toolchain compatibility patch. Current Nmap's Lua version requirement is a
necessary language baseline, not a sufficient compatibility test. The reference
research baseline is Nmap 7.993 and development revision
`4394ae5c1f5ca46725e13dcde5690258c1ab3d92`; differential execution against that
reference is future work. apps01's installed Nmap 7.93 uses Lua 5.3 and was not
upgraded or treated as the current compatibility oracle.

| Surface | Initial behavior |
| --- | --- |
| Script format | Top-level Lua metadata assignments and a required action function |
| Rule phase | Exactly one `hostrule` or `portrule`; rule must return a boolean |
| Host facts | Supplied IP, target name, and an empty name when no reverse-DNS fact exists |
| Port facts | Supplied number, protocol, state, service, and TLS tunnel metadata |
| Script globals | Script name/path identity; rule/action phase type |
| Arguments | `stdnse.get_script_args(name, ...)` over the supplied argument table; one return value per name (nil when absent) |
| Output tables | `stdnse.output_table()` returns a plain table; no NSE ordered-table guarantee |
| `stdnse` helpers | `get_hostname`, `string_or_blank`, `tohex`, `fromhex`, `parse_timespec`; `debug`/`debug1`/`debug2`/`debug3`/`verbose`/`print_debug`/`print_verbose` are silent no-ops (the library has no verbosity channel; diagnostics never become output) |
| Port helpers | `shortport.portnumber`, `shortport.service`, `shortport.port_or_service`, `shortport.port_range`, and the `shortport.http`/`shortport.ssl` rules (ssl also matches a supplied `service_tunnel == "ssl"` fact) |
| Likely-service tables | `shortport.LIKELY_HTTP_PORTS/SERVICES`, `LIKELY_SSL_PORTS/SERVICES`: documented Scribe initial sets pinned by first-party fixtures, not a claim of parity with any upstream nselib revision |
| Helper filters | Number/service, protocol, state; scalar or list inputs; default TCP and open/open\|filtered filters; unknown port-state names are an explicit error, not a silent never-match |
| Action output | Nil, string, JSON-representable table, or table plus textual return |
| Finding conversion | No automatic NSE text-to-vulnerability inference; raw output is preserved as data |

Unknown port state does not become open. Missing service facts do not become a
guessed service. The initial target model does not represent the full Nmap host
and service-version structures. The host runtime does not perform reverse DNS or
host discovery. Helper support is limited to the listed semantics and fixtures.

## Explicitly unsupported

- `prerule`, `postrule`, multiple rule phases, and nonempty script dependencies.
- `shortport.version_port_or_service` and `shortport.port_is_excluded` (they depend
  on Nmap version-probe state Scribe is not supplied), and every `stdnse` function
  not listed above (threads, registries, buffers, `sleep`, formatting, and clocks).
- `nmap` APIs, Nsock sockets, TCP/UDP/TLS networking through NSE APIs, raw packets,
  scanner-state mutation, target expansion, and version probing.
- NSE `http`, `vulns`, `comm`, `smb`, credentials, brute-force, and other protocol
  modules. Native `http.get` is a different contract and is unavailable here.
- General on-disk `nselib` module loading, C modules, LPeg, OpenSSL, libssh2, zlib,
  and arbitrary `package` search paths.
- Shared NSE registries/caches, script worker coroutines, mutexes, condition
  variables, and dependency-aware session scheduling.
- Full Lua `io`, `os`, `debug`, coroutine, and metatable behavior; binary result
  strings and non-JSON output structures.

An unrecognized module or helper API returns an explicit execution error. There
is no implicit Nmap subprocess fallback. A skipped script, unsupported API, or
empty output must not be recorded as a successful vulnerability assessment.

## Measured compatibility harness

The first-party harness runs original MIT fixtures against inert supplied facts.
The schema 2 report keeps fixture assertions and measured dispositions
independent. Each row includes the case-input and script SHA-256, the expected
and observed status, a bounded phase and reason code where available, and the
exact JSON output for completed scripts. Fixtures can additionally assert the
separate textual return and explicit verdict. A skipped rule, missing required
fact, recognized unsupported surface, or expected rejection can match its
fixture without increasing the pass count. A timeout, cancelled case or missing
result makes the run incomplete.

`Report.OK()` still tests fixture expectation agreement for SDK callers.
`Report.CoveredCases(manifest)` requires a strict schema 2 manifest and complete
matching rows with the pinned digests. It returns only the completed cases
whose asserted, nonempty data was observed. Schema 1 input remains readable for
regression runs. A schema 1 report supplies no schema 2 coverage.

Run `make compat` to refresh the checked-in portable snapshot in
`compat/report.json`. The CLI publishes full build provenance along with the
evidence. To write that report to a file, run
`go run ./cmd/scribe-compat --manifest compat/manifest.json --out report.json`.
The checked-in snapshot excludes machine-specific build provenance. The CLI
test regenerates twice and compares the report bytes and snapshot, so the
default CI test job detects stale snapshots and mismatched inputs. The
first-party evidence covers the fixture cases only.

## Offline reference lineage

`scribe-compat lineage` checks supplied JSON records without running a candidate,
reference tool, or fixture script. It emits a separate schema 1 receipt and
preserves the existing manifest and schema 2 fixture report. A successful
command exit means the receipt was produced. Read `release_qualified` and each
scope's `qualified` field to make an eligibility decision.

The checked-in [synthetic example](../internal/compatlineage/testdata/) has
one affirmative and one explicit negative comparison across two independent
scopes. Both pairs match and both retain their synthetic origin. There are zero
verified legacy comparisons and `release_qualified` is false.

```sh
go run ./cmd/scribe-compat lineage \
  --scope internal/compatlineage/testdata/scope.json \
  --candidate internal/compatlineage/testdata/candidate.json \
  --reference internal/compatlineage/testdata/reference.json \
  --review internal/compatlineage/testdata/review.json
```

The trusted scope declares the exact release tuple and the workflows, required
canonical case IDs, supplied inputs, expected reference producers and pinned
review digests. Keep this plan under independent review. A submitter able to
replace the trusted plan and every supplied file could choose all the digests
and producer identities. The verifier checks consistency against the trusted
pins. Producer identities and review approvals come from the caller's evidence
process.

The candidate and reference files each carry a record per workflow and case.
A record contains the SHA-256 of the normalized supplied input, the normalization
policy, its own producer identity and artifact SHA-256, and the SHA-256 of the
exact bytes of its `result` JSON value. Preserve those result bytes, including
whitespace inside the value, when transporting a reviewed record. The result
records disposition, terminal completeness, explicit verdict and data.

The independent review file approves a specific reference result digest,
producer, provenance kind, input, policy and scope digest. The scope digest
covers schema and policy, the release tuple, workflow ID, reference kind and
producer, and the case IDs with normalized input digests sorted by ID. The
workflow's per-case review digest is the SHA-256 of the compact JSON review
object in schema field order, as shown in the example. Scope and review objects
use Go's compact JSON encoding. The `scribe-json-v1` policy sorts JSON object
keys, preserves array order and numeric spelling, and rejects duplicate keys.
It compares the normalized data and the explicit verdict after verifying that
both results completed.

Omitting a record or review file records missing evidence for each required
case. Wrong pins, duplicate cases, changed reviewed bodies and outcome differences
have machine-readable case findings. Unsupported, skipped, failed, partial,
cancelled and unknown results never count toward affirmative or negative coverage.
The report retains each scope's denominator and counts when another scope fails.
A legacy scope requires an exact legacy artifact pin and an approved, matching
comparison for every required case. The root receipt includes the supplied release
tuple and the SHA-256 of its compact `scopes` array. The original ten fixture
cases still contribute five matching completed fixture cases and zero verified
legacy comparisons.

The receipt supplies case evidence for [Scribe #12](https://github.com/SiriusScan/scribe/issues/12).
[Sirius #183](https://github.com/SiriusScan/Sirius/issues/183) owns verifying that
the receipt applies to the packaged binary and platform image.

## Open item: select the Phase 1 reference pin

No reference Nmap version or external corpus revision has been selected yet as
the Phase 1 differential pin, so no upstream compatibility is claimed. The facts
on hand, from the linked research, do not by themselves make the selection:

- The research baseline is Nmap 7.993 with development revision
  `4394ae5c1f5ca46725e13dcde5690258c1ab3d92` (its `nse_main.lua` requires Lua 5.4+).
- The researched `SiriusScan/sirius-nse` corpus is at `a58e8c5330b49bd8f4e93c27e340c43c1fa89fa9`.
- The Sirius engine image builds Nmap 7.95 from source; apps01's installed Nmap
  7.93 uses Lua 5.3 and is not a current oracle. None of these has been approved
  as *the* pin, and the corpus distribution/license audit is still outstanding.

Closing this item means one explicit decision recording: the exact Nmap release
(and how the differential oracle is built/run), the exact external corpus
revision and its selected vulnerability-script subset, and the license review
outcome for that subset. Then record the values in `compat/manifest.json`'s
`reference_*` fields (and a second, external-corpus manifest), and update the
`pin_status` there and here. Until then, manifest reference fields stay empty
with `pin_status: open`.

## Corpus compatibility program

The current `SiriusScan/sirius-nse` research corpus contains 612 scripts at revision
`a58e8c5330b49bd8f4e93c27e340c43c1fa89fa9`. It contains more than vulnerability
checks, and it is not bundled here. Its direct-require census is a prioritization
input only; transitive modules and actual runtime paths determine compatibility.

For each proposed supported script, record the script digest, transitive bundle,
license review, required API semantics, supplied target facts, local fixture
cases, reference Nmap version, and actual outcomes. Report pass, fail, and
unsupported separately. Validate false rules, network errors, TLS, timeouts,
malformed/partial data, output state, cancellation, and cleanup. Only then advertise
that script/revision as supported.

The [roadmap](roadmap.md) places this gate before scanner replacement. The
[runtime research](research/nse-runtime.md) and
[Sirius research](research/sirius-integration.md) contain the pinned sources.

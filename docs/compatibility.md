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

`make compat` runs the pinned manifest in `compat/manifest.json` through the
`compat` package (`cmd/scribe-compat`) and writes the deterministic JSON report to
`compat/report.json`. Each case pins the exact script SHA-256 (a digest mismatch
fails without executing), the supplied target facts and arguments, and one asserted
outcome. A `completed` expectation must assert the exact action output as JSON;
completion or module loading without an output assertion is rejected by manifest
validation and can never count as a pass. Scripts that hit an explicitly
unsupported API are reported `unsupported` with the error as the reason, separately
from `pass` and `fail`; an unsupported outcome the manifest did not predict fails
the run. The current manifest covers original MIT fixtures only (10 cases over the
`stdnse`/`shortport` slice above, two of them expected-unsupported). It is
measurement infrastructure and first-party regression evidence, not an upstream
corpus result and not a compatibility percentage for any Nmap script set.

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

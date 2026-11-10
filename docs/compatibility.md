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
| Arguments | `stdnse.get_script_args(name)` over the supplied argument table |
| Output tables | `stdnse.output_table()` returns a plain table; no NSE ordered-table guarantee |
| Port helpers | `shortport.portnumber`, `shortport.service`, `shortport.port_or_service` |
| Helper filters | Number/service, protocol, state; scalar or list inputs; default TCP and open/open\|filtered filters |
| Action output | Nil, string, JSON-representable table, or table plus textual return |
| Finding conversion | No automatic NSE text-to-vulnerability inference; raw output is preserved as data |

Unknown port state does not become open. Missing service facts do not become a
guessed service. The initial target model does not represent the full Nmap host
and service-version structures. The host runtime does not perform reverse DNS or
host discovery. Helper support is limited to the listed semantics and fixtures.

## Explicitly unsupported

- `prerule`, `postrule`, multiple rule phases, and nonempty script dependencies.
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

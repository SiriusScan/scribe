# Native script API version 1

Select `sirius` explicitly. A script chunk returns this descriptor:

```lua
return {
  api_version = 1,
  rule = function(target, args)
    return target.protocol == "tcp" and target.port > 0
  end,
  action = function(target, args)
    local response = sirius.call("http.get", args.path or "/")
    return { data = { status = response.status }, findings = {} }
  end
}
```

`rule` is optional and must return a boolean. A false rule skips the action.
`action` is required and returns an output table. The top-level chunk executes
before rule evaluation, under the same finite invocation budget.

## Target and arguments

`target` exposes `host`, `ip`, `port`, `protocol`, `state`, `service`, and `tls` from
the submitted task. Host is the logical hostname or unbracketed IP. Optional IP is
the fixed connection address. Port zero means a host-only task. State, protocol,
and service are supplied facts; scripts must not infer that missing information
is known. `args` is the caller's argument object, or an empty table.

Source is limited to 1 MiB. Go arguments and capability values use explicit
JSON-compatible scalars, string-keyed maps, and arrays. Lua integers are signed
64-bit. Nonfinite numbers, functions, userdata, mixed-key tables, sparse arrays,
cycles, and non-UTF-8 strings cannot be represented in the JSON result contract.
Empty Lua tables normally encode as objects; an empty `findings` table is accepted
as an empty list. Nil array elements are rejected because Lua cannot retain them.

## Go capabilities

The host registers compiled Go functions by name in `lua54.Options.Functions`.
The script calls them with `sirius.call(name, ...)`. `require("sirius")` also returns
the same module. Unregistered names produce an execution error. No dynamic Go
imports, reflection bridge, shell, or automatic module installation is provided.

The function receives `context.Context`, the caller's `scribe.Target`, and its
converted arguments. It returns one JSON-compatible value or an error. The host
function must honor cancellation, validate inputs, and bound its own allocations
and output; VM quotas do not turn arbitrary Go code into contained code. Registered
functions may be called concurrently by different invocations.

The CLI registers `http.get`. Embedders must register it explicitly if wanted:

```go
client, err := httpcap.New(httpcap.Options{})
if err != nil { return err }
defer client.Close()
runtime, err := lua54.NewNative(lua54.Options{
    Functions: map[string]scribe.Function{"http.get": client.Function},
})
```

`sirius.call("http.get", "/path?query=value")` issues a GET to the task's known TCP
endpoint. TLS is selected by `Target.TLS`; a fixed IP preserves logical Host and
TLS server name. It returns `{status, headers, body}`. Header names are lowercase
and values are arrays of strings. Non-2xx responses remain observations.

Absolute URLs, alternate authorities, fragments, and redirects are not followed.
There is no ambient proxy, authentication, cookie jar, or automatic compression.
The capability defaults to a 10-second request timeout, 1 MiB body limit, and
64 KiB response-header limit. The CLI sets the HTTP timeout to the per-script
timeout. Oversized responses return errors rather than truncated successes.
Connections are reused only within the same logical authority, fixed connection
IP and TLS identity. Each client retains at most 64 endpoint pools, two idle
connections and 32 total connections per pool, with finite idle expiry. `Close`
releases idle resources and prevents new calls; `DisableReuse` forces fresh
connections. See [throughput controls](engine-throughput.md#connection-reuse).

## Output and findings

An action returns `data`, `findings`, or both. Unknown top-level output fields
produce an error. `data` is structured observation data. Each finding has:

```lua
{
  id = "check-specific-id",
  title = "Concrete observed issue",
  severity = "low",
  evidence = "The observed condition supporting this finding",
  references = { "https://example.test/advisory" },
  metadata = { affected_component = "example" }
}
```

ID, title, and severity are required. Valid severities are `info`, `low`, `medium`,
`high`, `critical`, and `unknown`. Evidence, references, and metadata are optional.
Finding IDs must be unique within one output. At most 256 findings are accepted.
References, when present, are limited to 64 strings per finding.
Scripts choose a severity from evidence; the engine does not create a score or
infer a vulnerability from textual keywords.

Conversion is bounded to 1 MiB, 10,000 value nodes, and depth 32; serialized output
also has a 1 MiB bound. An error clears the output and is reported independently
of findings. A completed action with no findings means only that it completed.

## Runtime environment and budgets

The profile includes selected base functions and the `string`, `table`, `math`,
and `utf8` libraries. It omits host I/O, shell, package search paths, arbitrary
loading, debug APIs, coroutine APIs, garbage-collection control, and metatable
mutation. Standard output is not available to scripts. The custom `require`
returns allowlisted modules only. This is deliberately narrower than full Lua.
`math.random`, `math.randomseed`, and `string.dump` are also omitted; the upstream
random functions mutate process-global state rather than per-job state.

The default limits are 10,000,000 VM CPU accounting units, 32 MiB VM memory
accounting, and 5 seconds per invocation. Zero option fields choose finite defaults.
Go I/O uses the invocation context. CPU-only code is stopped by finite VM quotas;
the implementation does not mutate a running VM from a cancellation goroutine.
These are accounting and bounded-work controls, not a process RSS ceiling or a
hard security boundary against hostile code.

See [http-header.lua](../examples/scripts/http-header.lua) for an original,
explicitly labeled demonstration and [the Go example](../examples/embed/main.go)
for an additional compiled-in function.

### Explicit Sirius verdicts

A Sirius action may return `{verdict="vulnerable", data=...}`,
`{verdict="not_vulnerable", data=...}`, or `{verdict="unknown"}`.
Omitting verdict means unknown, including empty output. Findings do not infer a
verdict. A not_vulnerable verdict with findings is rejected as contradictory.
Invalid verdicts fail execution.

JSONL results always include a top-level verdict. Stable execution statuses are
completed (action returned successfully), skipped (rule did not match), and
error (execution failed, including unsupported APIs). Errors, skips, and NSE
output always have unknown verdicts. Completed alone does not establish health.

### Raw TCP and TLS

The CLI registers `sirius.call("tcp.exchange", payload)`. Embedders register
`tcpcap.Function` in their native runtime's Functions map under that name.
Omit payload to grab a banner. Each call connects, sends the optional string,
receives one chunk, and closes. Results contain data and eof; data is at most
64 KiB and may be a partial protocol message. Scripts must not treat one chunk
as a complete response without protocol validation. Payloads are also limited
to 64 KiB. Calls have a five-second deadline shortened by the invocation context.

Only the caller-supplied explicit TCP endpoint is accessible; IP overrides the
connection address while Host remains the TLS server name. Target TLS enables
a verified handshake (system trust, TLS 1.2 minimum). The tls result contains
version, cipher_suite, subject, issuer, not_before and not_after for the leaf
certificate. Verification failures are errors. There is no insecure TLS mode,
persistent socket handle, or NSE socket emulation.


HTTP callers may supply inline source with `scripts`. Each entry requires a
nonempty `id` and `source`; `--script` is optional when inline scripts are
present. File and inline scripts may be combined (64 total). The existing
128 KiB JSON body cap applies, including JSON escaping; each source also obeys
the same source size limit as files. Inline scripts use the selected dialect,
arguments, validation, digest calculation, and JSONL result contract.
Invalid Lua produces a structured execution error. Require a complete response
and inspect execution status and explicit verdict; HTTP 200 is insufficient.

```sh
curl --fail-with-body http://192.168.123.22:18081/run \
  -H 'Content-Type: application/json' \
  --data '{"args":["--dialect","sirius","--host","example.internal"],"scripts":[{"id":"check.lua","source":"return {api_version=1,action=function() return {verdict=\"unknown\"} end}"}]}'
```

### Supplied endpoint facts

SDK callers set Target.Product and Target.Version alongside Host, IP, Port,
Protocol, State, Service and TLS. Sirius rule(target,args) and action(target,args)
receive the same flat endpoint table, including product and version strings;
missing strings remain empty. No service probing is implied.

CLI: --facts endpoints.json replaces --host/--port with a JSON array of 1–1024
Target objects (maximum 1 MiB). Each selected script runs against each endpoint.
HTTP POST /run accepts the same array as facts (within the 128 KiB request limit).
For example: {"args":["--dialect","sirius","--script","/path/check.lua"],
"facts":[{"host":"localhost","port":80,"protocol":"tcp","state":"open",
"service":"http","product":"example","version":"1.0"}]}.
Facts are caller assertions, not independently verified observations.

### Scanner report envelope v1

The exported report.Map(Result) returns
{schema_version:1,source:{name:"scribe",config:{script_id,script_sha256,dialect}},
assessment,verdict,evidence:Result}. Evidence retains the complete execution
record including raw output, findings, diagnostics, target and elapsed time.
Only completed Sirius explicit verdicts become vulnerable or not_vulnerable
assessments; all other outcomes remain inconclusive with unknown verdict.
NSE output text is never interpreted as a verdict. This standalone envelope
deliberately avoids the database-heavy go-api dependency; the scanner shim can
place evidence in report metadata and populate source name/config.

Engine.Run and CLI/HTTP batches emit one terminal record per task, including
queued tasks on cancellation (status cancelled). A failing result callback
prevents further delivery; transport loss therefore requires the caller to mark
missing records inconclusive. Record order is completion order. Cancellation is
request-wide; independently cancellable jobs should use separate Run contexts.

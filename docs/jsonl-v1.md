# JSONL schema v1

CLI execution and POST /run share one encoder and SDK path. Default output is
one Result per accepted module/endpoint pair. Each line is a complete JSON object
with schema_version: 1. Result fields are defined by the public Go Result,
Target and Output types. status and verdict are independent: only completed
explicit vulnerable/not_vulnerable verdicts establish an assessment. Errors,
skips, unknowns and missing records are inconclusive. elapsed_ms measures module
execution including planning, excluding scheduler queue time.

Opt in with --events (HTTP: include it in args) to receive the SDK Event schema:
schema_version (integer 1), type (planning, timing, verdict), result (the complete
Result object). Each terminal record generates those three events in order;
different modules arrive in completion order. Planning observations are emitted
retrospectively at terminal delivery and include output.skip_reason. Timing and
verdict observations retain the same evidence. This avoids duplicate policy or
assessment logic between SDK and transports.

OnEvent in Options receives these same records serially within a run. It may
return an error to stop delivery; callbacks shared by concurrent runs must
synchronize their own state. Callbacks must return promptly. No callback operates
on a Lua state. Events do not include separate Lua compilation/action timings.

HTTP flushes each JSONL write. HTTP 200 is not completion evidence. Require a
complete stream and expected terminal module records; transport loss is
inconclusive. Existing size, concurrency and timeout limits apply.

Consumers must tolerate additional object fields. Incompatible field or semantic
changes require a new schema version independent of the module release.
testdata/events-v1.golden.json pins representative skipped event output.

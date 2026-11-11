# v1 exported-field audit

Reviewed against implementation and behavioral fixtures on apps01, 2026-11-11.
Field contracts live beside declarations so there is one maintained reference.
Strings and counts have no implicit measurement unit; duration fields use Go
nanoseconds, byte ceilings use bytes, ports are unsigned transport port numbers,
and confidence is dimensionless in [0,1]. Nil evidence collections supply no
observations. They never establish a negative vulnerability assessment.

| Surface | Reviewed contract and behavioral evidence |
| --- | --- |
| Target, Script, Task | Required endpoint/source validation, explicit dialect, optional identity, exact grants; exported_zero_test.go, engine and job tests |
| Limits, CapabilityDeniedError | Finite Lua defaults, tightening only, typed exact-name denial; runtime/lua54/audit_test.go and grant/limit tests |
| Finding, Verdict, Status, Output, Result | Explicit evidence versus execution; empty enum values are uninitialized, no clean inference; runtime conversion and summary/report tests |
| Summary | Counts records, conservative verdicts, nil initialization; summary tests |
| Match | AND fields, OR alternatives, inclusive versions, advisory ports, bounded nesting; exported_zero_test.go and planner tests |
| Options, Plan | Plan is Options.Plan, not a type; zero defaults, bounded scheduling, opt-in identification; options/default tests and planner transport fixtures |
| Module, Index | Detached metadata, nil match warnings, constructor requirement; selection tests |
| Event, VersionInfo | Versioned observations, callback errors, module provenance and unavailable metadata; observability/version tests |
| adapter/pingpp | Wire schema, endpoint states, confirmed noncontradictory identity, bounded reader; adapter fixtures |
| capability/httpcap | Constructor-only client, ten-second/1 MiB defaults, bounded endpoint requests; HTTP capability tests |
| capability/tcpcap | No exported fields; five-second/64 KiB exchange, TLS validation, EOF semantics; TCP fixtures |
| capability/localcap | No exported fields; rooted regular files, byte/entry ceilings, unsupported-platform errors; local capability fixtures and cross-compilation |
| compat | Pinned cases, required assertions, counts and empty report behavior; manifest/report tests |
| fingerprint | Optional identity only, nil patterns skipped, empty matcher unknown; pinned banner/header fixtures |
| job, report | Schema 1, absent grants deny all, source resolution, conservative native assessments; job/report tests |
| runtime/lua54 | Limits alias, isolated invocation ownership, exact functions, finite cache defaults and disable behavior; runtime audit and execution tests |

The exported declaration golden was reviewed for compatibility: changes are
formatting and splitting the grouped Facts fields into individual documented
fields. Names, field order, types, tags and callable signatures are unchanged.
No runtime behavior or default was changed by this documentation audit.

`make check` covers race tests, external SDK examples, vet, CGO-disabled build
and Windows/Darwin CLI cross-compilation. This is local execution and build
evidence, not scanner/agent or full vGPT workflow acceptance. The original Sirius
corpus is first-party evidence, not upstream NSE compatibility. Phase 3 stays
paused.

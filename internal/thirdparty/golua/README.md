# Internal GoLua 5.4 subset

Origin: arnodel/golua v0.1.2, commit
`ebe9f094210ac365f1cd4043e8aa6b99e2135a69`. This is modified third-party
Apache-2.0 code, not MIT first-party implementation. See `LICENSE`,
`UPSTREAM.json`, and `../../../third_party/golua-PATCHES.md`.

Only the 20 packages in the interpreter dependency closure used by Scribe are
included. Imports use the enclosing Scribe module's internal path; there is no
nested module and no replace directive. The upstream executable, unused standard
libraries, REPL dependencies, and full-library Lua test harness are excluded.

Retained package tests and fixture data remain upstream source. Seven
`lua_test.go` drivers that import the excluded full library/harness are omitted;
their associated Lua fixtures remain for provenance. This subset does not claim
to run the complete upstream Lua suite. Scribe's runtime, CLI, and protocol suites
exercise the embedded configuration.

Sirius modifications are limited to internal import paths, supported Go hashing,
and hash/equality regressions, as itemized in the patch manifest.

# GoLua 5.4 internal fork changes

## Origin and license

- Upstream: https://github.com/arnodel/golua
- Tag: `v0.1.2`
- Exact commit: `ebe9f094210ac365f1cd4043e8aa6b99e2135a69`
- License: Apache-2.0, retained at
  [`internal/thirdparty/golua/LICENSE`](../internal/thirdparty/golua/LICENSE).
- All original file notices are preserved. New fork regression tests use
  Apache-2.0 as stated in their source header. This fork remains third-party code
  under its upstream license.

[`UPSTREAM.json`](../internal/thirdparty/golua/UPSTREAM.json) lists selected
packages, omitted test drivers, and SHA-256 of every retained upstream file before
import rewriting and code patches.

## Why this is in the tree

The Lua 5.4 upstream tag uses `//go:linkname` for private Go runtime hashing
symbols. Its scalar `runtime.memhash64` reference fails to link on the inspected
Go 1.27 toolchain. A consuming Go module cannot inherit Scribe's replace
directives, so this copy uses Scribe-internal imports within the one enclosing
module. It requires Go 1.24 or newer for the public hashing API and preserves the
selected Lua 5.4 language baseline. Upgrading the original dependency to current
Lua 5.5 releases would change that baseline.

## Selection

The package list was obtained before import rewriting with:

```sh
GOTOOLCHAIN=go1.24.1 go list -deps ./runtime/lua54
```

Only the 20 upstream packages in that dependency closure, their package files,
compatible Go unit tests, and non-Go fixture directories are copied. Root CLI,
REPL, unused libraries, upstream module files, and their dependencies are absent.
Seven `lua_test.go` drivers are omitted because they import the excluded full
`lib` and `luatesting` packages. Their Lua fixture data is preserved. The fork
does not claim to run the entire upstream Lua test suite.

## Code changes

1. All internal upstream import prefixes are rewritten from
   `github.com/arnodel/golua/` to
   `github.com/SiriusScan/scribe/internal/thirdparty/golua/`.
2. `runtime/hash.go` replaces private `memhash64`, `nilinterhash`, and `noescape`
   references and unsafe bridge code with public `hash/maphash.Comparable`. One
   process-wide `maphash.MakeSeed()` remains fixed across all table insertions and
   lookups. Hash values are implementation details, not persistent identifiers.
   Existing helper signatures are retained; all existing call sites pass zero for
   their historical seed argument.
3. `runtime/value.go` normalizes positive and negative floating zero before
   hashing, because `Value.Equals` considers them equal. It also hashes Lua
   closures by their shared code pointer: `Closure.Equals` can consider distinct
   closure objects equal when code and upvalue cells match. Hashing only code may
   increase collisions between unequal closures but preserves equal-value hashes
   without inspecting mutable upvalues.
4. `runtime/hash_scribe_test.go` adds regressions for scalar and comparable
   interface hashing, float zero and equal-closure hashing, and actual Lua table
   growth/lookups with integer, float, Boolean, short/long string, table, and
   function keys.

No parser, compiler, scheduler, quota implementation, or library behavior is
otherwise changed. Upstream still uses unsafe representations elsewhere; removing
private hashing symbol dependencies is not a claim that the entire interpreter
avoids unsafe code.

## Validation scope

The retained package tests and fork regression tests must run with the module's
minimum Go 1.24 toolchain and the current toolchain. Run Scribe's runtime and CLI
suites after updating their imports; cross-compile supported deployment targets.
The retained package tests do not establish Nmap NSE corpus compatibility or
installed Sirius acceptance.

```sh
go test -race ./internal/thirdparty/golua/...
GOTOOLCHAIN=go1.24.1 go test ./internal/thirdparty/golua/runtime -run '^TestScribe'
```

## Immutable VM code templates

`runtime/scribe_cache.go` adds `Runtime.BindCode`, which creates a fresh closure
and environment cell around an immutable VM `Code` graph. Scribe caches only
compiler-produced constants/code, never closures, tables, grants or invocation
state. The caller charges retained code memory before binding. Every invocation
still owns a new runtime, globals, module tables and upvalues. The upstream
version and Lua 5.4 baseline are unchanged. This fork extension follows the
upstream Apache-2.0 license.

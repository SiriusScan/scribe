# Third-party notices

Sirius Scribe's first-party code is MIT. The following dependencies retain their
own licenses; distributing a binary must retain the applicable notices.

- **GoLua v0.1.2 source subset** — Apache-2.0; copyright Arnaud Delobelle and
  contributors. [Upstream](https://github.com/arnodel/golua/tree/v0.1.2),
  [license copy](third_party/golua-LICENSE.txt),
  [local patch manifest](third_party/golua-PATCHES.md).

The required Lua 5.4 source is bundled under `internal/thirdparty/golua`, with
rewritten local imports and a portable hashing patch. Upstream v0.1.2 uses private
Go runtime symbols that fail to link on Go 1.27; bundling this declared subset
preserves Lua 5.4 without requiring consumer linker overrides or ignored module
replacement directives. The included source retains Apache-2.0. See the manifest
for exact provenance, copied scope, and changes. Check the actual build graph again
when adding libraries or changing versions.

This repository includes no Nmap implementation, Nmap script corpus, or Nmap Lua
libraries. Its `.nse` example is original MIT-licensed source. NSE compatibility
work does not change the licenses of scripts supplied by users or of any future
separate corpus distribution.

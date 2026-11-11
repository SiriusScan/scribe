# vGPT regression corpus

Unmodified generated Sirius-dialect scripts from `/home/agi/Projects/vgpt/nse/samples`. Identical bytes are stored once. These Apache CVE-2021-41773 fixtures detect version banners; they do not prove traversal exploitability. The pre-verdict run b75ae69731b3 and unrelated nginx-only run e53393c36bd4 are excluded.

Tests live in `cmd/scribe/vgpt_test.go` and cover CLI plus inline POST /run, check before execution, and explicit verdicts. Local responses model the recorded Apache Server banners and HTTP status; build/test evidence is separate from live scanner or Activepieces acceptance.

- `16e0d4fdf21e.lua`: source runs 16e0d4fdf21e.
- `181803048392.lua`: source runs 181803048392.
- `47e67da9cbb4.lua`: source runs 47e67da9cbb4.
- `65b0ae4ab214.lua`: source runs 65b0ae4ab214.
- `6bcfa6dbd35d.lua`: source runs 6bcfa6dbd35d.
- `91c06faf26c9.lua`: source runs 91c06faf26c9.
- `cb74418455e2.lua`: source runs cb74418455e2.
- `edf150c7e6b7.lua`: source runs edf150c7e6b7.

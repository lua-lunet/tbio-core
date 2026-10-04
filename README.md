# tbio-core

The durable-IO strip: the **AOF** (append-only write-behind log) and the **lifecycle marker
store** over the superblock quorum-of-copies construction, vendored from
[TigerBeetle](https://github.com/tigerbeetle/tigerbeetle) release tag **0.17.9** as a stripped Zig
source tree (`zig/`), compiled with upstream's pinned Zig 0.14.1 to a C-ABI cdylib, behind a safe
Rust wrapper.

System
description, the C ABI, the optional force knob, the retention policy, and the standby learner
wiring live in [`AOF.md`](AOF.md); the upstream file map and every strip is recorded in
[`VENDORED.md`](VENDORED.md).

**What this crate is not.** It carries no WAL and no grid. Upstream's consensus WAL — two
contiguous circular buffers, `Zone.wal_headers` for redundant headers and `Zone.wal_prepares` for
the messages — and the async direct-IO backends that serve it are deliberately not vendored (see
the strip list in `VENDORED.md`). The AOF is upstream's write-behind log of committed prepares,
written with plain blocking page-cached IO — upstream's own comment: "This is written *without*
O_DIRECT" — and upstream's own file doc states it "borrows durability from the WAL precisely
because its writes are page-cached blocking calls". Files written here parse with upstream's
`aof debug` / `aof merge`, and the vendored iterator reads any file upstream wrote; the name
should not be read as a promise of WAL-grade semantics.

## What the C ABI exposes

Two families over the vendored code (`zig/src/aof_c.zig`):

- **The AOF family** — `lunet_aof_open` (with the optional `force_flush` knob),
  `lunet_aof_append`, `lunet_aof_flush`, `lunet_aof_close`, and the reader
  `lunet_aof_iter_open` / `lunet_aof_iter_next` / `lunet_aof_iter_close`. Each entry is a fixed
  u128 magic plus the full Prepare message, Aegis-checksummed per entry and chained across
  entries (`parent` → previous checksum), with the chain validated on read.
- **The lifecycle-marker family** — `lunet_aof_marker_geometry`, `lunet_aof_marker_write`,
  `lunet_aof_marker_classify`, `lunet_aof_marker_inspect`, `lunet_aof_marker_format`,
  `lunet_aof_marker_state_string_offset`. The marker store over the vendored superblock
  construction: `constants.superblock_copies` (4) sector-aligned copies of a `SuperBlockHeader` in
  fixed zones of one marker file, each Aegis-checksummed and hash-chained `sequence`/`parent` (a
  torn, misdirected or rotted copy is detectable rather than trusted), quorum writes verified at
  the `.verify` threshold (3/4) and quorum reads from the `.open` threshold (2/4) resolving by
  highest sequence, carrying the uVRR identity pair `{systemIdentifier, crashCounter}` (one-indexed;
  the pair-aware write guard refuses a cross-system overwrite and a regressing crash counter — the
  identity law, `docs/uvrr-io-obligations.md` in uvrr-core, the termination chapter §4, after
  Lampson & Sturgis 1979 §5.1, "the good, the complete, or the newest").

The Rust wrapper adds, above the C ABI and not exported through it: the safe `AofFile` surface
with the optional force knob, the typed envelope record layer over the raw append, and the
`{unixepoch}.aof` retention planner.

## Systems it serves

- **The uVRR contract.** The marker implements the termination chapter's lifecycle marker (the §4
  "quorum of copies" construction) from [uvrr-core](https://github.com/lua-lunet/uvrr-core)
  ([docs/uvrr-io-obligations.md](https://github.com/lua-lunet/uvrr-core/blob/main/docs/uvrr-io-obligations.md)).
- **[lua-lunet/lunet-locks](https://github.com/lua-lunet/lunet-locks)**, two consumers with
  different halves:
  - `ext/advisory_lock` takes **only the marker store** (`tbio::marker`) for its
    lifecycle and identity writes: the graceful-stop path drains its own event series, then writes
    the `stopped` and `flushed` marker rounds through this store, so a marker that says flushed
    vouches for the drained bytes under it. The `LKE1` record series in that crate's `aof.rs` and
    `journal.rs` is its own code — the TigerBeetle AOF *pattern*, not this crate's AOF.
  - `examples/lease-sequencer` takes **the AOF** as its flight recorder: the envelope records of
    the node's raw uVRR wire messages are appended through the vendored AOF and replayed by the
    bridge to serve the console UI (`/locks`, `/events`, `/metrics`, `/telemetry/log`).

## Layout

| Path | Contents |
|---|---|
| `zig/src/` | The vendored strip (`aof.zig`, `marker.zig`, the vendored `vsr/superblock*.zig`, and the minimal dependency closure; see VENDORED.md) |
| `zig/src/aof_c.zig` | The C ABI surface over the vendored strip (crate-owned) |
| `zig/build.zig` | cdylib + static library + test steps, the `vsr_options` module, the fine-grain log gate |
| `src/lib.rs` | Safe wrapper: `AofFile` open/append/flush/close with the optional force knob |
| `src/marker.rs` | The lifecycle marker surface over the vendored superblock copies |
| `src/envelope.rs` | The typed telemetry record layer over the raw AOF append |
| `src/retention.rs` | The `{unixepoch}.aof` retention planner (pure, unit-tested) |
| `src/ffi.rs` | The raw FFI bindings over the cdylib |
| `tests/` | Retention TDD + the FFI append/read round-trip smoke |
| `LICENSE-TigerBeetle` | Upstream Apache-2.0 licence text, verbatim |

## Build and test

```console
cargo test --manifest-path ext/lunet-locks-aof/Cargo.toml
```

`build.rs` compiles the Zig cdylib with the repo's mise-pinned Zig
0.14.1 (`TBIO_ZIG` → `mise which zig` → PATH) and links the
wrapper against it. The Zig side has its own suite:

```console
make -C ext/lunet-locks-aof/zig -f /dev/null 2>/dev/null; mise exec -- zig build test
```

run from `ext/lunet-locks-aof/zig/` — 14 tests including upstream's own
`aof write / read` test against the vendored code.

## Attribution and licence

The TigerBeetle name and copyright remain those of the
[TigerBeetle project](https://github.com/tigerbeetle/tigerbeetle). This
software makes no claim to be in any way related to the TigerBeetle DB
project. The naming of that origin is intended to give credit and is in no
way to be seen as an endorsement of this code, which is customised.

The vendored sources are from tigerbeetle/tigerbeetle release tag 0.17.9,
upstream licence **Apache-2.0** (`LICENSE-TigerBeetle`, verbatim). This
repository is likewise **Apache-2.0** (`LICENSE`). Apache-2.0 is
permissive: the vendored files remain Apache-2.0 with attribution and
licence notice preserved, and the combined work carries no copyleft
obligation from them. This corrects the item spec's AGPL-3.0 premise —
the pinned release is not AGPL-3.0; the full licence discussion is in
[`AOF.md`](AOF.md).

Thanks to the TigerBeetle team and contributors for the durable AOF and VSR
implementation on which this adapter is built.
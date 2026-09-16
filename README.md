# lunet-locks-aof — the vendored TigerBeetle AOF

The TigerBeetle AOF (append-only write-behind log) vendored from release
tag **0.17.9** as a stripped Zig source tree (`zig/`) compiled to a C-ABI
cdylib, behind this safe Rust wrapper. System description, the C ABI, the
optional force knob, the retention policy, and the standby learner wiring
live in [`AOF.md`](AOF.md); the upstream file map and every strip is
recorded in [`VENDORED.md`](VENDORED.md).

## Layout

| Path | Contents |
|---|---|
| `zig/src/` | The vendored TigerBeetle AOF strip (`aof.zig` + its minimal dependency closure; see VENDORED.md) |
| `zig/src/aof_c.zig` | The C ABI surface over the vendored AOF (crate-owned) |
| `zig/build.zig` | cdylib + test steps, the `vsr_options` module |
| `src/lib.rs` | Safe wrapper: `AofFile` open/append/flush/close with the optional force knob |
| `src/retention.rs` | The `{unixepoch}.aof` retention planner (pure, unit-tested) |
| `src/ffi.rs` | The raw FFI bindings over the cdylib |
| `tests/` | Retention TDD + the FFI append/read round-trip smoke |
| `LICENSE-TigerBeetle` | Upstream Apache-2.0 licence text, verbatim |

## Build and test

```console
cargo test --manifest-path ext/lunet-locks-aof/Cargo.toml
```

`build.rs` compiles the Zig cdylib with the repo's mise-pinned Zig
0.14.1 (`LUNET_LOCKS_AOF_ZIG` → `mise which zig` → PATH) and links the
wrapper against it. The Zig side has its own suite:

```console
make -C ext/lunet-locks-aof/zig -f /dev/null 2>/dev/null; mise exec -- zig build test
```

run from `ext/lunet-locks-aof/zig/` — 14 tests including upstream's own
`aof write / read` test against the vendored code.

## Attribution and licence

The vendored sources are from
[tigerbeetle/tigerbeetle](https://github.com/tigerbeetle/tigerbeetle)
release tag 0.17.9, upstream licence **Apache-2.0**
(`LICENSE-TigerBeetle`). Apache-2.0 is permissive: the vendored files
remain Apache-2.0 with attribution and licence notice preserved, and the
combined work (this repository, MIT) carries no copyleft obligation from
them. Note: this corrects the item spec's AGPL-3.0 premise — the pinned
release is not AGPL-3.0; the full licence discussion is in
[`AOF.md`](AOF.md).

Thanks to the TigerBeetle team and contributors for the durable AOF and VSR
implementation on which this adapter is built.

# VENDORED — the TigerBeetle AOF strip

Upstream: [tigerbeetle/tigerbeetle](https://github.com/tigerbeetle/tigerbeetle),
release tag **0.17.9** (published 2026-07-06), vendored from the pinned ref
`https://raw.githubusercontent.com/tigerbeetle/tigerbeetle/0.17.9/...`.
Toolchain: Zig **0.14.1** — upstream's own pinned version (upstream
`zig/download.sh` pins 0.14.1 for this release); wired through this repo's
mise setup (`mise.toml: zig = "0.14.1"`), resolved by the wrapper's
`build.rs` (`mise which zig` → `LUNET_LOCKS_AOF_ZIG` override → PATH).

The current stripped source identity is reproducible with
`tools/source_hash.sh`: it hashes the sorted `(path, file SHA-256)` list
under `zig/src`. The resulting hash is recorded here whenever the vendored
source changes. This supplements, and does not replace, the upstream release
tag and the eventual fork commit/tag that will own this adapted source tree.

Current source SHA-256:
`ba8e881fe3342d773eed10aefbc4a81462e97e95c8329d60d7e9026907d507ba`.

Licence: **Apache-2.0** (`LICENSE-TigerBeetle`, copied from the pinned
ref). See `README.md` and `AOF.md` for the licence facts and the one
correction to the spec's AGPL premise.

## The strip principle

Vendor ONLY the AOF code path and its minimal dependencies; strip
everything else. Upstream's AOF is a hash-chained append-only log of
committed prepares: one entry = fixed u128 magic
(`0xbcd8d3fee406119ed192c4f4c4fc82`) + the full Prepare message
(`Header.Prepare`, 256 bytes, Aegis-checksummed), written with plain
blocking page-cached IO — upstream's own comment: "This is written
_without_ O_DIRECT". The chain is validated on read per entry
(header/body checksums) and across entries (`parent` → previous
checksum). That format and its write/read machinery is what ships here,
byte-identical: files written by this build parse with upstream's
`aof debug` / `aof merge` and vice versa.

## Vendored file map (upstream path → vendored path → strip)

| Upstream (0.17.9) | Vendored | Strip |
|---|---|---|
| `src/aof.zig` | `zig/src/aof.zig` | Keep `AOFEntry`, `AOFType(IO)` (init/close/write/sync/checkpoint/on_fsync/validate/Iterator), the `aof write / read` test. The offline CLI (`main`, `CLIArgs`, `aof recover/debug/merge`), the `merge` function it drives and `ReplayClient` are not vendored — the recovery tooling rides the whole client/message-bus stack and is not the AOF write path. |
| `src/vsr.zig` | `zig/src/vsr.zig` | Stripped root module: keep `Version`, `Command`, `Operation`, `Peer`, `BlockReference`, `Checkpoint`, `RegisterRequest/Result`, `BlockRequest`, `UpgradeRequest`, `ReconfigurationRequest/Result` + member helpers, and re-exports (Header, checksum, Release, MessagePool, tigerbeetle, CheckpointState). Drop every replica/client/message-bus/grid/storage/sync/testing re-export — none is referenced by the AOF path. Re-added verbatim from upstream for the marker surface's closure: `member_index`, `Zone` (the vendored superblock's `data_file_size_min` computes the grid padding through it), and `ClientSessions.encode_size` (the superblock's consistency asserts compare against it). |
| `src/vsr/message_header.zig` | `zig/src/vsr/message_header.zig` | Verbatim. |
| `src/vsr/checksum.zig` | `zig/src/vsr/checksum.zig` | Verbatim (Aegis-based checksums — the on-disk contract). |
| `src/vsr/superblock.zig` | `zig/src/vsr/superblock.zig` | Verbatim except: the two `Storage == testing/storage` conditional blocks inside the (lazy) SuperBlock state machine are removed — the vendored build carries no testing corpus. Only `SuperBlockHeader`/`CheckpointState` (the on-wire layout constants and `view_headers_max` sizing assert) are in the compiled closure. |
| `src/vsr/superblock_quorums.zig` | `zig/src/vsr/superblock_quorums.zig` | Verbatim except: the module-level `log` binding is gated behind the fine-logs build option (the per-copy and per-quorum checksum lines are finest-grain trace, quiet unless `-Dfine-logs` asks; see the file's gate comment and the enforcing census test in `zig/src/aof_c.zig`). |
| `src/constants.zig` | `zig/src/constants.zig` | Verbatim. |
| `src/config.zig` | `zig/src/config.zig` | Verbatim (build-time `vsr_options` provided by this crate's `build.zig`, same fields upstream's `build_vsr_module` sets; values = upstream defaults). |
| `src/multiversion.zig` | `zig/src/multiversion.zig` | Stripped to the identity types `Release`/`ReleaseTriple` (+ the `ReleaseTriple.parse` test). The `MultiversionOS` re-exec machinery is not vendored — the `Multiversion` vtable, `ReleaseList`, `section_to_macho_cpu`, `MultiversionHeader`, the bundled-binary header/body parsers (`parse_elf`/`parse_macho`/`parse_pe`), and the process-replacement plumbing (`self_exe_path`, `random_wstr`, `wait_for_parent_to_exit`, `execveat`, `open_memory_file`) all exist to re-execute the replica binary at another release, and no AOF code path names any of them. |
| `src/message_pool.zig` | `zig/src/message_pool.zig` | Verbatim (the message the C-ABI append path builds). |
| `src/stack.zig` | `zig/src/stack.zig` | Verbatim (the pool's freelist). |
| `src/tigerbeetle.zig` | `zig/src/tigerbeetle.zig` | Verbatim (`Operation`, the Account/Transfer schema — referenced by config.zig's cache-size defaults). |
| `src/lsm/schema.zig` | `zig/src/lsm/schema.zig` | Verbatim (`BlockType` for `Header.Block`; lazy beyond that). |
| `src/io/common.zig` | `zig/src/io/common.zig` | Stripped to the `aof_blocking_*` functions, verbatim (plain blocking `std.fs` calls — the AOF's actual IO). Upstream's TCP socket helpers, `listen`, `tcp_options`, and the `Stats`/`Tracer` plumbing are not part of the AOF path. |
| `src/io.zig` | `zig/src/io.zig` | **New glue, not upstream**: the blocking IO backend exposing exactly the surface `AOFType(IO)` consumes (`aof_blocking_*` delegating to the vendored `io/common.zig`, `open_dir` and `aof_blocking_open` mirroring upstream darwin.zig's composition, `fsync` as a blocking `posix.fsync` delivered through the same completion-callback shape). Upstream's async backends (io_uring/kevent/IOCP) are the WAL/grid machinery, not the AOF's blocking path — the AOF's file doc states it borrows durability from the WAL precisely because its writes are page-cached blocking calls. |
| `src/stdx/*` | `zig/src/stdx/*` | `stdx.zig` verbatim except the trailing `comptime { _ = @import(...) }` test-index block and the `testing/low_level_hash_vectors.zig`-referencing test are dropped (the upstream stdx test corpus needs snapshot fixtures outside the AOF path); every referenced submodule vendored verbatim: `vendored/aegis.zig`, `time_units.zig`, `prng.zig`, `bit_set.zig`, `net.zig`, `flags.zig`, `debug.zig`, `radix.zig`, `unshare.zig`, `huge_page_allocator.zig`, `mlock.zig`, `shell.zig`, `zipfian.zig`, `windows.zig`, `iops.zig`, `bounded_array.zig`, `ring_buffer.zig`, `sort_test.zig`, `testing/snaptest.zig`, `testing/low_level_hash_vectors.zig`. |
| `LICENSE` | `LICENSE-TigerBeetle` | Verbatim (Apache-2.0). |

Deliberately NOT vendored (the dependency web the strip cuts):

- `src/vsr/replica.zig`, `src/vsr/journal.zig`, `src/vsr/client.zig`,
  `src/vsr/sync.zig` — the VSR protocol state machine and client;
- `src/message_bus.zig`, `src/message_buffer.zig`, `src/queue.zig`,
  `src/time.zig`, `src/trace.zig` (+ `statsd`/`event`) — the event-loop
  transport stack the AOF never touches;
- `src/io/linux.zig`, `src/io/darwin.zig`, `src/io/windows.zig` — the
  async direct-IO backends (the WAL/grid path; see `zig/src/io.zig` above);
- `src/state_machine.zig`, `src/lsm/*` (beyond `schema.zig`),
  `src/storage.zig`, `src/clients/*`, the testing corpus.

## New (crate-owned) files — not upstream code

- `zig/src/aof_c.zig` — the C ABI surface (open/append/flush/close +
  read-back iterator) over the vendored `AOFType`, with the
  header-builder (chain, op, timestamp, Aegis checksums) and the
  optional-force knob wiring.
- `zig/src/marker.zig` — the lifecycle marker store (the uVRR termination
  obligations' §4 marker): four fixed sector-aligned copies of a
  `SuperBlockHeader` in one marker file, hash-chained sequence/parent,
  quorum write with forced I/O verified at the `.verify` threshold, and
  the boot classification resolved through the vendored
  `superblock_quorums.zig` flexible quorums (highest sequence within the
  `.open` threshold). The marker's identity pair (the system identifier
  and the crash counter) is explicit in the header; `commit_max` stays
  zero and `sync_view` is the lifecycle state. All of it is inside the
  header checksum.
- `zig/build.zig` — the cdylib + static library + test steps, the
  `vsr_options` module, and the fine-grain log gate (`-Dfine-logs`): the
  `gate_options` module the module root's std.log level pin
  (`zig/src/aof_c.zig`) and the vendored quorum file's comptime gate
  consume.

## Provenance evidence

- `mise exec -- zig build test` runs the vendored suite plus the marker
  store's own fault-model tests (quorum write/read, a rotted or torn copy
  cannot decide the read, a stale copy cannot drag the classification
  back, a single advanced copy without a quorum cannot fake a clean
  stop, a forged fork fails closed), including upstream's own
  `aof write / read` test (kept verbatim) executing
  against the vendored code and this build's blocking IO backend.
- The Rust `tests/aof_test.rs::ffi_append_read_round_trips_through_the_cdylib`
  proves an append + read round-trip through the built cdylib, with the
  vendored checksum chain validating every entry on read-back
  (`ffi_read_rejects_a_corrupted_entry_checksum` pins that the chain is
  real: a flipped body byte fails the iterator with the checksum error).

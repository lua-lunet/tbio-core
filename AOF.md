# AOF.md — the vendored TigerBeetle AOF

This subcrate vendors TigerBeetle's **AOF** (append-only file, the
write-behind log) — the real upstream code path from the pinned release
**tigerbeetle/tigerbeetle 0.17.9** — as a stripped Zig source tree compiled
to a cdylib with a C ABI, behind a safe Rust wrapper. See `VENDORED.md`
for the exact file map and every strip; see `AOF.md`'s licence section at
the bottom for the licence facts.

## What the vendored thing is

Upstream's AOF is a hash-chained append-only log of committed prepares,
kept outside the consensus durability argument ("this is not a WAL"). One
entry is a fixed u128 magic (`0xbcd8d3fee406119ed192c4f4c4fc82`) plus the
full Prepare message (256-byte `Header.Prepare` + body), written with
plain blocking page-cached IO — deliberately, upstream's own comment:
"This is written _without_ O_DIRECT". Entries chain by checksum and every
read validates the header/body Aegis checksums and the chain. The on-disk
format here is byte-identical to upstream: files written by this build
parse with upstream's `aof debug` / `aof merge`, and the vendored
`Iterator` reads any file upstream wrote.

## The C ABI

The cdylib (`liblunet_locks_aof.{dylib,so}`, built by
`ext/lunet-locks-aof/zig/build.zig` with the repo's mise-pinned Zig
0.14.1) exports:

```text
int32  lunet_aof_open(path, path_len, force_flush: u8, out: *?*AofFile)
int32  lunet_aof_append(h, data, len, out_op: ?*u64)
int32  lunet_aof_flush(h)              // the explicit fsync (checkpoint path)
int32  lunet_aof_close(h)              // graceful: flush, then release
int32  lunet_aof_iter_open(path, path_len, out: *?*AofIter)
int32  lunet_aof_iter_next(it, out_data, cap, out_len: *usize, out_op: *u64)
void   lunet_aof_iter_close(it)
```

Result codes: `0` OK; `-1` INVALID (malformed path/flag), `-6` TOO_LARGE
(record above the message body capacity, 1 MiB − 256 B), `-7` SERVICE
(IO failure or checksum-corrupted read). The iterator returns `0` at end
of file (a torn final entry ends iteration cleanly).

`append` wraps the caller's record bytes as the body of a fresh Prepare
entry: the vendored Zig side stamps the chain (`parent` = the previous
entry's checksum), a monotonic op, the unix-millisecond timestamp, and
valid Aegis checksums — the exact on-disk shape an upstream `aof debug`
run parses. The surface is single-threaded by contract (the standby host
drives it from its UDP pump thread).

## The optional force (the spec's "forced flush made optional")

TigerBeetle's durability taxonomy has three write methods; the AOF is the
**async** one — nothing waits on its write completion, its deadline is
someone else's checkpoint. The "forced" behaviour (write-completion ==
durability, the WAL method) is therefore **optional and off by default**:

- **force OFF (default — the telemetry setting)**: appends are amortized
  page-cached writes; fsync happens on explicit
  `lunet_aof_flush`/`lunet_aof_close` and when the vendored unflushed-entry
  window reaches `journal_slot_count` (1024). Upstream asserts that window
  never exceeds the WAL capacity because upstream *borrows* durability
  from the WAL; this build has no WAL behind it, so the same bound closes
  itself with a flush at the cap — the unflushed window stays bounded,
  nothing forces per-record.
- **force ON** (the knob, `AofFile::open_with(Options { force_flush: true,
  .. })` / `lunet_aof_open(..., force_flush=1)`): every append is followed
  immediately by the fsync through the vendored checkpoint path — write
  completion equals durability, per record.

The buffer is never disabled: TB's AOF writes every entry through
`writeAll` into the OS page cache (upstream's mechanism, untouched), and
the vendored `AOF.write`/`AOF.checkpoint`/`Iterator` code is upstream
verbatim.

## Retention (the `{unixepoch}.aof` series)

On learner startup, in the AOF directory:

1. The wrapper applies the retention sweep over the pre-existing
   (full) `.aof` files: keep the active file (being created) and the
   newest full file; delete OLDER files oldest-first while the sum of all
   retained AOF sizes exceeds the threshold — never below one active +
   one older (min retention 2). Boundary: sum == threshold keeps
   everything; one byte over deletes the oldest file. More old files
   survive only while their sum stays under the threshold.
2. It then opens the NEW active file named `{unix_epoch_seconds}.aof`
   (same-second collisions pick `{epoch}-1.aof`, `-2.aof`, ... —
   create-new, never truncate).

Default threshold: **10 MiB** (`--aof-retention-mib N` on the
lease-sequencer standby). The planner is pure and unit-tested
(`tests/retention_test.rs`): epoch filename, threshold arithmetic, min-2
rule, delete-oldest-first order, threshold boundary, and the FS listing.
The sweep runs on every `AofFile::open*` and counts only `.aof` files —
the LKE1 `.bin` series sharing the directory (the console feed's series,
`docs/src/telemetry-aof.md`) is never touched.

## The standby learner wiring

`examples/lease-sequencer`: a node started with `--aof-dir PATH` is the
standby. It joins at voting weight 0 through the existing
reconfigure-join learner path (the §10 learner acquisition serves its
catch-up; the `reconfigure_abi_joins_a_learner_then_leaves_it_at_zero`
test pins the core path), and every Commit datagram it receives on the
peer channel — the leader's heartbeat/commit stream plus the commit
cascades — appends one entry to the active `{epoch}.aof` WITHOUT a forced
flush (the bytes recorded are the trailer-stripped wire message, exactly
what the core receives; `examples/lease-sequencer/src/main.rs`,
`handle_packet`, the `is_commit` branch). The force knob stays OFF for
this host: the entries ride the AOF's own amortized window, fsync'd when
the cap fills. An append failure disables the stream for the process and
logs once — telemetry never poisons the replication path.

A reconfiguration that changes the learner's role is logged by the host's
ordinary status/leader notes, not a correctness requirement — the AOF
carries no role state. The writes ride the same epoch/config era context
as the phi sketches: era transitions land in the stream as the Commits
that fold them.

## Toolchain

Zig is pinned at **0.14.1** in the repo's `mise.toml` (upstream's own pin
for the 0.17.9 release). `cargo build` of this crate invokes the Zig
build through `build.rs`: `LUNET_LOCKS_AOF_ZIG` override →
`mise which zig` → PATH `zig`. The cdylib's install name is
`@rpath/liblunet_locks_aof.dylib`; downstream binaries get the runtime
rpath via the `links = "lunet_locks_aof"` metadata contract (see the
lease-sequencer's `build.rs`).

## The honest framing

For telemetry tracking alone this is overkill. The AOF is built for full
disaster recovery of a database: a hash-chained, checksum-validated,
replayable copy of every committed operation, with `aof recover` able to
rebuild a cluster from it. This repo's telemetry needs none of that — the
console feed consumes the 61-byte `LKE1` series. The vendored AOF is
incubated here because the downstream uvrr-core applications will want
exactly this standby/DR shape: a zero-voting-weight learner streaming the
leader's commit/heartbeat records into a durable, chain-validated,
checksummed log — the lease-sequencer is the incubator, not the final
consumer.

## Attribution and licence

The vendored Zig sources are from
[tigerbeetle/tigerbeetle](https://github.com/tigerbeetle/tigerbeetle)
release tag 0.17.9, upstream's AOF implementation (written upstream by
the TigerBeetle team; see the file headers for the individual authors'
notes). Copyright and licence text are preserved in
`LICENSE-TigerBeetle` (Apache License 2.0).

**Licence fact, stated plainly (and one spec correction):** TigerBeetle
0.17.9's `LICENSE` is the Apache License 2.0 — it is *not* AGPL-3.0. The
item spec's premise ("NOTE that upstream is AGPL-3.0") does not match the
pinned release. The actual implication: Apache-2.0 imposes no copyleft on
the combined work — the vendored files remain Apache-2.0 (the
attribution and licence notice above is the only obligation), and this
repository's MIT licensing is unaffected. Had upstream been AGPL-3.0,
the vendored AOF would have required distributing this combined work
under AGPL-3.0; it is not.

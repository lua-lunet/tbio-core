//! The C ABI over the WAL lock snapshot store's two-stream double-ring
//! rotating engine (docs/src/wal-snapshot.md in the outer repo is the
//! binding design). The `aof_c.zig` precedent: the ABI is the module
//! boundary — opaque handles, errno-style result codes, no Zig types
//! crossing.
//!
//! This surface drives both streams: `wal_submit` carries the 64-byte
//! ephemeral records, `wal_durable_submit` the 768-byte fat frames
//! (validated through the engine's own codec, pointer-only,
//! caller-owned), `wal_load` / `wal_load_durable` answer with each
//! stream's live set, and `wal_flush_sync` writes the caller's two
//! live sets forward — reconciled per stream against the engine's
//! mirrors — and fsyncs exactly once: the one fsync covers both
//! streams. The frame exchange `wal_frame_encode` / `wal_frame_decode`
//! rides the engine's codec, the record exchange's shape.
//!
//! The host is a sans-IO single-threaded libuv loop. **Single-thread
//! contract**: every call here runs on the caller's loop thread — the
//! same thread that opened the handle. No threads are spawned and no
//! state is shared; every counter below is a plain loop-owned integer
//! (no atomics, no locks — there is no other thread to be safe from).
//! On Linux completions are drained on the loop thread too (eventfd
//! wake or timer tick); on darwin there is no kernel-async file IO
//! (kqueue's EVFILT_AIO is documented unsupported; upstream's darwin
//! backend states file IO "is synchronous") and each write completes
//! inline at submit time.
//!
//! Durability classes: the steady path (`wal_submit`) is page-cached
//! and fsyncs never; the shutdown generation (`wal_flush_sync`) writes
//! the caller's full live set in the foreground and fsyncs exactly
//! once — blocking is the contract there. Closing a dirty handle
//! (`wal_close`) drops the in-flight state without fsync: the
//! documented loss window (a crash mid-period loses the periodic
//! snapshot and a dirty boot never reads the artefact).
//!
//! Clock: the engine is sans-IO and takes its clock per call; the C ABI
//! does not carry one, so the wall clock of the calling host is taken
//! here (`std.time.nanoTimestamp`, the loop thread) — the node's clock
//! is the leader's clock.
//!
//! Result codes are errno-style negatives: 0 ok, `-EINVAL` (22) for a
//! caller mistake or refused content, `-ENOSPC` (28) for a capacity
//! refusal, `-EIO` (5) for a backend IO failure (the handle is poisoned:
//! drop it), `-EAGAIN` (11) when a previous batch is still outstanding
//! (pump first), `-ENOBUFS` (105) when a load buffer is too small.
//!
//! Counter semantics (the design doc's status table, driven by
//! completions — not by submits): `completed_records` counts records
//! landed, `completed_generations` counts fully completed batches, both
//! move when the writes complete (inline on darwin, at `wal_pump` /
//! inside `wal_flush_sync` on Linux). `in_flight` is 0 or one
//! generation's worth of outstanding records. The engine's own internal
//! counters (`wal_snapshot`'s status) are submit-time bookkeeping; this
//! ABI's `WalStatus` is the exposed truth.
const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const assert = std.debug.assert;

const wal_snapshot = @import("wal_snapshot.zig");

const uring_backend = @import("io/wal_uring_linux.zig");

const BackendIO = if (builtin.os.tag == .linux)
    uring_backend.UringIO
else
    wal_snapshot.SyncIO;

/// Darwin (and every non-Linux host this build targets): the backend is
/// the engine's synchronous IO — page-cached blocking pwrite, completion
/// inline at submit. Linux: io_uring + eventfd, completion at pump.
const inline_completion = BackendIO == wal_snapshot.SyncIO;

const Wal = wal_snapshot.WalType(BackendIO);

/// The ABI's status record (the design doc's counter table, per stream —
/// the doc's table notes each counter's stream). Field order is the
/// ABI's layout; the host mirrors it. One row per stream: the ephemeral
/// stream's counters and the durable stream's, each completion-driven.
/// The ABI's status row for one stream (the design doc's status table).
pub const WalStreamStatus = extern struct {
    completed_generations: u64,
    completed_records: u64,
    refusals: u64,
    in_flight: u32,
};

pub const WalStatus = extern struct {
    ephemeral: WalStreamStatus,
    durable: WalStreamStatus,
    last_completed_unix_ns: u64,
};

/// One stream's ABI counters and outstanding-batch tracking (Linux; the
/// batch is always closed on the inline-completion platforms).
pub const StreamHandle = struct {
    completed_generations: u64 = 0,
    completed_records: u64 = 0,
    refusals: u64 = 0,
    in_flight: u32 = 0,

    /// The outstanding batch's record count and completion watermark
    /// (Linux only): the batch is complete when the backend's contiguous
    /// watermark reaches `batch_end`.
    batch_open: bool = false,
    batch_records: u32 = 0,
    batch_end: u64 = 0,
};

/// One open WAL handle: the engine over this platform's backend, plus
/// the ABI's per-stream counters and the per-stream outstanding-batch
/// tracking (Linux; always closed on the inline-completion platforms).
pub const WalHandle = struct {
    wal: Wal,

    eph: StreamHandle = .{},
    dur: StreamHandle = .{},

    last_completed_unix_ns: u64 = 0,

    /// A backend IO failure poisons the handle: every subsequent call
    /// reports -EIO until the host drops it. Never a silent partial.
    poisoned: bool = false,
};

/// Open (create or open, never truncate) the fixed-size 8 MiB `.wal`
/// file at `path`, select both streams' epochs, load both active pairs'
/// live sets, and leave the engine ready. `capacity` is the operator
/// knob (records per ring, both streams); 0 selects the default (1024),
/// anything above the ring geometry's maximum is refused. Returns null
/// on refusal: a bad path, a wrong-size file, a busy (already-owned)
/// file, corrupt content at open, or an engine-refused config — the load
/// path's content refusals (wrong checksums, twin disagreement) are all
/// here.
export fn wal_open(path: [*:0]const u8, capacity: u32) ?*WalHandle {
    const path_len = mem.len(path);
    if (path_len == 0 or path_len > std.fs.max_path_bytes) return null;

    const capacity_effective = if (capacity == 0) wal_snapshot.capacity_default else capacity;
    // The capacity honesty law: a generation that exceeds the capacity is
    // a refused flush, and a capacity beyond the ring's fixed geometry is
    // a refused OPEN — the file's every offset is fixed, so the caller's
    // sizing knob is bounded. A caller error is refused like any other
    // open refusal (null), never an assertion: the ring's geometry
    // arithmetic is only ever handed a capacity inside its bound.
    if (capacity_effective > wal_snapshot.ring_capacity_max) return null;

    const config = wal_snapshot.Config{
        .capacity = capacity_effective,
    };

    const io = backend_open(path[0..path_len], config.capacity) catch return null;
    errdefer io.close();

    const wal = Wal.open(std.heap.c_allocator, io, config, now_ns()) catch return null;

    const handle = std.heap.c_allocator.create(WalHandle) catch {
        var owned = wal;
        owned.deinit();
        return null;
    };
    handle.* = .{ .wal = wal };
    return handle;
}

/// Open the platform's backend: the ring geometry rides along only where
/// there is a ring (the comptime-known branch prunes the other call).
fn backend_open(path: []const u8, capacity: u32) !BackendIO {
    if (inline_completion) return BackendIO.open(path);
    return BackendIO.open(path, uring_backend.geometry_for_capacity(capacity));
}

/// Close the handle. No fsync on the steady path: a dirty close drops
/// the in-flight state (the documented loss window). The durability the
/// caller wanted at shutdown belongs to `wal_flush_sync`, called before
/// this.
export fn wal_close(handle: ?*WalHandle) void {
    const h = handle orelse return;
    h.wal.deinit();
    h.wal.io.close();
    std.heap.c_allocator.destroy(h);
}

/// The steady tick's write: `buf` is the caller's serialized records —
/// one batch, one generation, `len` bytes (a multiple of the 64-byte
/// record size, at least one record). Each record is validated (data
/// checksum, tag) and submitted forward through the active pair. On the
/// inline-completion platforms the writes complete inside this call and
/// the counters move immediately; on Linux the SQEs are entered with
/// one non-blocking `io_uring_enter` and the batch completes at
/// `wal_pump` (`in_flight` = the batch's records until then).
///
/// A capacity refusal (`-ENOSPC`) is counted in `refusals` and leaves
/// the serving state untouched: the records that fit are in flight and
/// complete normally at the next pump; the host serializes the refused
/// lock's change again next tick. Never a silent partial write.
export fn wal_submit(handle: ?*WalHandle, buf: [*]const u8, len: usize) c_int {
    const h = handle orelse return -EINVAL;
    if (h.poisoned) return -EIO;
    if (len == 0 or len % wal_snapshot.record_size != 0) return -EINVAL;
    if (len / wal_snapshot.record_size > std.math.maxInt(u32)) return -EINVAL;
    if (!inline_completion and h.eph.batch_open) return -EAGAIN;

    const now = now_ns();
    const records: usize = len / wal_snapshot.record_size;
    var landed: usize = 0;

    for (0..records) |i| {
        const record_bytes = buf[i * wal_snapshot.record_size ..][0..wal_snapshot.record_size];
        const record = wal_snapshot.record_decode(record_bytes) catch return -EINVAL;
        h.wal.submit(record, now) catch |err| switch (err) {
            error.WalCapacity => {
                h.eph.refusals += 1;
                return close_generation(h, &h.eph, landed, now, -ENOSPC);
            },
            else => {
                h.poisoned = true;
                return -EIO;
            },
        };
        landed += 1;
    }

    return close_generation(h, &h.eph, landed, now, 0);
}

/// The steady tick's durable write: `frame_bytes` is the caller's
/// serialized fat frames — one batch, one durable generation, `len`
/// bytes (a nonzero multiple of the 768-byte frame size). Each frame is
/// validated through the engine's own codec (both integrity layers, the
/// durable tag, the budget lengths) and submitted to the durable stream
/// through the active pair; the batch discipline is the ephemeral
/// submit's, per stream: on the inline-completion platforms the writes
/// complete inside this call and the durable counters move immediately;
/// on Linux the SQEs are entered with one non-blocking `io_uring_enter`
/// and the batch completes at `wal_pump` (`in_flight` on the durable
/// row until then). A second durable submit before the pump is refused
/// (`-EAGAIN`) — the ephemeral batch is a separate stream and does not
/// block this one.
///
/// A capacity refusal (`-ENOSPC`) is counted on the durable row and
/// leaves the serving state untouched, the ephemeral submit's rule.
export fn wal_durable_submit(handle: ?*WalHandle, frame_bytes: [*]const u8, len: usize) c_int {
    const h = handle orelse return -EINVAL;
    if (h.poisoned) return -EIO;
    if (len == 0 or len % wal_snapshot.fat_frame_size != 0) return -EINVAL;
    if (len / wal_snapshot.fat_frame_size > std.math.maxInt(u32)) return -EINVAL;
    if (!inline_completion and h.dur.batch_open) return -EAGAIN;

    const now = now_ns();
    const frames: usize = len / wal_snapshot.fat_frame_size;
    var landed: usize = 0;

    for (0..frames) |i| {
        const bytes =
            frame_bytes[i * wal_snapshot.fat_frame_size ..][0..wal_snapshot.fat_frame_size];
        // The engine's own codec validates the frame; the change it
        // feeds submit_durable is the decoded frame's own content — the
        // re-encode inside the engine reproduces these bytes exactly.
        const frame = wal_snapshot.frame_decode(bytes) catch return -EINVAL;
        const change = wal_snapshot.DurableChange{
            .record = frame.header,
            .name = frame.name(),
            .taken_at_ms = frame.taken_at_ms(),
            .renew_count = frame.renew_count(),
            .tag_bytes = frame.tag_bytes(),
        };
        h.wal.submit_durable(change, now) catch |err| switch (err) {
            error.WalCapacity => {
                h.dur.refusals += 1;
                return close_generation(h, &h.dur, landed, now, -ENOSPC);
            },
            else => {
                h.poisoned = true;
                return -EIO;
            },
        };
        landed += 1;
    }

    return close_generation(h, &h.dur, landed, now, 0);
}

/// Drain completions non-blocking. Inline-completion platforms: a no-op
/// success (everything completed at submit). Linux: reaps the ring's
/// CQEs and moves the counters for every batch that fully completed. A
/// backend IO failure reports -EIO (and poisons the handle) — the host
/// drops the handle; never a silent partial write.
export fn wal_pump(handle: ?*WalHandle) c_int {
    const h = handle orelse return -EINVAL;
    if (h.poisoned) return -EIO;

    if (!inline_completion) {
        _ = h.wal.io.pump();
        return collect(h, now_ns());
    }
    return 0;
}

/// The eventfd registered with the ring (created and registered at
/// open): each completion wakes it. The host polls it (`uv_poll`) and
/// calls `wal_pump` on wake. -1 where there is no ring (the
/// inline-completion platforms).
export fn wal_event_fd(handle: ?*WalHandle) c_int {
    const h = handle orelse return -1;
    if (inline_completion) return -1;
    return @intCast(h.wal.io.event_fd);
}

/// The shutdown generation: the caller's full live sets — the ephemeral
/// set (`buf`, a multiple of the record size; `len == 0` an empty table)
/// and the durable set (`dur_buf`, a multiple of the 768-byte frame size;
/// `dur_len == 0` an empty durable set) — written forward through their
/// active pairs in the foreground, then exactly ONE fsync. Blocking is
/// the contract. Records and frames are validated and re-stamped with
/// the shutdown write's own time; each set is reconciled against its
/// stream's engine mirror — the ephemeral set must agree exactly (same
/// count, same locks, same values), the durable set must agree member
/// for member (every caller frame matches its mirror entry field-true;
/// mirror entries the caller does not name are kept records whose frames
/// the engine already holds — they stand). A divergence is a loud failed
/// stop, not a silent drift. Capacity refusal (`position + live >
/// capacity`, per stream) is a negative code: the failed stop of the
/// law, counted on the stream that overran.
export fn wal_flush_sync(
    handle: ?*WalHandle,
    buf: [*]const u8,
    len: usize,
    dur_buf: [*]const u8,
    dur_len: usize,
) c_int {
    const h = handle orelse return -EINVAL;
    if (h.poisoned) return -EIO;
    if (len % wal_snapshot.record_size != 0) return -EINVAL;
    if (len / wal_snapshot.record_size > std.math.maxInt(u32)) return -EINVAL;
    if (dur_len % wal_snapshot.fat_frame_size != 0) return -EINVAL;
    if (dur_len / wal_snapshot.fat_frame_size > std.math.maxInt(u32)) return -EINVAL;

    const now = now_ns();

    // Validate the whole sets first: nothing lands on a refused member.
    const records: usize = len / wal_snapshot.record_size;
    const set = std.heap.c_allocator.alloc(wal_snapshot.WalRecord, records) catch
        return -EIO;
    defer std.heap.c_allocator.free(set);

    for (0..records) |i| {
        const record_bytes = buf[i * wal_snapshot.record_size ..][0..wal_snapshot.record_size];
        const record = wal_snapshot.record_decode(record_bytes) catch return -EINVAL;
        // Tombstones are not live-set members: a lock that is gone was
        // dropped by a submitted tombstone and is simply absent here.
        if (record.kind() != .live) return -EINVAL;
        if (record.lock_id == 0) return -EINVAL;
        set[i] = record;
    }

    const frames_n: usize = dur_len / wal_snapshot.fat_frame_size;
    const frames = std.heap.c_allocator.alloc(wal_snapshot.FatFrame, frames_n) catch
        return -EIO;
    defer std.heap.c_allocator.free(frames);

    var seen_durable_ids = std.AutoHashMap(u64, void).init(std.heap.c_allocator);
    defer seen_durable_ids.deinit();

    for (0..frames_n) |i| {
        const frame_bytes =
            dur_buf[i * wal_snapshot.fat_frame_size ..][0..wal_snapshot.fat_frame_size];
        const frame = wal_snapshot.frame_decode(frame_bytes) catch return -EINVAL;
        if (frame.header.lock_id == 0) return -EINVAL;
        seen_durable_ids.put(frame.header.lock_id, {}) catch return -EIO;
        frames[i] = frame;
    }
    if (seen_durable_ids.count() != frames_n) return -EINVAL;

    // Reconcile with the engine's mirrors: the host's lock table is the
    // authority, the mirrors were built from the same submissions, and a
    // disagreement means something was lost in between — a failed stop.
    if (h.wal.live_count() != records) return -EINVAL;
    for (set) |record| {
        const mirror = h.wal.live_get(record.lock_id) orelse return -EINVAL;
        if (mirror.kind() != .live) return -EINVAL;
        if (mirror.expiry != record.expiry or
            mirror.lease_id != record.lease_id or
            !mem.eql(u8, &mirror.holder, &record.holder) or
            mirror.lease_ms != record.lease_ms) return -EINVAL;
    }
    for (frames) |frame| {
        const mirror = h.wal.dur_live_get(frame.header.lock_id) orelse return -EINVAL;
        if (!durable_frames_agree(mirror, frame)) return -EINVAL;
    }

    if (!inline_completion) {
        // Foreground drain of the outstanding batches first (blocking is
        // the contract here), so the flush's writes never share the
        // ring's completion depth with them.
        while (h.eph.batch_open or h.dur.batch_open) {
            _ = h.wal.io.pump();
            const rc = collect(h, now_ns());
            if (rc != 0) return rc;
            if ((h.eph.batch_open or h.dur.batch_open) and
                h.wal.io.submitted == h.wal.io.completed_contiguous)
            {
                // Everything is reaped yet a batch never completed:
                // unreachable by construction — poison rather than spin.
                h.poisoned = true;
                return -EIO;
            }
        }
    }

    // The capacity attribution the refusal carries: the stream whose
    // pair cannot take its set. The engine refuses authoritatively; the
    // arithmetic here only names the stream (or both) for the counters.
    const eph_over = @as(u64, h.wal.eph_position()) + records > h.wal.capacity;
    const dur_over = @as(u64, h.wal.dur_position()) + frames_n > h.wal.capacity;

    h.wal.flush_records(set, frames, now) catch |err| switch (err) {
        error.WalCapacity => {
            if (eph_over) h.eph.refusals += 1;
            if (dur_over) h.dur.refusals += 1;
            if (!eph_over and !dur_over) {
                h.poisoned = true;
                return -EIO;
            }
            return -ENOSPC;
        },
        else => {
            h.poisoned = true;
            return -EIO;
        },
    };

    // The flush completed synchronously on both platforms (on Linux the
    // fsync's drain reaped every write completion before returning).
    h.eph.completed_records += records;
    h.eph.completed_generations += 1;
    h.dur.completed_records += frames_n;
    h.dur.completed_generations += 1;
    h.last_completed_unix_ns = now;
    return 0;
}

/// Field-true agreement of a caller's frame with its engine mirror entry:
/// the durable content the mirror vouches for, compared field by field.
/// The stamp and the checksums are NOT compared — the flush re-stamps
/// with its own write time and both integrity layers recompute with it.
fn durable_frames_agree(mirror: wal_snapshot.FatFrame, frame: wal_snapshot.FatFrame) bool {
    if (mirror.kind() != frame.kind()) return false;
    if (mirror.header.expiry != frame.header.expiry) return false;
    if (mirror.header.lease_id != frame.header.lease_id) return false;
    if (!mem.eql(u8, &mirror.header.holder, &frame.header.holder)) return false;
    if (mirror.header.lease_ms != frame.header.lease_ms) return false;
    if (!mem.eql(u8, mirror.name(), frame.name())) return false;
    if (mirror.taken_at_ms() != frame.taken_at_ms()) return false;
    if (mirror.renew_count() != frame.renew_count()) return false;
    if (!mem.eql(u8, mirror.tag_bytes(), frame.tag_bytes())) return false;
    return true;
}

/// The boot read: the engine's live set copied into `buf` as on-disk
/// records (the submit path's own wire format — the host decodes what
/// it needs). 0 = live set found and copied, 1 = none (a cold start
/// opens empty; content corruption — wrong checksums, twin
/// disagreement — refuses the `wal_open` itself and never reaches
/// this), -ENOBUFS = a buffer too small for the whole set (never a
/// partial copy), negative = an unexpected IO error. The host maps
/// 0/1/negative per the law: content problems are Ok(None), never Err.
export fn wal_load(handle: ?*WalHandle, buf: [*]u8, len: usize, out_len: *usize) c_int {
    const h = handle orelse return -EINVAL;
    if (h.poisoned) return -EIO;

    // live_encode's only failure is a too-small buffer: refused whole,
    // never a partial copy.
    const written = h.wal.live_encode(buf[0..len]) catch return -ENOBUFS;
    if (written == 0) return 1;
    out_len.* = written;
    return 0;
}

/// The boot read's durable half: the durable stream's live set — live
/// and kept frames alike — copied into `buf` as on-disk fat frames (the
/// durable submit path's own wire format). 0 = the set found and copied,
/// 1 = none (cold start), negative = an unexpected IO error or a buffer
/// too small (`-ENOBUFS`, refused whole — never a partial copy). The
/// same found/none/error classes as `wal_load`; the host reads both
/// streams at boot, one call each. Content refusals refuse at
/// `wal_open` and never reach here, as everywhere.
export fn wal_load_durable(handle: ?*WalHandle, buf: [*]u8, len: usize, out_len: *usize) c_int {
    const h = handle orelse return -EINVAL;
    if (h.poisoned) return -EIO;

    const written = h.wal.dur_live_encode(buf[0..len]) catch return -ENOBUFS;
    if (written == 0) return 1;
    out_len.* = written;
    return 0;
}

/// The counters (the design doc's status table). Plain loop-owned
/// integers, updated on the calling thread by completions.
export fn wal_status(handle: ?*WalHandle, out: ?*WalStatus) c_int {
    const h = handle orelse return -EINVAL;
    const o = out orelse return -EINVAL;
    o.* = .{
        .ephemeral = .{
            .completed_generations = h.eph.completed_generations,
            .completed_records = h.eph.completed_records,
            .refusals = h.eph.refusals,
            .in_flight = h.eph.in_flight,
        },
        .durable = .{
            .completed_generations = h.dur.completed_generations,
            .completed_records = h.dur.completed_records,
            .refusals = h.dur.refusals,
            .in_flight = h.dur.in_flight,
        },
        .last_completed_unix_ns = h.last_completed_unix_ns,
    };
    return 0;
}

// ---------------------------------------------------------------------------
// The record exchange: thin exports over the engine's own codec. There is
// exactly one record codec and one checksum in the system — the engine's,
// over the vendored primitive — and these exports are the host's only way
// to it: the fields struct in, the on-disk bytes out (encode, checksum
// stamped here) and the on-disk bytes in, the fields struct out (decode,
// checksum verified here). A host that serializes records itself would be
// a second checksum implementation that must agree with this one forever;
// none exists.
// ---------------------------------------------------------------------------

/// One record, the ABI's exchange shape between the host and the engine's
/// codec: the engine's own `WalRecord`, shared as the ABI struct. The
/// struct is layout-exact and memcpy-round-trippable — 64 bytes, zero
/// padding, the on-disk bytes ARE the struct's bytes — and the layout is
/// pinned by the shared module's comptime asserts (size, every offset,
/// alignment, no padding), which run on every build that imports this
/// type. The `tag` the host exchanges is the record kind's code (the
/// engine's `Kind` enum values: 1 = live, 2 = tombstone); the on-disk
/// tag's format-version bits are the engine's knowledge — encode stamps
/// them, decode hands the kind code back. The `checksum` is the engine's:
/// encode stamps it into the struct's own field, decode verifies it.
pub const WalRecordIn = wal_snapshot.WalRecord;

comptime {
    // The shared layout asserts (the struct's own comptime block) run on
    // every build; this explicit pin restates the ABI's own contract.
    assert(wal_snapshot.record_size == @sizeOf(WalRecordIn));
}

/// The kind a tag code names, or null for an unknown code — the caller
/// mistake the exports refuse.
fn kind_from_tag(tag: u32) ?wal_snapshot.Kind {
    return switch (tag) {
        @intFromEnum(wal_snapshot.Kind.live) => .live,
        @intFromEnum(wal_snapshot.Kind.tombstone) => .tombstone,
        else => null,
    };
}

/// Encode one record through the engine's own codec: the struct in (the
/// kind code in `tag`, the checksum field ignored), the 64-byte on-disk
/// record out — the engine stamps the format-version bits and the
/// checksum into the struct's own fields, then memcpy. Refusals: a null
/// struct pointer or a caller mistake in the fields — a zero lock id, an
/// unknown kind code — is `-EINVAL`; a buffer smaller than the record
/// size is `-ENOBUFS`, refused whole, never a partial write.
export fn wal_record_encode(out: [*]u8, out_cap: usize, in: ?*const WalRecordIn) c_int {
    const fields = in orelse return -EINVAL;
    if (out_cap < wal_snapshot.record_size) return -ENOBUFS;
    const kind = kind_from_tag(fields.tag) orelse return -EINVAL;
    if (fields.lock_id == 0) return -EINVAL;
    var record: wal_snapshot.WalRecord = fields.*;
    record.tag = wal_snapshot.tag_encode(kind);
    wal_snapshot.record_encode(out[0..wal_snapshot.record_size], record);
    return 0;
}

/// Decode one on-disk record through the engine's own codec: the 64
/// bytes in (checksum verified here), the struct out. Refusals: a null
/// pointer, a length other than the record size, or content the engine
/// refuses — a rotted checksum, a foreign format version, an unknown
/// kind — is `-EINVAL`; a zero lock id is refused too (a record the
/// engine's own constructors can never produce).
export fn wal_record_decode(out: ?*WalRecordIn, buf: [*]const u8, len: usize) c_int {
    const fields = out orelse return -EINVAL;
    if (len != wal_snapshot.record_size) return -EINVAL;
    const record = wal_snapshot.record_decode(buf[0..wal_snapshot.record_size]) catch
        return -EINVAL;
    if (record.lock_id == 0) return -EINVAL;
    fields.* = record;
    fields.tag = @intFromEnum(record.kind());
    return 0;
}

// ---------------------------------------------------------------------------
// The frame exchange: the durable fat frame's exports over the engine's
// own codec, the record exchange's shape. The caller's fields struct in
// through flat, pointer-only arguments (name and tag bytes are the
// caller's buffers, never copied by the ABI), the 768-byte on-disk frame
// out — the engine stamps the sha and the frame checksum. Decode is the
// reverse: the on-disk frame in (both integrity layers verified here),
// the mirror struct out. A host that serializes frames itself would be a
// second checksum implementation; none exists.
// ---------------------------------------------------------------------------

/// The durable kind a tag code names, or null for an unknown code — the
/// caller mistake the exports refuse.
fn durable_kind_from_tag(tag: u32) ?wal_snapshot.DurableKind {
    return switch (tag) {
        @intFromEnum(wal_snapshot.DurableKind.live) => .live,
        @intFromEnum(wal_snapshot.DurableKind.kept) => .kept,
        @intFromEnum(wal_snapshot.DurableKind.delete) => .delete,
        else => null,
    };
}

/// Encode one durable frame through the engine's own codec: the header
/// record's fields (the durable kind's code in `tag`) plus the name,
/// counters and tag bytes (the caller's buffers, at most the frame's
/// budgets), the 768-byte on-disk form out — the engine stamps the
/// format-version bits, the sha and the frame checksum. Refusals: a
/// null record pointer, a zero lock id, an unknown kind code, a name or
/// tag-bytes span over the frame's budget, or a null byte buffer under a
/// nonzero length — `-EINVAL`; a buffer smaller than the frame size is
/// `-ENOBUFS`, refused whole, never a partial write.
export fn wal_frame_encode(
    out: [*]u8,
    out_cap: usize,
    record: ?*const WalRecordIn,
    name: ?[*]const u8,
    name_len: usize,
    taken_at_ms: u64,
    renew_count: u32,
    tag_bytes: ?[*]const u8,
    tag_len: usize,
) c_int {
    const fields = record orelse return -EINVAL;
    if (out_cap < wal_snapshot.fat_frame_size) return -ENOBUFS;
    const kind = durable_kind_from_tag(fields.tag) orelse return -EINVAL;
    if (fields.lock_id == 0) return -EINVAL;
    if (name_len > wal_snapshot.fat_name_capacity) return -EINVAL;
    if (tag_len > wal_snapshot.fat_tag_bytes_capacity) return -EINVAL;
    if (name_len > 0 and name == null) return -EINVAL;
    if (tag_len > 0 and tag_bytes == null) return -EINVAL;

    // The tag the host exchanges is the durable kind's code; the
    // format-version bits are the engine's knowledge — encode stamps
    // them, exactly like the record exchange.
    var stamped = fields.*;
    stamped.tag = wal_snapshot.tag_encode_durable(kind);
    const change = wal_snapshot.DurableChange{
        .record = stamped,
        .name = if (name_len == 0) &.{} else name.?[0..name_len],
        .taken_at_ms = taken_at_ms,
        .renew_count = renew_count,
        .tag_bytes = if (tag_len == 0) &.{} else tag_bytes.?[0..tag_len],
    };
    var frame_bytes: [wal_snapshot.fat_frame_size]u8 = undefined;
    wal_snapshot.frame_encode(&frame_bytes, change) catch return -EINVAL;
    @memcpy(out[0..wal_snapshot.fat_frame_size], &frame_bytes);
    return 0;
}

/// Decode one on-disk fat frame through the engine's own codec: the 768
/// bytes in (both integrity layers verified here, the durable tag and
/// the budget lengths validated), the mirror struct out — the on-disk
/// checksum stays in its field. Refusals: a null out pointer, a length
/// other than the frame size, or content the engine refuses — `-EINVAL`.
export fn wal_frame_decode(out: ?*wal_snapshot.FatFrame, frame_bytes: [*]const u8, len: usize) c_int {
    const mirror = out orelse return -EINVAL;
    if (len != wal_snapshot.fat_frame_size) return -EINVAL;
    const bytes: *const [wal_snapshot.fat_frame_size]u8 = @ptrCast(frame_bytes);
    const frame = wal_snapshot.frame_decode(bytes) catch return -EINVAL;
    if (frame.header.lock_id == 0) return -EINVAL;
    mirror.* = frame;
    // The kind code rides back in `tag` — the version bits are the
    // engine's knowledge, exactly like the record exchange's decode.
    mirror.header.tag = @intFromEnum(frame.kind());
    return 0;
}

// ---------------------------------------------------------------------------
// Internals.
// ---------------------------------------------------------------------------

fn now_ns() u64 {
    return @intCast(@max(0, std.time.nanoTimestamp()));
}

/// The generation's close (either stream): the batch's queued writes are
/// entered (Linux — without the enter the SQEs sit queued forever, the
/// pump never completes them, and the shutdown drain spins), the
/// generation is marked complete, and the counters move: on the
/// inline-completion platforms inside this call, on Linux at the pump.
/// `deficit_rc` is the refusal code to return (0 = clean) — a refused
/// batch takes the same close, so the records that landed are always in
/// flight and complete normally.
fn close_generation(h: *WalHandle, st: *StreamHandle, landed: usize, now: u64, deficit_rc: c_int) c_int {
    if (!inline_completion) {
        h.wal.io.submit_batch() catch {
            h.poisoned = true;
            return -EIO;
        };
    }

    h.wal.complete_generation();

    if (inline_completion) {
        st.completed_records += landed;
        st.completed_generations += 1;
        h.last_completed_unix_ns = now;
        return deficit_rc;
    }

    if (landed == 0) return deficit_rc;

    st.batch_open = true;
    st.batch_records = @intCast(landed);
    st.batch_end = h.wal.io.submitted;
    st.in_flight = st.batch_records;
    return deficit_rc;
}

/// Completion bookkeeping after a reap: every batch whose watermark the
/// backend's contiguous completion watermark has passed is complete —
/// its records landed and its generation counted, now (the completion
/// time). A backend failure poisons the handle and reports -EIO.
fn collect(h: *WalHandle, now: u64) c_int {
    if (h.wal.io.completion_errors > 0) {
        h.poisoned = true;
        return -EIO;
    }

    for ([_]*StreamHandle{ &h.eph, &h.dur }) |st| {
        if (st.batch_open and h.wal.io.completed_contiguous >= st.batch_end) {
            st.completed_records += st.batch_records;
            st.completed_generations += 1;
            h.last_completed_unix_ns = now;
            st.batch_open = false;
            st.in_flight = 0;
        }
    }
    return 0;
}

// The errno-style result codes (the errno values; the call sites return
// them negated, so a refusal is the documented negative: -EINVAL etc).
const EINVAL: c_int = 22;
const EAGAIN: c_int = 11;
const ENOBUFS: c_int = 105;
const ENOSPC: c_int = 28;
const EIO: c_int = 5;

// ---------------------------------------------------------------------------
// Tests (deterministic, defensive; the suite is rooted at aof_c.zig).
// ---------------------------------------------------------------------------

const testing = std.testing;

const Holder: [16]u8 = "holder-uuid-0001".*;
const Window: u64 = 30_000;

fn record_bytes_live(stamp: u64, expiry: u64, lock_id: u64, lease_id: u64) [wal_snapshot.record_size]u8 {
    const record = wal_snapshot.WalRecord.live(stamp, expiry, lock_id, lease_id, Holder, Window);
    return record_encode_for_test(record);
}

fn record_bytes_tombstone(stamp: u64, lock_id: u64, lease_id: u64) [wal_snapshot.record_size]u8 {
    return record_encode_for_test(wal_snapshot.WalRecord.tombstone(stamp, lock_id, lease_id));
}

fn record_encode_for_test(record: wal_snapshot.WalRecord) [wal_snapshot.record_size]u8 {
    var bytes: [wal_snapshot.record_size]u8 = undefined;
    wal_snapshot.record_encode(&bytes, record);
    return bytes;
}

/// The host's durable fields struct: the tag is the bare kind code —
/// the format-version bits are the engine's, stamped by the encode
/// export.
fn durable_fields(
    kind: wal_snapshot.DurableKind,
    stamp: u64,
    expiry: u64,
    lock_id: u64,
    lease_id: u64,
) wal_snapshot.WalRecord {
    return .{
        .stamp = stamp,
        .expiry = expiry,
        .lock_id = lock_id,
        .lease_id = lease_id,
        .holder = Holder,
        .lease_ms = Window,
        .tag = @intFromEnum(kind),
    };
}

/// One durable frame through the ABI's own encode export: the identity
/// fields plus a name, tag bytes and the counters. The round trips in
/// the tests below hold this caller-side encoding against what the
/// engine stores and hands back.
fn durable_frame(
    kind: wal_snapshot.DurableKind,
    stamp: u64,
    expiry: u64,
    lock_id: u64,
    lease_id: u64,
    name: []const u8,
    taken_at_ms: u64,
    renew_count: u32,
    tag_bytes: []const u8,
) [wal_snapshot.fat_frame_size]u8 {
    const record = durable_fields(kind, stamp, expiry, lock_id, lease_id);
    var bytes: [wal_snapshot.fat_frame_size]u8 = undefined;
    const rc = wal_frame_encode(
        &bytes,
        bytes.len,
        &record,
        name.ptr,
        name.len,
        taken_at_ms,
        renew_count,
        tag_bytes.ptr,
        tag_bytes.len,
    );
    assert(rc == 0);
    return bytes;
}

fn tmp_wal_path_z(allocator: mem.Allocator, tmp: *testing.TmpDir) ![:0]u8 {
    const abs = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(abs);
    const joined = try std.fs.path.join(allocator, &.{ abs, "snapshot.wal" });
    defer allocator.free(joined);
    return try allocator.dupeZ(u8, joined);
}

/// The steady loop's cadence, compressed. The linux ring's completions
/// land with real time — the pump reaps only what the kernel has
/// posted — while the darwin backend completes inside the submit. The
/// beat is the production loop's ~1000 ms tick, sped up: pump, then a
/// bounded wait for the outstanding batch to complete, pumping as the
/// completions arrive. Every test step that reads a completed counter,
/// submits again, closes, reopens, or flushes holds only past a beat.
fn beat(handle: *WalHandle) void {
    _ = wal_pump(handle);
    var attempts: usize = 0;
    while (attempts < 80) : (attempts += 1) {
        var status: WalStatus = undefined;
        _ = wal_status(handle, &status);
        if (status.ephemeral.in_flight == 0 and status.durable.in_flight == 0) {
            return;
        }
        std.Thread.sleep(25 * std.time.ns_per_ms);
        _ = wal_pump(handle);
    }
    @panic("the wal test's batch never completed");
}

test "wal c: record encode/decode round trip through the ABI (one codec)" {
    // Fields in, engine bytes out: the ABI's encode is byte-identical to
    // the engine's own codec — the same implementation, one checksum.
    const fields = WalRecordIn{
        .stamp = 111,
        .expiry = 222,
        .lock_id = 7,
        .lease_id = 70,
        .tag = @intFromEnum(wal_snapshot.Kind.live),
        .holder = Holder,
        .lease_ms = Window,
    };
    var bytes: [wal_snapshot.record_size]u8 = undefined;
    try testing.expectEqual(@as(c_int, 0), wal_record_encode(&bytes, bytes.len, &fields));
    try testing.expectEqualSlices(u8, &record_bytes_live(111, 222, 7, 70), &bytes);

    var out: WalRecordIn = undefined;
    try testing.expectEqual(@as(c_int, 0), wal_record_decode(&out, &bytes, bytes.len));
    try testing.expectEqual(fields.stamp, out.stamp);
    try testing.expectEqual(fields.expiry, out.expiry);
    try testing.expectEqual(fields.lock_id, out.lock_id);
    try testing.expectEqual(fields.lease_id, out.lease_id);
    try testing.expectEqual(fields.tag, out.tag);
    try testing.expectEqualSlices(u8, &fields.holder, &out.holder);
    try testing.expectEqual(fields.lease_ms, out.lease_ms);
    // The decoded struct carries the engine's verified checksum and the
    // kind code in `tag`; re-encoding through the ABI is bit-identical
    // (the codec is deterministic, the version bits the engine's).
    var again: [wal_snapshot.record_size]u8 = undefined;
    try testing.expectEqual(@as(c_int, 0), wal_record_encode(&again, again.len, &out));
    try testing.expectEqualSlices(u8, &bytes, &again);

    // A tombstone round trips and encodes to the engine's tombstone bytes.
    const tomb_fields = WalRecordIn{
        .stamp = 9,
        .expiry = 0,
        .lock_id = 7,
        .lease_id = 70,
        .tag = @intFromEnum(wal_snapshot.Kind.tombstone),
        .holder = @splat(0),
        .lease_ms = 0,
    };
    var tomb_bytes: [wal_snapshot.record_size]u8 = undefined;
    try testing.expectEqual(@as(c_int, 0), wal_record_encode(&tomb_bytes, tomb_bytes.len, &tomb_fields));
    try testing.expectEqualSlices(u8, &record_bytes_tombstone(9, 7, 70), &tomb_bytes);
    var tomb_out: WalRecordIn = undefined;
    try testing.expectEqual(@as(c_int, 0), wal_record_decode(&tomb_out, &tomb_bytes, tomb_bytes.len));
    try testing.expectEqual(tomb_fields.tag, tomb_out.tag);
}

test "wal c: record encode/decode refusals" {
    var bytes: [wal_snapshot.record_size]u8 = undefined;
    const good = WalRecordIn{
        .stamp = 1,
        .expiry = 2,
        .lock_id = 7,
        .lease_id = 70,
        .tag = @intFromEnum(wal_snapshot.Kind.live),
        .holder = Holder,
        .lease_ms = Window,
    };

    // Encode: a zero lock id and an unknown kind code are caller mistakes.
    var zero_lock = good;
    zero_lock.lock_id = 0;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_record_encode(&bytes, bytes.len, &zero_lock));
    var unknown_tag = good;
    unknown_tag.tag = 7;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_record_encode(&bytes, bytes.len, &unknown_tag));

    // A short buffer is refused whole; a null fields pointer too.
    try testing.expectEqual(@as(c_int, -ENOBUFS), wal_record_encode(&bytes, bytes.len - 1, &good));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_record_encode(&bytes, bytes.len, null));

    // Decode: wrong length, null out.
    const encoded = record_bytes_live(1, 2, 7, 70);
    var out: WalRecordIn = undefined;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_record_decode(&out, &encoded, encoded.len - 1));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_record_decode(null, &encoded, encoded.len));

    // Content the engine refuses: a rotted checksum...
    var rotted = encoded;
    rotted[wal_snapshot.checksum_data_offset] ^= 0xFF;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_record_decode(&out, &rotted, rotted.len));

    // ...a foreign format version (the tag's second byte)...
    var foreign = encoded;
    foreign[wal_snapshot.tag_offset + 1] = 9;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_record_decode(&out, &foreign, foreign.len));

    // ...an unknown kind (the tag's first byte)...
    var unknown_bytes = encoded;
    unknown_bytes[wal_snapshot.tag_offset] = 7;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_record_decode(&out, &unknown_bytes, unknown_bytes.len));

    // ...and a zero lock id under a valid checksum (a record the
    // engine's own constructors can never produce; the flush path's
    // refusal, carried into the codec's decode too).
    var zero_lock_bytes = record_encode_for_test(wal_snapshot.WalRecord.live(1, 2, 0, 70, Holder, Window));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_record_decode(&out, &zero_lock_bytes, zero_lock_bytes.len));
}

test "wal c: open cold start, status zero, event fd" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    var status: WalStatus = undefined;
    try testing.expectEqual(@as(c_int, 0), wal_status(handle, &status));
    try testing.expectEqual(@as(u64, 0), status.ephemeral.completed_generations);
    try testing.expectEqual(@as(u64, 0), status.ephemeral.completed_records);
    try testing.expectEqual(@as(u64, 0), status.durable.completed_generations);
    try testing.expectEqual(@as(u64, 0), status.durable.completed_records);
    try testing.expectEqual(@as(u64, 0), status.last_completed_unix_ns);
    try testing.expectEqual(@as(u32, 0), status.ephemeral.in_flight);
    try testing.expectEqual(@as(u32, 0), status.durable.in_flight);
    try testing.expectEqual(@as(u64, 0), status.ephemeral.refusals);
    try testing.expectEqual(@as(u64, 0), status.durable.refusals);

    if (inline_completion) {
        // No ring, no eventfd: -1.
        try testing.expectEqual(@as(c_int, -1), wal_event_fd(handle));
    } else {
        // The ring's eventfd: a real, non-blocking descriptor.
        try testing.expect(wal_event_fd(handle) >= 0);
    }
}

test "wal c: open refusals (empty path)" {
    try testing.expect(wal_open("", 0) == null);
}

test "wal c: open refusals (missing dir)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const missing = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(missing);
    const bad = try std.fmt.allocPrintZ(testing.allocator, "{s}/nope/snapshot.wal", .{missing});
    defer testing.allocator.free(bad);
    try testing.expect(wal_open(bad.ptr, 0) == null);
}

test "wal c: open refusals (wrong size)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);
    {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.setEndPos(wal_snapshot.file_size - 1);
    }
    try testing.expect(wal_open(path.ptr, 0) == null);
}

test "wal c: open refusals (capacity)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);
    try testing.expect(wal_open(path.ptr, wal_snapshot.ring_capacity_max + 1) == null);
}

test "wal c: open refusals (corrupt header)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);
    {
        const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
        defer file.close();
        try file.setEndPos(wal_snapshot.file_size);
        var garbage: [wal_snapshot.header_record_size]u8 = @splat(0xAA);
        try file.pwriteAll(&garbage, 1 * 1024 * 1024);
    }
    try testing.expect(wal_open(path.ptr, 0) == null);
}

test "wal c: open refusals (busy)" {
    var fresh = testing.tmpDir(.{});
    defer fresh.cleanup();
    const clean = try tmp_wal_path_z(testing.allocator, &fresh);
    defer testing.allocator.free(clean);
    const first = wal_open(clean.ptr, 0) orelse return error.TestUnexpectedResult;
    defer wal_close(first);
    try testing.expect(wal_open(clean.ptr, 0) == null);
}

test "wal c: submit completes inline (darwin) with exact counters" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    var batch: [3 * wal_snapshot.record_size]u8 = undefined;
    for (0..3) |i| {
        const now = now_ns();
        const bytes = record_bytes_live(now + i, now + 10_000_000_000, i + 1, 100 + i);
        @memcpy(batch[i * wal_snapshot.record_size ..][0..wal_snapshot.record_size], &bytes);
    }

    const rc = wal_submit(handle, &batch, batch.len);
    if (inline_completion) {
        // The darwin path fires the completion inline: 0 now, counters
        // already moved, nothing in flight, pump a no-op.
        try testing.expectEqual(@as(c_int, 0), rc);
        var status: WalStatus = undefined;
        try testing.expectEqual(@as(c_int, 0), wal_status(handle, &status));
        try testing.expectEqual(@as(u64, 1), status.ephemeral.completed_generations);
        try testing.expectEqual(@as(u64, 3), status.ephemeral.completed_records);
        try testing.expectEqual(@as(u32, 0), status.ephemeral.in_flight);
        try testing.expect(status.last_completed_unix_ns > 0);
        beat(handle);
        try testing.expectEqual(@as(u64, 1), status.ephemeral.completed_generations);
    } else {
        // Linux: submitted, in flight until the pump.
        try testing.expectEqual(@as(c_int, 0), rc);
        var status: WalStatus = undefined;
        try testing.expectEqual(@as(c_int, 0), wal_status(handle, &status));
        try testing.expectEqual(@as(u32, 3), status.ephemeral.in_flight);
        try testing.expectEqual(@as(u64, 0), status.ephemeral.completed_generations);

        beat(handle);
        try testing.expectEqual(@as(c_int, 0), wal_status(handle, &status));
        try testing.expectEqual(@as(u64, 1), status.ephemeral.completed_generations);
        try testing.expectEqual(@as(u64, 3), status.ephemeral.completed_records);
        try testing.expectEqual(@as(u32, 0), status.ephemeral.in_flight);
        try testing.expect(status.last_completed_unix_ns > 0);
    }
}

test "wal c: submit refusals — bad length, corrupt record bytes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    // Zero length and a non-multiple of the record size are caller mistakes.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_submit(handle, &.{}, 0));
    var one: [wal_snapshot.record_size]u8 = undefined;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_submit(handle, &one, wal_snapshot.record_size + 1));

    // Corrupt record bytes (a broken checksum) are refused, nothing lands.
    const now = now_ns();
    var bytes = record_bytes_live(now, now + 10_000_000_000, 1, 100);
    bytes[wal_snapshot.checksum_data_offset] ^= 0xFF;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_submit(handle, &bytes, bytes.len));
    try testing.expectEqual(@as(u64, 0), handle.eph.refusals);

    var status: WalStatus = undefined;
    _ = wal_status(handle, &status);
    try testing.expectEqual(@as(u64, 0), status.ephemeral.completed_records);
}

test "wal c: steady capacity refusal counted, serving state unaffected" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const handle = wal_open(path.ptr, 2) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    const now = now_ns();
    var bytes = record_bytes_live(now, now + 10_000_000_000, 1, 100);
    try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &bytes, bytes.len));
    if (!inline_completion) beat(handle);
    bytes = record_bytes_live(now, now + 10_000_000_000, 2, 101);
    try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &bytes, bytes.len));
    if (!inline_completion) beat(handle);

    // The live set fills the ring: the third lock is a counted refusal.
    bytes = record_bytes_live(now, now + 10_000_000_000, 3, 102);
    try testing.expectEqual(@as(c_int, -ENOSPC), wal_submit(handle, &bytes, bytes.len));
    try testing.expectEqual(@as(u64, 1), handle.eph.refusals);

    // The landed records still complete normally.
    if (!inline_completion) beat(handle);
    var status: WalStatus = undefined;
    _ = wal_status(handle, &status);
    try testing.expectEqual(@as(u64, 2), status.ephemeral.completed_records);
    try testing.expectEqual(@as(u32, 0), status.ephemeral.in_flight);
}

test "wal c: load round trip through the ABI" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const now = now_ns();
    {
        const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;

        // Cold start: the empty live set loads as 1 (none).
        var out: [wal_snapshot.record_size]u8 = undefined;
        var out_len: usize = 0;
        try testing.expectEqual(@as(c_int, 1), wal_load(handle, &out, out.len, &out_len));

        var batch: [2 * wal_snapshot.record_size]u8 = undefined;
        const a = record_bytes_live(now, now + 10_000_000_000, 1, 100);
        const b = record_bytes_live(now, now + 20_000_000_000, 2, 101);
        @memcpy(batch[0..wal_snapshot.record_size], &a);
        @memcpy(batch[wal_snapshot.record_size..], &b);
        try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &batch, batch.len));
        if (!inline_completion) beat(handle);
        wal_close(handle);
    }

    {
        // Reopen: the epoch selection finds the generation, the scan
        // hydrates, and the load copies the set out.
        const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
        defer wal_close(handle);

        var out: [2 * wal_snapshot.record_size]u8 = undefined;
        var out_len: usize = 0;
        try testing.expectEqual(@as(c_int, 0), wal_load(handle, &out, out.len, &out_len));
        try testing.expectEqual(out.len, out_len);

        var seen: usize = 0;
        for (0..2) |i| {
            const record = wal_snapshot.record_decode(out[i * wal_snapshot.record_size ..][0..wal_snapshot.record_size]) catch
                return error.TestUnexpectedResult;
            seen += 1;
            if (record.lock_id == 1) {
                try testing.expectEqual(@as(u64, 100), record.lease_id);
                try testing.expectEqual(@as(u64, now), record.stamp);
            } else {
                try testing.expectEqual(@as(u64, 101), record.lease_id);
            }
            try testing.expectEqualSlices(u8, &Holder, &record.holder);
        }
        try testing.expectEqual(@as(usize, 2), seen);

        // A too-small buffer is refused whole (-ENOBUFS), never partial.
        var small: [wal_snapshot.record_size]u8 = undefined;
        try testing.expectEqual(
            @as(c_int, -ENOBUFS),
            wal_load(handle, &small, small.len, &out_len),
        );
    }
}

test "wal c: flush_sync lands the set, fsyncs exactly once, reopen reads it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const now = now_ns();
    {
        const handle = wal_open(path.ptr, 8) orelse return error.TestUnexpectedResult;

        var batch: [2 * wal_snapshot.record_size]u8 = undefined;
        const a = record_bytes_live(now, now + 10_000_000_000, 1, 100);
        const b = record_bytes_live(now, now + 10_000_000_000, 2, 101);
        @memcpy(batch[0..wal_snapshot.record_size], &a);
        @memcpy(batch[wal_snapshot.record_size..], &b);
        try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &batch, batch.len));
        if (!inline_completion) beat(handle);

        // The shutdown generation: the caller's full live set.
        try testing.expectEqual(@as(c_int, 0), wal_flush_sync(handle, &batch, batch.len, &.{}, 0));

        if (inline_completion) {
            // The sync backend's fsync audit: exactly one fsync.
            try testing.expectEqual(@as(usize, 1), handle.wal.io.fsync_count);
        }
        var status: WalStatus = undefined;
        _ = wal_status(handle, &status);
        try testing.expectEqual(@as(u64, 2), status.ephemeral.completed_generations);
        try testing.expectEqual(@as(u64, 4), status.ephemeral.completed_records);
        try testing.expectEqual(@as(u32, 0), status.ephemeral.in_flight);
        wal_close(handle);
    }

    {
        const handle = wal_open(path.ptr, 8) orelse return error.TestUnexpectedResult;
        defer wal_close(handle);

        // The flush generation wins the epoch; the set reopens intact
        // (stamps re-stamped by the flush — the flush write's own time).
        var out: [2 * wal_snapshot.record_size]u8 = undefined;
        var out_len: usize = 0;
        try testing.expectEqual(@as(c_int, 0), wal_load(handle, &out, out.len, &out_len));
        for (0..2) |i| {
            const record = wal_snapshot.record_decode(out[i * wal_snapshot.record_size ..][0..wal_snapshot.record_size]) catch
                return error.TestUnexpectedResult;
            try testing.expect(record.stamp >= now);
            if (record.lock_id == 1) try testing.expectEqual(@as(u64, 100), record.lease_id);
            if (record.lock_id == 2) try testing.expectEqual(@as(u64, 101), record.lease_id);
        }
    }
}

test "wal c: flush_sync refusals — bad set, tombstone, mirror disagreement, capacity" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const now = now_ns();
    const handle = wal_open(path.ptr, 2) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    var bytes = record_bytes_live(now, now + 10_000_000_000, 1, 100);
    try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &bytes, bytes.len));
    if (!inline_completion) beat(handle);

    // A length that is not a multiple of the record size.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &bytes, wal_snapshot.record_size - 1, &.{}, 0));

    // A tombstone is not a live-set member.
    const tomb = record_bytes_tombstone(now + 1, 1, 100);
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &tomb, tomb.len, &.{}, 0));

    // Corrupt bytes are refused before anything lands.
    var corrupt = record_bytes_live(now, now + 10_000_000_000, 1, 100);
    corrupt[wal_snapshot.checksum_data_offset] ^= 0xFF;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &corrupt, corrupt.len, &.{}, 0));

    // The set must agree with the mirror: one extra lock is a divergence.
    var extra: [2 * wal_snapshot.record_size]u8 = undefined;
    @memcpy(extra[0..wal_snapshot.record_size], &record_bytes_live(now, now + 10_000_000_000, 1, 100));
    @memcpy(extra[wal_snapshot.record_size..], &record_bytes_live(now, now + 10_000_000_000, 2, 101));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &extra, extra.len, &.{}, 0));

    // An empty set against a non-empty mirror: divergence too.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &.{}, 0, &.{}, 0));

    // Field drift on an existing lock (window differs) is a divergence.
    var drifted = record_bytes_live(now, now + 10_000_000_000, 1, 100);
    {
        var record = wal_snapshot.record_decode(&drifted) catch return error.TestUnexpectedResult;
        record.lease_ms += 1;
        wal_snapshot.record_encode(&drifted, record);
    }
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &drifted, drifted.len, &.{}, 0));

    // Capacity: the pair's remaining room cannot hold the live set
    // (position 1 + live 1... fits). Fill the pair first, then the
    // flush of the full set overruns.
    bytes = record_bytes_live(now, now + 10_000_000_000, 2, 101);
    try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &bytes, bytes.len));
    if (!inline_completion) beat(handle);
    // position 2, live 2, capacity 2: 2 + 2 > 2 → the failed stop.
    var full: [2 * wal_snapshot.record_size]u8 = undefined;
    @memcpy(full[0..wal_snapshot.record_size], &record_bytes_live(now, now + 10_000_000_000, 1, 100));
    @memcpy(full[wal_snapshot.record_size..], &record_bytes_live(now, now + 10_000_000_000, 2, 101));
    try testing.expectEqual(@as(c_int, -ENOSPC), wal_flush_sync(handle, &full, full.len, &.{}, 0));
    try testing.expectEqual(@as(u64, 1), handle.eph.refusals);
    if (inline_completion) {
        // Refused before anything landed: no fsync at all.
        try testing.expectEqual(@as(usize, 0), handle.wal.io.fsync_count);
    }
}

test "wal c: an empty live set flushes (one fsync, zero records)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    try testing.expectEqual(@as(c_int, 0), wal_flush_sync(handle, &.{}, 0, &.{}, 0));
    var status: WalStatus = undefined;
    _ = wal_status(handle, &status);
    try testing.expectEqual(@as(u64, 1), status.ephemeral.completed_generations);
    try testing.expectEqual(@as(u64, 0), status.ephemeral.completed_records);
    if (inline_completion) {
        try testing.expectEqual(@as(usize, 1), handle.wal.io.fsync_count);
    }
}

test "wal c: close drops the dirty in-flight state" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const now = now_ns();
    const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;

    var bytes = record_bytes_live(now, now + 10_000_000_000, 1, 100);
    try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &bytes, bytes.len));
    if (!inline_completion) beat(handle);

    // A dirty close: no flush, no fsync — the loss window. The page
    // cache still holds the generation, so the reopen below finds it;
    // the contract is about a crash, not a graceful close.
    wal_close(handle);

    const reopened = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
    defer wal_close(reopened);
    var out: [wal_snapshot.record_size]u8 = undefined;
    var out_len: usize = 0;
    try testing.expectEqual(@as(c_int, 0), wal_load(reopened, &out, out.len, &out_len));
}

test "wal c: null and poisoned handles" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    // A null handle is refused everywhere, loudly.
    var probe: [wal_snapshot.fat_frame_size]u8 = undefined;
    var probe_len: usize = 0;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_submit(null, &.{}, 0));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_pump(null));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_load(null, undefined, 0, undefined));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_load_durable(null, &probe, probe.len, &probe_len));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_durable_submit(null, &probe, probe.len));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_decode(null, &probe, probe.len));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(null, &.{}, 0, &.{}, 0));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_status(null, null));
    wal_close(null);
    try testing.expectEqual(@as(c_int, -1), wal_event_fd(null));

    // A poisoned handle reports -EIO until dropped.
    const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);
    handle.poisoned = true;
    var bytes = record_bytes_live(1, 2, 1, 1);
    try testing.expectEqual(@as(c_int, -EIO), wal_submit(handle, &bytes, bytes.len));
    try testing.expectEqual(@as(c_int, -EIO), wal_pump(handle));
    try testing.expectEqual(@as(c_int, -EIO), wal_durable_submit(handle, &probe, probe.len));
    try testing.expectEqual(@as(c_int, -EIO), wal_load_durable(handle, &probe, probe.len, &probe_len));
    var out_len: usize = 0;
    try testing.expectEqual(@as(c_int, -EIO), wal_load(handle, &bytes, bytes.len, &out_len));
    try testing.expectEqual(@as(c_int, -EIO), wal_flush_sync(handle, &bytes, bytes.len, &.{}, 0));

    // A live handle with a null status out is a caller mistake.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_status(handle, null));
}

test "wal c: linux io_uring backend facts (compile-checked everywhere, executed on Linux)" {
    if (inline_completion) return error.SkipZigTest;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    // The ring geometry covers the worst case: a full compaction batch
    // plus a coexisting flush never overflows the completion depth.
    const geometry = uring_backend.geometry_for_capacity(2);
    try testing.expect(geometry.entries >= 1024);
    try testing.expect(geometry.ops_len >= 4 * @as(u32, geometry.entries));
    // The handle itself rides the default capacity: the flush at the
    // end rewrites a live set the capacity-2 ring could not hold.
    const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    // The eventfd is real and registered with the ring.
    const efd = wal_event_fd(handle);
    try testing.expect(efd >= 0);
    const event_fd: std.posix.fd_t = @intCast(efd);
    const flags = try std.posix.fcntl(event_fd, std.posix.F.GETFL, 0);
    // O_NONBLOCK's bit, read off the struct's own field layout. The
    // named member does not resolve through the type on aarch64-linux
    // in the pinned 0.14.1 toolchain (the field is in the struct —
    // typeInfo sees it — and the named access refuses it), so the bit
    // is walked: packed fields lay out least-significant-bit first,
    // and the field's position is the sum of the widths before it.
    const o_nonblock_bit: u32 = blk: {
        var bit: u32 = 0;
        inline for (@typeInfo(std.posix.O).@"struct".fields) |f| {
            if (std.mem.eql(u8, f.name, "NONBLOCK")) {
                break :blk @as(u32, 1) << @intCast(bit);
            }
            bit += @bitSizeOf(f.type);
        }
        break :blk 0;
    };
    try testing.expect((@as(u32, @intCast(flags)) & o_nonblock_bit) != 0);

    // The eventfd wakes on completions: submit, then wait on the fd.
    const now = now_ns();
    var bytes = record_bytes_live(now, now + 10_000_000_000, 1, 100);
    try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &bytes, bytes.len));
    var status: WalStatus = undefined;
    _ = wal_status(handle, &status);
    try testing.expectEqual(@as(u32, 1), status.ephemeral.in_flight);
    try testing.expectEqual(@as(u32, 0), status.durable.in_flight);

    // Block on the eventfd (up to a second): the kernel posts one event
    // per completion. The ABI's pump then drains.
    var wake: [8]u8 = undefined;
    // The pollfd array is the poll's own scratch (the kernel may write
    // revents through it), so it is mutable.
    var poll_fds = [_]std.posix.pollfd{.{ .fd = event_fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = try std.posix.poll(&poll_fds, 1000);
    try testing.expectEqual(@as(usize, 1), ready);
    const got = try std.posix.read(event_fd, &wake);
    try testing.expect(got > 0);

    beat(handle);
    try testing.expectEqual(@as(c_int, 0), wal_status(handle, &status));
    try testing.expectEqual(@as(u64, 1), status.ephemeral.completed_generations);
    try testing.expectEqual(@as(u64, 1), status.ephemeral.completed_records);
    try testing.expectEqual(@as(u32, 0), status.ephemeral.in_flight);

    // A second submit before pumping is refused (-EAGAIN): one
    // generation's worth outstanding, per the doc — per stream. A
    // durable submit rides a separate stream and is NOT refused by the
    // ephemeral batch; a second durable submit before the pump is.
    bytes = record_bytes_live(now, now + 10_000_000_000, 2, 101);
    try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &bytes, bytes.len));
    try testing.expectEqual(@as(c_int, -EAGAIN), wal_submit(handle, &bytes, bytes.len));

    var frame = durable_frame(.live, now, now + 10_000_000_000, 5, 50, "/five", 5, 0, &.{});
    try testing.expectEqual(@as(c_int, 0), wal_durable_submit(handle, &frame, frame.len));
    try testing.expectEqual(@as(c_int, -EAGAIN), wal_durable_submit(handle, &frame, frame.len));

    // The flush_sync path drains the outstanding batches first, so the
    // shutdown is clean without an explicit pump. The flush's live set
    // matches the engine's mirror: BOTH ephemeral records (the first
    // generation's record 1 is still live — no tombstone was submitted
    // for it) and the durable frame.
    var live_set: [2 * wal_snapshot.record_size]u8 = undefined;
    @memcpy(live_set[0..wal_snapshot.record_size], &record_bytes_live(now, now + 10_000_000_000, 1, 100));
    @memcpy(live_set[wal_snapshot.record_size..], &bytes);
    try testing.expectEqual(@as(c_int, 0), wal_flush_sync(handle, &live_set, live_set.len, &frame, frame.len));
    _ = wal_status(handle, &status);
    // The generations: record 1's submit, record 2's submit, the flush's
    // own set — three ephemeral generations, four records; the durable
    // frame's submit and the flush's frame — two generations, two
    // records.
    try testing.expectEqual(@as(u64, 3), status.ephemeral.completed_generations);
    try testing.expectEqual(@as(u64, 4), status.ephemeral.completed_records);
    try testing.expectEqual(@as(u64, 2), status.durable.completed_generations);
    try testing.expectEqual(@as(u64, 2), status.durable.completed_records);
    try testing.expectEqual(@as(u32, 0), status.ephemeral.in_flight);
    try testing.expectEqual(@as(u32, 0), status.durable.in_flight);
}

test "wal c: frame encode/decode round trip through the ABI (one codec)" {
    var bytes: [wal_snapshot.fat_frame_size]u8 = undefined;
    const record = durable_fields(.live, 111, 222, 7, 70);
    try testing.expectEqual(@as(c_int, 0), wal_frame_encode(&bytes, bytes.len, &record, "/seven", 6, 1_700_000_000_000, 3, "lane-a\nlane-b", 13));

    var mirror: wal_snapshot.FatFrame = undefined;
    try testing.expectEqual(@as(c_int, 0), wal_frame_decode(&mirror, &bytes, bytes.len));
    try testing.expectEqual(@intFromEnum(wal_snapshot.DurableKind.live), mirror.header.tag);
    try testing.expectEqual(@as(u64, 111), mirror.header.stamp);
    try testing.expectEqual(@as(u64, 222), mirror.header.expiry);
    try testing.expectEqual(@as(u64, 7), mirror.header.lock_id);
    try testing.expectEqual(@as(u64, 70), mirror.header.lease_id);
    try testing.expectEqualSlices(u8, &Holder, &mirror.header.holder);
    try testing.expectEqual(Window, mirror.header.lease_ms);
    try testing.expectEqualSlices(u8, "/seven", mirror.name());
    try testing.expectEqual(@as(u64, 1_700_000_000_000), mirror.taken_at_ms());
    try testing.expectEqual(@as(u32, 3), mirror.renew_count());
    try testing.expectEqualSlices(u8, "lane-a\nlane-b", mirror.tag_bytes());

    // A kept frame round trips too, and re-encoding the decoded frame's
    // content reproduces the bytes bit for bit (the codec is
    // deterministic).
    var kept: [wal_snapshot.fat_frame_size]u8 = undefined;
    const kept_record = durable_fields(.kept, 9, 0, 8, 80);
    try testing.expectEqual(@as(c_int, 0), wal_frame_encode(&kept, kept.len, &kept_record, "/eight", 6, 5, 0, &.{}, 0));
    var kept_mirror: wal_snapshot.FatFrame = undefined;
    try testing.expectEqual(@as(c_int, 0), wal_frame_decode(&kept_mirror, &kept, kept.len));
    try testing.expectEqual(@intFromEnum(wal_snapshot.DurableKind.kept), kept_mirror.header.tag);
    var again: [wal_snapshot.fat_frame_size]u8 = undefined;
    try testing.expectEqual(@as(c_int, 0), wal_frame_encode(&again, again.len, &kept_mirror.header, kept_mirror.name().ptr, kept_mirror.name().len, kept_mirror.taken_at_ms(), kept_mirror.renew_count(), kept_mirror.tag_bytes().ptr, kept_mirror.tag_bytes().len));
    try testing.expectEqualSlices(u8, &kept, &again);
}

test "wal c: frame encode/decode refusals" {
    var bytes: [wal_snapshot.fat_frame_size]u8 = undefined;
    const good = wal_snapshot.durable_record(.live, 1, 2, 7, 70, Holder, Window);

    // Encode: a zero lock id, an unknown kind code, oversize name and
    // tag bytes, a null byte buffer under a nonzero length.
    var zero_lock = good;
    zero_lock.lock_id = 0;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_encode(&bytes, bytes.len, &zero_lock, "/x", 2, 0, 0, &.{}, 0));
    var unknown_tag = good;
    unknown_tag.tag = 7;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_encode(&bytes, bytes.len, &unknown_tag, "/x", 2, 0, 0, &.{}, 0));
    var too_long_name = good;
    try testing.expectEqual(
        @as(c_int, -EINVAL),
        wal_frame_encode(&bytes, bytes.len, &too_long_name, &.{}, wal_snapshot.fat_name_capacity + 1, 0, 0, &.{}, 0),
    );
    try testing.expectEqual(
        @as(c_int, -EINVAL),
        wal_frame_encode(&bytes, bytes.len, &good, "/x", 2, 0, 0, &.{}, wal_snapshot.fat_tag_bytes_capacity + 1),
    );
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_encode(&bytes, bytes.len, &good, null, 2, 0, 0, &.{}, 0));

    // A short buffer is refused whole; a null record pointer too.
    try testing.expectEqual(@as(c_int, -ENOBUFS), wal_frame_encode(&bytes, bytes.len - 1, &good, "/x", 2, 0, 0, &.{}, 0));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_encode(&bytes, bytes.len, null, "/x", 2, 0, 0, &.{}, 0));

    // Decode: wrong length, null out, rotted checksum, foreign format
    // version, unknown kind.
    const encoded = durable_frame(.live, 1, 2, 7, 70, "/seven", 5, 1, "lane-a");
    var mirror: wal_snapshot.FatFrame = undefined;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_decode(&mirror, &encoded, encoded.len - 1));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_decode(null, &encoded, encoded.len));

    var rotted = encoded;
    rotted[wal_snapshot.fat_sha_offset + 3] ^= 0xFF;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_decode(&mirror, &rotted, rotted.len));

    // The whole-frame checksum's own byte flips too: the deep integrity
    // layer refuses the same way.
    var deep = encoded;
    deep[wal_snapshot.checksum_data_offset] ^= 0xFF;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_decode(&mirror, &deep, deep.len));

    var foreign = encoded;
    foreign[wal_snapshot.tag_offset + 1] = 9;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_decode(&mirror, &foreign, foreign.len));

    var unknown_bytes = encoded;
    unknown_bytes[wal_snapshot.tag_offset] = 7;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_frame_decode(&mirror, &unknown_bytes, unknown_bytes.len));
}

test "wal c: durable submit and load round trip through the ABI" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const now = now_ns();
    {
        const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;

        // Cold start: both streams load as 1 (none).
        var probe: [wal_snapshot.fat_frame_size]u8 = undefined;
        var out_len: usize = 0;
        try testing.expectEqual(@as(c_int, 1), wal_load_durable(handle, &probe, probe.len, &out_len));

        var live = durable_frame(.live, now, now + 10_000_000_000, 5, 50, "/five", 1_700_000_000_000, 3, "lane-a\nlane-b");
        var kept = durable_frame(.kept, now + 1, 0, 6, 60, "/six", 1_700_000_000_001, 0, "lane-c");
        var batch: [2 * wal_snapshot.fat_frame_size]u8 = undefined;
        @memcpy(batch[0..wal_snapshot.fat_frame_size], &live);
        @memcpy(batch[wal_snapshot.fat_frame_size..], &kept);

        try testing.expectEqual(@as(c_int, 0), wal_durable_submit(handle, &batch, batch.len));
        if (!inline_completion) beat(handle);

        var status: WalStatus = undefined;
        try testing.expectEqual(@as(c_int, 0), wal_status(handle, &status));
        try testing.expectEqual(@as(u64, 1), status.durable.completed_generations);
        try testing.expectEqual(@as(u64, 2), status.durable.completed_records);
        try testing.expectEqual(@as(u32, 0), status.durable.in_flight);
        try testing.expectEqual(@as(u64, 0), status.ephemeral.completed_generations);
        try testing.expectEqual(@as(u64, 0), status.ephemeral.completed_records);
        wal_close(handle);
    }

    {
        const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
        defer wal_close(handle);

        // The ephemeral load answers none; the durable load answers with
        // the two frames, byte-exact through the codec.
        var eph_probe: [wal_snapshot.record_size]u8 = undefined;
        var eph_len: usize = 0;
        try testing.expectEqual(@as(c_int, 1), wal_load(handle, &eph_probe, eph_probe.len, &eph_len));

        var out: [2 * wal_snapshot.fat_frame_size]u8 = undefined;
        var out_len: usize = 0;
        try testing.expectEqual(@as(c_int, 0), wal_load_durable(handle, &out, out.len, &out_len));
        try testing.expectEqual(out.len, out_len);

        var seen: usize = 0;
        for (0..2) |i| {
            var frame: wal_snapshot.FatFrame = undefined;
            const raw: *const [wal_snapshot.fat_frame_size]u8 = out[i * wal_snapshot.fat_frame_size ..][0..wal_snapshot.fat_frame_size];
            try testing.expectEqual(@as(c_int, 0), wal_frame_decode(&frame, raw, raw.len));
            seen += 1;
            if (frame.header.lock_id == 5) {
                try testing.expectEqualSlices(u8, "/five", frame.name());
                try testing.expectEqual(@as(u64, 1_700_000_000_000), frame.taken_at_ms());
                try testing.expectEqual(@as(u32, 3), frame.renew_count());
                try testing.expectEqualSlices(u8, "lane-a\nlane-b", frame.tag_bytes());
            } else {
                try testing.expectEqualSlices(u8, "/six", frame.name());
                try testing.expectEqual(@as(u64, 1_700_000_000_001), frame.taken_at_ms());
                try testing.expectEqual(@as(u32, 0), frame.renew_count());
                try testing.expectEqualSlices(u8, "lane-c", frame.tag_bytes());
            }
        }
        try testing.expectEqual(@as(usize, 2), seen);

        // A too-small buffer is refused whole (-ENOBUFS), never partial.
        var small: [wal_snapshot.fat_frame_size]u8 = undefined;
        try testing.expectEqual(
            @as(c_int, -ENOBUFS),
            wal_load_durable(handle, &small, small.len, &out_len),
        );
    }
}

test "wal c: durable submit refusals — bad length, corrupt frame, capacity" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const handle = wal_open(path.ptr, 0) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    // Zero length and a non-multiple of the frame size are caller mistakes.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_durable_submit(handle, &.{}, 0));
    var one: [wal_snapshot.fat_frame_size]u8 = undefined;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_durable_submit(handle, &one, wal_snapshot.fat_frame_size + 1));

    // A corrupt frame (both integrity layers broken) is refused, nothing lands.
    const now = now_ns();
    var bytes = durable_frame(.live, now, now + 10_000_000_000, 1, 100, "/one", 5, 1, "lane-a");
    bytes[wal_snapshot.fat_name_offset] ^= 0xFF;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_durable_submit(handle, &bytes, bytes.len));
    try testing.expectEqual(@as(u64, 0), handle.dur.refusals);
}

test "wal c: durable capacity refusal counted on the durable row" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const handle = wal_open(path.ptr, 2) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    const now = now_ns();
    var a = durable_frame(.live, now, now + 10_000_000_000, 1, 100, "/one", 5, 0, &.{});
    var b = durable_frame(.live, now, now + 10_000_000_000, 2, 101, "/two", 6, 0, &.{});
    var batch: [2 * wal_snapshot.fat_frame_size]u8 = undefined;
    @memcpy(batch[0..wal_snapshot.fat_frame_size], &a);
    @memcpy(batch[wal_snapshot.fat_frame_size..], &b);
    try testing.expectEqual(@as(c_int, 0), wal_durable_submit(handle, &batch, batch.len));
    if (!inline_completion) beat(handle);

    // The live set fills the ring: the third lock is a counted refusal.
    var c = durable_frame(.live, now, now + 10_000_000_000, 3, 102, "/three", 7, 0, &.{});
    try testing.expectEqual(@as(c_int, -ENOSPC), wal_durable_submit(handle, &c, c.len));
    try testing.expectEqual(@as(u64, 1), handle.dur.refusals);
    try testing.expectEqual(@as(u64, 0), handle.eph.refusals);

    // The landed frames still complete normally.
    if (!inline_completion) beat(handle);
    var status: WalStatus = undefined;
    _ = wal_status(handle, &status);
    try testing.expectEqual(@as(u64, 2), status.durable.completed_records);
    try testing.expectEqual(@as(u32, 0), status.durable.in_flight);
}

test "wal c: flush_sync lands both streams, one fsync, reopen reads both" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const now = now_ns();
    {
        const handle = wal_open(path.ptr, 4) orelse return error.TestUnexpectedResult;

        var eph_batch: [2 * wal_snapshot.record_size]u8 = undefined;
        const a = record_bytes_live(now, now + 10_000_000_000, 1, 100);
        const b = record_bytes_live(now, now + 10_000_000_000, 2, 101);
        @memcpy(eph_batch[0..wal_snapshot.record_size], &a);
        @memcpy(eph_batch[wal_snapshot.record_size..], &b);
        try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &eph_batch, eph_batch.len));
        if (!inline_completion) beat(handle);

        var dur_batch: [1 * wal_snapshot.fat_frame_size]u8 = undefined;
        const frame = durable_frame(.live, now, now + 10_000_000_000, 5, 50, "/five", 5, 2, "lane-a");
        @memcpy(&dur_batch, &frame);
        try testing.expectEqual(@as(c_int, 0), wal_durable_submit(handle, &dur_batch, dur_batch.len));
        if (!inline_completion) beat(handle);

        // The shutdown generation: the caller's full live sets, both
        // streams, one fsync.
        try testing.expectEqual(
            @as(c_int, 0),
            wal_flush_sync(handle, &eph_batch, eph_batch.len, &dur_batch, dur_batch.len),
        );

        if (inline_completion) {
            try testing.expectEqual(@as(usize, 1), handle.wal.io.fsync_count);
        }
        var status: WalStatus = undefined;
        _ = wal_status(handle, &status);
        try testing.expectEqual(@as(u64, 2), status.ephemeral.completed_generations);
        try testing.expectEqual(@as(u64, 4), status.ephemeral.completed_records);
        try testing.expectEqual(@as(u64, 2), status.durable.completed_generations);
        try testing.expectEqual(@as(u64, 2), status.durable.completed_records);
        try testing.expectEqual(@as(u32, 0), status.ephemeral.in_flight);
        try testing.expectEqual(@as(u32, 0), status.durable.in_flight);
        wal_close(handle);
    }

    {
        const handle = wal_open(path.ptr, 4) orelse return error.TestUnexpectedResult;
        defer wal_close(handle);

        var out: [2 * wal_snapshot.record_size]u8 = undefined;
        var out_len: usize = 0;
        try testing.expectEqual(@as(c_int, 0), wal_load(handle, &out, out.len, &out_len));

        var dur_out: [1 * wal_snapshot.fat_frame_size]u8 = undefined;
        var dur_len: usize = 0;
        try testing.expectEqual(@as(c_int, 0), wal_load_durable(handle, &dur_out, dur_out.len, &dur_len));
        try testing.expectEqual(dur_out.len, dur_len);

        var frame: wal_snapshot.FatFrame = undefined;
        try testing.expectEqual(@as(c_int, 0), wal_frame_decode(&frame, &dur_out, dur_out.len));
        try testing.expectEqualSlices(u8, "/five", frame.name());
        try testing.expectEqual(@as(u64, 5), frame.taken_at_ms());
        try testing.expectEqual(@as(u32, 2), frame.renew_count());
        try testing.expectEqualSlices(u8, "lane-a", frame.tag_bytes());
        try testing.expect(frame.header.stamp >= now);
    }
}

test "wal c: flush_sync durable refusals — corruption, drift, capacity; the kept stand" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path_z(testing.allocator, &tmp);
    defer testing.allocator.free(path);

    const now = now_ns();
    const handle = wal_open(path.ptr, 2) orelse return error.TestUnexpectedResult;
    defer wal_close(handle);

    var frame = durable_frame(.live, now, now + 10_000_000_000, 1, 100, "/one", 5, 1, "lane-a");
    try testing.expectEqual(@as(c_int, 0), wal_durable_submit(handle, &frame, frame.len));
    if (!inline_completion) beat(handle);

    // A durable length that is not a multiple of the frame size.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &.{}, 0, &frame, frame.len - 1));

    // Corrupt durable bytes are refused before anything lands.
    var corrupt = frame;
    corrupt[wal_snapshot.fat_tag_bytes_offset] ^= 0xFF;
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &.{}, 0, &corrupt, corrupt.len));

    // Field drift on an existing durable lock (the renew counter differs)
    // is a divergence.
    var drifted = durable_frame(.live, now, now + 10_000_000_000, 1, 100, "/one", 5, 2, "lane-a");
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &.{}, 0, &drifted, drifted.len));

    // A durable lock the mirror does not hold is a divergence.
    var unknown = durable_frame(.live, now, now + 10_000_000_000, 9, 90, "/nine", 5, 1, &.{});
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &.{}, 0, &unknown, unknown.len));

    // A duplicate durable lock is a divergence.
    var dup: [2 * wal_snapshot.fat_frame_size]u8 = undefined;
    @memcpy(dup[0..wal_snapshot.fat_frame_size], &frame);
    @memcpy(dup[wal_snapshot.fat_frame_size..], &frame);
    try testing.expectEqual(@as(c_int, -EINVAL), wal_flush_sync(handle, &.{}, 0, &dup, dup.len));

    // An empty durable set against a non-empty mirror: the mirror's own
    // frames stand (they are already on disk — the load-then-lose case
    // the durable stream's kept semantics allow).
    try testing.expectEqual(@as(c_int, 0), wal_flush_sync(handle, &.{}, 0, &.{}, 0));
    try testing.expectEqual(@as(usize, 0), handle.dur.refusals);

    // Capacity: the durable pair's remaining room cannot take the set
    // (position 1, live 2 in the set... the set must reconcile first, so
    // fill the pair with a second lock, then flush the two-frame set).
    var second = durable_frame(.live, now, now + 10_000_000_000, 2, 101, "/two", 6, 0, &.{});
    try testing.expectEqual(@as(c_int, 0), wal_durable_submit(handle, &second, second.len));
    if (!inline_completion) beat(handle);
    var full: [2 * wal_snapshot.fat_frame_size]u8 = undefined;
    @memcpy(full[0..wal_snapshot.fat_frame_size], &frame);
    @memcpy(full[wal_snapshot.fat_frame_size..], &second);
    // position 2, live 2, capacity 2: 2 + 2 > 2 → the failed stop,
    // counted on the durable row.
    try testing.expectEqual(@as(c_int, -ENOSPC), wal_flush_sync(handle, &.{}, 0, &full, full.len));
    try testing.expectEqual(@as(u64, 1), handle.dur.refusals);
    try testing.expectEqual(@as(u64, 0), handle.eph.refusals);

    // The ephemeral row's capacity is its own: fill the ephemeral pair,
    // then the flush of the full ephemeral set overruns — counted on the
    // ephemeral row.
    var eph_a = record_bytes_live(now, now + 10_000_000_000, 1, 100);
    var eph_b = record_bytes_live(now, now + 10_000_000_000, 2, 101);
    try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &eph_a, eph_a.len));
    if (!inline_completion) beat(handle);
    try testing.expectEqual(@as(c_int, 0), wal_submit(handle, &eph_b, eph_b.len));
    if (!inline_completion) beat(handle);
    var eph_full: [2 * wal_snapshot.record_size]u8 = undefined;
    @memcpy(eph_full[0..wal_snapshot.record_size], &eph_a);
    @memcpy(eph_full[wal_snapshot.record_size..], &eph_b);
    try testing.expectEqual(@as(c_int, -ENOSPC), wal_flush_sync(handle, &eph_full, eph_full.len, &.{}, 0));
    try testing.expectEqual(@as(u64, 1), handle.eph.refusals);
    try testing.expectEqual(@as(u64, 1), handle.dur.refusals);
    if (inline_completion) {
        // Refused before anything landed: no fsync at all beyond the
        // clean flush above.
        try testing.expectEqual(@as(usize, 1), handle.wal.io.fsync_count);
    }
}

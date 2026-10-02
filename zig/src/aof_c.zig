//! The C ABI over the vendored TigerBeetle AOF (0.17.9).
//!
//! The ABI exposes the write-behind log's blocking surface:
//! open (create a file in a directory), append (wrap one record into an
//! AOFEntry with a fresh Prepare header and a valid Aegis checksum chain),
//! flush (the explicit checkpoint fsync), close, and the read-back iterator
//! the smoke tests use. The record bytes ride inside the AOF entry; the
//! on-disk format is byte-identical to upstream's AOF file layout, so the
//! vendored `Iterator` (per-entry header/body checksum validation and the
//! checksum chain) reads every file back.
//!
//! The force knob is a construction-time flag, exactly the "optional
//! durability force" contract: with force off (the default, and the mode
//! the standby learner runs in) appends are page-cached blocking writes and
//! durability lands only when the caller flushes — or when the entry
//! window reaches the vendored `journal_slot_count` cap, which preserves
//! upstream's "never buffer more than the WAL can hold" bound (here the
//! bound closes itself with a flush, since there is no WAL to borrow
//! durability from). With force on, every append is immediately followed
//! by the fsync — the upstream checkpoint's flush discipline applied per
//! entry.
const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;

const aof = @import("aof.zig");
const constants = @import("constants.zig");
const marker = @import("marker.zig");
const superblock = @import("vsr/superblock.zig");
const vsr = @import("vsr.zig");
const io_backend = @import("io.zig");

const AOF = aof.AOFType(io_backend.IO);
const Header = vsr.Header;
const IO = io_backend.IO;
const MessagePool = vsr.MessagePool;

const log = std.log.scoped(.aof_c);

/// The fine-grain log gate's build option (see build.zig's `-Dfine-logs`):
/// closed by default — the suite's stdout stays quiet unless asked.
const gate = @import("gate_options");

/// The module root's half of the fine-grain log gate: std.log's level is
/// pinned at `warn` unless the fine-logs option opens it, so every
/// `debug`- and `info`-level site in this module (the vendored AOF's
/// per-append chain detail, the vendored multiversion and superblock
/// machinery's chatter) compiles to nothing — std.log's level check is
/// comptime, so neither the line nor its formatting exists in a closed
/// build. Without the pin a Debug-mode cdylib (the build the Rust suite
/// links) defaults to `debug` and prints every one of them, raw, to
/// stderr. The marker store's warn-level refusals (the boot-read law's
/// loud logs) pass the pin and stay loud in every mode.
///
/// (A test build ignores this declaration — the compiler's test runner
/// owns std.log's options there — which is why the vendored quorum file
/// carries its own gate for the warn-level detail the runner would
/// print. The enforcing census test at the bottom of this file asserts
/// both gates exist.)
pub const std_options: std.Options = .{
    .log_level = if (gate.fine_logs) .debug else .warn,
};

/// One open AOF file plus the C ABI's own header-builder state: the entry
/// chain (each record's Prepare header names the previous entry's checksum
/// as its parent), the op counter, and the force knob. The message pool
/// carries the one Prepare message the append path re-uses.
pub const AofFile = struct {
    aof: AOF,
    io: *IO,
    pool: *MessagePool,
    op: u64,
    /// The open path, OWNED: the vendored AOF keeps the caller's slice
    /// verbatim, but a C-ABI caller's buffer may die immediately after
    /// `lunet_aof_open` returns (any FFI host, not just Rust) — the
    /// close-time checkpoint stats `self.path`, so the copy must outlive
    /// the handle.
    owned_path: []u8,
    /// Records appended since the last durable flush. The vendored write
    /// path keeps its own window counter with the same cap; this shadow
    /// drives the wrap-side flush when the force knob is off.
    unflushed: u64,
    force_flush: bool,
};

/// C ABI result codes. 0 is success; negative are errors.
pub const OK: i32 = 0;
pub const INVALID: i32 = -1;
pub const TOO_LARGE: i32 = -6;
pub const SERVICE: i32 = -7;
/// A readable marker copy failed its checksum: the boot-read law's
/// refusal (the Zig store's `error.ChecksumRot`). Distinct so the host
/// adapter can PANIC on it — a bad block is a loud log and a panic,
/// never a hang, never a clear, never a repair, never a fallback.
pub const CORRUPT: i32 = -11;
/// The marker file's format version is not the current one: an
/// old-format marker is invalid, never converted (the marker format's
/// bumps are legacy-free). Distinct so the host can tell "you are
/// pointing at an old-format marker" apart from rot.
pub const INCOMPATIBLE: i32 = -12;

/// Open (create or open, never truncate) an AOF file at `path`.
///
/// `force_flush` is the optional durability force: 0 (the default for the
/// telemetry standby) keeps appends page-cached, with durability only on
/// explicit flushes and at the entry-window cap; non-zero fsyncs after
/// every append. The path must end in `.aof` and its parent directory must
/// exist — the caller owns directory creation.
export fn lunet_aof_open(
    path_data: [*]const u8,
    path_len: usize,
    force_flush: u8,
    out: *?*AofFile,
) i32 {
    if (path_len == 0 or path_len > std.fs.max_path_bytes) return INVALID;
    if (force_flush > 1) return INVALID;
    const path = path_data[0..path_len];

    if (!std.mem.endsWith(u8, path, ".aof")) {
        return INVALID;
    }

    const io = std.heap.c_allocator.create(IO) catch return SERVICE;
    io.* = IO.init(32, 0) catch {
        std.heap.c_allocator.destroy(io);
        return SERVICE;
    };

    const pool = std.heap.c_allocator.create(MessagePool) catch {
        std.heap.c_allocator.destroy(io);
        return SERVICE;
    };
    pool.* = MessagePool.init_capacity(std.heap.c_allocator, 1) catch {
        std.heap.c_allocator.destroy(pool);
        std.heap.c_allocator.destroy(io);
        return SERVICE;
    };

    const owned_path = std.heap.c_allocator.dupe(u8, path) catch {
        std.heap.c_allocator.destroy(pool);
        std.heap.c_allocator.destroy(io);
        return SERVICE;
    };
    const file = std.heap.c_allocator.create(AofFile) catch {
        std.heap.c_allocator.free(owned_path);
        std.heap.c_allocator.destroy(pool);
        std.heap.c_allocator.destroy(io);
        return SERVICE;
    };
    file.* = .{
        .aof = AOF.init(io, owned_path) catch {
            std.heap.c_allocator.free(owned_path);
            std.heap.c_allocator.destroy(file);
            std.heap.c_allocator.destroy(pool);
            std.heap.c_allocator.destroy(io);
            return SERVICE;
        },
        .io = io,
        .pool = pool,
        .op = 0,
        .unflushed = 0,
        .owned_path = owned_path,
        .force_flush = force_flush != 0,
    };
    out.* = file;
    return OK;
}

/// Append one record. The record bytes become the body of a fresh Prepare
/// entry: the header carries the AOF's chain (parent = the previous
/// entry's checksum), a monotonic op, the current unix-milliseconds
/// timestamp, and valid Aegis checksums — the exact on-disk shape an
/// upstream `aof debug` run parses.
export fn lunet_aof_append(
    file: *AofFile,
    data: [*]const u8,
    len: usize,
    out_op: ?*u64,
) i32 {
    if (len > constants.message_body_size_max) return TOO_LARGE;
    if (file.unflushed >= constants.journal_slot_count) return SERVICE;

    const message = file.pool.get_message(.prepare);
    defer file.pool.unref(message);

    header: {
        message.header.* = .{
            .op = file.op + 1,
            .commit = 0,
            .view = 0,
            .client = 0,
            .request = 0,
            .parent = file.aof.last_checksum orelse 0,
            .request_checksum = 0,
            .cluster = 0,
            .timestamp = @intCast(@max(std.time.milliTimestamp(), 0)),
            .checkpoint_id = 0,
            .release = vsr.Release.minimum,
            .command = .prepare,
            .operation = .pulse,
            .size = @intCast(@sizeOf(Header) + len),
        };
        break :header;
    }
    @memcpy(message.body_used(), data[0..len]);
    message.header.set_checksum_body(data[0..len]);
    message.header.set_checksum();

    file.aof.write(message) catch |err| {
        log.warn("aof append failed: {}", .{err});
        return SERVICE;
    };

    file.op = message.header.op;
    file.unflushed += 1;
    if (out_op) |op| op.* = message.header.op;

    if (file.force_flush or file.unflushed >= constants.journal_slot_count) {
        return flush(file);
    }
    return OK;
}

/// The explicit flush: one fsync through the vendored checkpoint path.
/// `AOF.checkpoint` hands its completion to `IO.fsync`, which is blocking
/// in this backend, so the checkpoint completes synchronously.
export fn lunet_aof_flush(file: *AofFile) i32 {
    return flush(file);
}

fn flush(file: *AofFile) i32 {
    file.aof.checkpoint(
        @ptrCast(&flush_state),
        struct {
            fn callback(_: *anyopaque) void {
                // The blocking fsync has completed: AOF.on_fsync already
                // reset the unflushed window; the flag reports completion
                // only after the inode-change checks ran.
                flush_state.done = true;
            }
        }.callback,
    );
    if (!flush_state.done) return SERVICE;
    file.unflushed = 0;
    return OK;
}

/// The synchronous flush flag the checkpoint callback sets. The blocking
/// IO backend serializes checkpoints, so one static flag is safe: the C
/// ABI surface is documented as single-threaded (the lease-sequencer host
/// drives it from the UDP pump's thread).
var flush_state = struct {
    done: bool = false,
}{};

export fn lunet_aof_close(file: *AofFile) i32 {
    // Graceful close: the checkpoint flush lands, then the fd releases.
    const rc = flush(file);
    file.aof.close();
    std.heap.c_allocator.free(file.owned_path);
    std.heap.c_allocator.destroy(file);
    if (rc != OK) return rc;
    return OK;
}

/// The read-back iterator over an AOF file: per-entry header/body checksum
/// validation plus the checksum chain, upstream semantics verbatim. One
/// entry per call; the body bytes land in `out_data` and the entry's op in
/// `out_op`. Call repeatedly until it reports 0 (end of file).
export fn lunet_aof_iter_open(
    path_data: [*]const u8,
    path_len: usize,
    out: *?*AofIter,
) i32 {
    if (path_len == 0 or path_len > std.fs.max_path_bytes) return INVALID;
    const path = path_data[0..path_len];

    const io = std.heap.c_allocator.create(IO) catch return SERVICE;
    io.* = IO.init(32, 0) catch {
        std.heap.c_allocator.destroy(io);
        return SERVICE;
    };

    const it = std.heap.c_allocator.create(AofIter) catch {
        std.heap.c_allocator.destroy(io);
        return SERVICE;
    };
    it.* = .{
        .iterator = AOF.Iterator.init(io, path) catch {
            std.heap.c_allocator.destroy(it);
            std.heap.c_allocator.destroy(io);
            return SERVICE;
        },
        .io = io,
    };
    out.* = it;
    return OK;
}

pub const AofIter = struct {
    iterator: AOF.Iterator,
    io: *IO,
    entry: aof.AOFEntry align(constants.sector_size) = undefined,
};

export fn lunet_aof_iter_next(
    it: *AofIter,
    out_data: [*]u8,
    cap: usize,
    out_len: *usize,
    out_op: *u64,
) i32 {
    const entry = (it.iterator.next(&it.entry) catch |err| switch (err) {
        error.AOFShortRead => return 0, // Torn tail: a partial final entry ends iteration.
        error.AOFMagicNumberMismatch,
        error.AOFChecksumMismatch,
        error.AOFBodyChecksumMismatch,
        error.AOFChecksumChainMismatch,
        => return SERVICE,
        else => return SERVICE,
    }) orelse return 0;

    const body = it.entry.message[@sizeOf(Header)..entry.header().size];
    if (body.len > cap) return TOO_LARGE;
    @memcpy(out_data[0..body.len], body);
    out_len.* = @intCast(body.len);
    out_op.* = entry.header().op;
    return 1;
}

export fn lunet_aof_iter_close(it: *AofIter) void {
    it.iterator.close();
    std.heap.c_allocator.destroy(it);
}

// ---------------------------------------------------------------------------
// The lifecycle marker surface (the superblock copies' quorum construction).
//
// The marker is the uVRR I/O obligations' termination chapter's lifecycle
// marker (docs/uvrr-io-obligations.md §2-§4): `unflushed` (the
// running sentinel) → `stopped` (termination begins; the wire closed
// before this write) → `flushed` (the durable-state write completed at the
// drain point). The storage is the vendored superblock copies
// construction — `marker.zig` for the details: four fixed sector-aligned
// Aegis-checksummed copies, hash-chained sequence/parent, quorum write
// verified at the `.verify` threshold (3/4), quorum read resolving by
// highest sequence at the `.open` threshold (2/4), forced I/O (the fsync
// lands before the write reports success).
//
// The single-threaded discipline applies verbatim (see the flush flag
// below): marker calls stay on the caller's thread; no threads are
// spawned, and every call opens, drives, and closes its own store.
// ---------------------------------------------------------------------------

/// The marker zone geometry: copy count and per-copy byte size. A C-ABI
/// host derives its own diagnostic offsets from this (e.g. to rot one copy
/// in a fault test) instead of hard-coding the vendored layout.
export fn lunet_aof_marker_geometry(
    out_copies: ?*usize,
    out_copy_size: ?*usize,
) i32 {
    if (out_copies) |p| p.* = marker.copies_count;
    if (out_copy_size) |p| p.* = marker.copy_size;
    return OK;
}

/// One lifecycle transition: quorum-write `(node, state)` into the
/// marker file at `path` (creating it, never truncating it), forced I/O,
/// verify read-back — one completable marker round (the fsync lands
/// before the call reports success), the act a host completes before its
/// first emission. `node` is the packed identity pair
/// {systemIdentifier, crashCounter} (MSB system, LSB crash): the halves
/// never cross the ABI individually, and a zero half refuses at the edge
/// (the pair is one-indexed). Returns INVALID for a state code outside
/// the lifecycle, a zero identity half, or a crash counter that would
/// regress the marker; CORRUPT for a different system identifier on an
/// existing marker (corruption, not an overwrite); SERVICE for every
/// storage-level failure (quorum lost, fork, I/O).
export fn lunet_aof_marker_write(
    path_data: [*]const u8,
    path_len: usize,
    node: u32,
    state: u32,
) i32 {
    if (path_len == 0 or path_len > std.fs.max_path_bytes) return INVALID;
    const marker_state = marker.State.from_code(state) orelse return INVALID;
    const system = marker.system_of(node);
    const crash = marker.crash_of(node);
    if (system == 0 or crash == 0) return INVALID;
    const path = path_data[0..path_len];

    var store = marker.MarkerStore.open(path, std.heap.c_allocator) catch |err| {
        return marker_error(err);
    };
    defer store.close(std.heap.c_allocator);
    store.write(system, crash, marker_state) catch |err| return marker_error(err);
    return OK;
}

/// The boot classification: read the marker's working quorum (the
/// `.open` threshold) and report its `(node, state)` — the packed
/// identity pair and the lifecycle state. The caller classifies:
/// `stopped`/`flushed` → a clean continue under the same identity;
/// `unflushed` → the running sentinel → a DIRTY bump (one marker write,
/// durable before the first emission — the host's flush-before-announce
/// gate is exactly one `lunet_aof_marker_write` call). SERVICE covers
/// every unreadable-marker shape (no quorum, fork, rotted copies) — the
/// caller refuses the boot rather than guessing an identity.
export fn lunet_aof_marker_classify(
    path_data: [*]const u8,
    path_len: usize,
    out_node: *u32,
    out_state: *u32,
) i32 {
    if (path_len == 0 or path_len > std.fs.max_path_bytes) return INVALID;
    const path = path_data[0..path_len];

    var store = marker.MarkerStore.open(path, std.heap.c_allocator) catch |err| {
        return marker_error(err);
    };
    defer store.close(std.heap.c_allocator);
    const classified = store.classify() catch |err| return marker_error(err);
    out_node.* = marker.pack(classified.system, classified.crash);
    out_state.* = @intFromEnum(classified.state);
    return OK;
}

fn marker_error(err: anyerror) i32 {
    return switch (err) {
        error.CrashCounterRegressed => INVALID,
        // A zero identity half refused at the write's edge (the pair is
        // one-indexed): the caller's mistake, not the store's.
        error.ZeroIdentity => INVALID,
        // A different system identifier on an existing marker:
        // corruption, not an overwrite — the boot-read law's distinct
        // code, the host adapter panics on it.
        error.SystemMismatch => CORRUPT,
        // An old-format marker is invalid, never converted (legacy-free).
        error.IncompatibleVersion => INCOMPATIBLE,
        // Checksum-class corruption (a rotted checksum, or a
        // checksum-valid copy whose state string disagrees with its
        // numeric state): the boot-read law's distinct code — the host
        // adapter panics on it.
        error.ChecksumRot, error.StateStringDisagreement => CORRUPT,
        else => SERVICE,
    };
}

/// The byte offset of the marker header's on-disk state string (the
/// fixed-width, space-padded name) within one copy zone: where a raw
/// hexdump of a written block reads the state. The offset of the vendored
/// header's `state_string` field, exported so a C-ABI host never
/// hard-codes the vendored layout.
export fn lunet_aof_marker_state_string_offset() usize {
    return @offsetOf(superblock.SuperBlockHeader, "state_string");
}

/// One copy's raw facts for the inspect export: everything the
/// `lunet_locks_nuke` admin tool prints about the marker store's copies.
/// Pure diagnostics — the store itself is never mutated by an inspect.
pub const CopyInfo = extern struct {
    /// The zone read a full header.
    readable: u8,
    /// The header's checksum verifies (only meaningful when readable).
    valid_checksum: u8,
    sequence: u64,
    /// The raw lifecycle-state code (may be outside the lifecycle).
    state: u32,
    /// The packed identity pair (MSB system, LSB crash) as the copy
    /// carries it — a zero half on a checksum-valid copy is corruption
    /// (the read paths refuse; the inspect reports the raw fact).
    node: u32,
    checksum_lo: u64,
    checksum_hi: u64,
};

/// The marker store's per-copy raw facts (read-only, never
/// classified): the `lunet_locks_nuke` admin tool's view of the four
/// copies — presence, checksum status, sequence, state code, identity
/// pair. Missing zones read as `readable = 0` with the remaining fields
/// zero. A missing file reports SERVICE; the caller distinguishes with
/// its own existence check.
export fn lunet_aof_marker_inspect(
    path_data: [*]const u8,
    path_len: usize,
    out: [*]CopyInfo,
) i32 {
    if (path_len == 0 or path_len > std.fs.max_path_bytes) return INVALID;
    const path = path_data[0..path_len];
    const file = std.fs.cwd().openFile(path, .{}) catch return SERVICE;
    defer file.close();

    const header = std.heap.c_allocator.alignedAlloc(
        superblock.SuperBlockHeader,
        constants.sector_size,
        1,
    ) catch return SERVICE;
    defer std.heap.c_allocator.free(header);

    for (0..marker.copies_count) |index| {
        const bytes = mem.asBytes(&header[0]);
        const read = file.preadAll(bytes, marker.copy_size * index) catch return SERVICE;
        if (read < marker.copy_header_bytes) {
            out[index] = mem.zeroes(CopyInfo);
            continue;
        }
        out[index] = .{
            .readable = 1,
            .valid_checksum = @intFromBool(header[0].valid_checksum()),
            .sequence = header[0].sequence,
            .state = header[0].vsr_state.sync_view,
            .node = marker.pack(header[0].system_identifier, header[0].crash_counter),
            .checksum_lo = @truncate(header[0].checksum),
            .checksum_hi = @truncate(header[0].checksum >> 64),
        };
    }
    return OK;
}

/// The `lunet_locks_nuke` admin tool's deliberate reset: re-format the marker file FRESH at
/// sequence 1 with the named `(node, state)` — four copies,
/// forced I/O, verify read-back. An explicit operator action (the tool's
/// own review gate confirms it), never a boot-read repair: no read path
/// formats over anything, and the reset is the one path that re-seats a
/// marker to a different system identifier. INVALID for a state code
/// outside the lifecycle or a zero identity half; CORRUPT/SERVICE per
/// the store's refusals.
export fn lunet_aof_marker_format(
    path_data: [*]const u8,
    path_len: usize,
    node: u32,
    state: u32,
) i32 {
    if (path_len == 0 or path_len > std.fs.max_path_bytes) return INVALID;
    const marker_state = marker.State.from_code(state) orelse return INVALID;
    const system = marker.system_of(node);
    const crash = marker.crash_of(node);
    if (system == 0 or crash == 0) return INVALID;
    const path = path_data[0..path_len];

    var store = marker.MarkerStore.open(path, std.heap.c_allocator) catch |err| {
        return marker_error(err);
    };
    defer store.close(std.heap.c_allocator);
    store.format(system, crash, marker_state) catch |err| return marker_error(err);
    return OK;
}

// -------------------------------------------------------------------
// The fine-grain log census.
//
// The suite's finest-grain trace detail — the per-copy and per-quorum
// checksum lines the vendored quorum machinery logs, and every log line
// below `warn` — never prints unless a build asks for it. Two gates hold
// that law and both are asserted here, the same shape as the host
// adapter's lifecycle-path census (`every path through boot and stop
// names itself`): the gates must exist, and the census of fine-grain
// sites the sources carry must equal the census declared here. A new
// fine-grain site outside the gated paths fails this test naming its
// file; a declared count no source carries fails it too.
//
// - The module root pins std.log's level at `warn` unless the fine-logs
//   gate opens: every `debug`- and `info`-level site in the module
//   compiles to nothing (std.log's level check is comptime, so neither
//   the line nor its formatting exists in a closed build). Without the
//   pin, a Debug-mode cdylib — the build the Rust suite links — prints
//   every one of them, raw, straight to stderr.
// - The vendored `vsr/superblock_quorums.zig` carries its own comptime
//   gate: its per-copy detail is trace, not operator output, and the
//   test runner the `zig build test` step uses prints warn-level lines
//   through the runner's own log fn (the module root's pin cannot
//   reach it), so the file's warn sites are gated at their own edge.
//
// The marker store's warn lines are NOT fine grain: they are the
// boot-read law's loud refusals (a bad checksum on any copy is a loud
// log, and the non-unanimity at the moment of resolution is logged in
// full) — the store's only voice, since the C ABI carries its refusals
// as distinct codes the host adapter panics on.
// -------------------------------------------------------------------

/// One compiled source file of this module (the module rooted here),
/// with its declared count of fine-grain log sites.
const CensusFile = struct {
    name: []const u8,
    source: []const u8,
    /// The `debug`- and `info`-level log call sites — the levels the
    /// module root's pin discards at comptime.
    below_warn: usize,
    /// The `warn`-level sites of the one file whose warn detail is
    /// fine grain (the vendored quorum file's per-copy lines); every
    /// other file's warn lines are the loud operator law.
    fine_warn: usize,
};

/// The census's ground truth: every source file of the module that can
/// emit a log line (the vendored `stdx` extension module is a separate
/// compilation whose sites are unreachable from this module's code).
const census_files = [_]CensusFile{
    .{ .name = "aof_c.zig", .source = @embedFile("aof_c.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "aof.zig", .source = @embedFile("aof.zig"), .below_warn = 5, .fine_warn = 0 },
    .{ .name = "config.zig", .source = @embedFile("config.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "constants.zig", .source = @embedFile("constants.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "io.zig", .source = @embedFile("io.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "io/common.zig", .source = @embedFile("io/common.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "lsm/schema.zig", .source = @embedFile("lsm/schema.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "marker.zig", .source = @embedFile("marker.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "message_pool.zig", .source = @embedFile("message_pool.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "multiversion.zig", .source = @embedFile("multiversion.zig"), .below_warn = 7, .fine_warn = 0 },
    .{ .name = "stack.zig", .source = @embedFile("stack.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "tigerbeetle.zig", .source = @embedFile("tigerbeetle.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "vsr.zig", .source = @embedFile("vsr.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "vsr/checksum.zig", .source = @embedFile("vsr/checksum.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "vsr/message_header.zig", .source = @embedFile("vsr/message_header.zig"), .below_warn = 0, .fine_warn = 0 },
    .{ .name = "vsr/superblock.zig", .source = @embedFile("vsr/superblock.zig"), .below_warn = 8, .fine_warn = 0 },
    .{ .name = "vsr/superblock_quorums.zig", .source = @embedFile("vsr/superblock_quorums.zig"), .below_warn = 2, .fine_warn = 5 },
};

/// The vendored quorum file: the one source whose warn-level detail is
/// fine grain (every copy of every quorum read, logged).
const census_quorum_file = "vsr/superblock_quorums.zig";

/// The crate-owned files (not vendored): a raw print in our own code is
/// a fine-grain site outside every gate.
const census_owned = [_][]const u8{ "aof_c.zig", "marker.zig", "io.zig" };

/// One failed census assertion: logged at warn (the runner prints warn
/// lines, and a Debug-mode cdylib pins its level at warn too), then
/// returned as the test's error.
fn census_fail(comptime format: []const u8, args: anytype) anyerror!void {
    std.log.scoped(.census).warn(format, args);
    return error.TestFineGrainLogCensus;
}

fn census_count(source: []const u8, needle: []const u8) usize {
    var total: usize = 0;
    var cursor: usize = 0;
    while (std.mem.indexOfPos(u8, source, cursor, needle)) |found| {
        total += 1;
        cursor = found + needle.len;
    }
    return total;
}

// The ask-in: `-Dfine-logs=true` re-opens the fine grain for a test run.
// The compiler's test runner owns std.log's options in a test build and
// filters at its own `std.testing.log_level` (warn by default), so the
// runner's filter rises here — the root file's tests are collected and
// run first, before any other file's tests log.
test {
    if (gate.fine_logs) std.testing.log_level = .debug;
}

test "the fine-grain log census: every site behind a gate, every gate declared" {
    // The needles are assembled at run time so this scanner's own
    // source carries no literal site for any of them to count.
    const debug_site = "log.de" ++ "bug(";
    const info_site = "log.in" ++ "fo(";
    const warn_site = "log.wa" ++ "rn(";
    const raw_print = "std.debug.pr" ++ "int(";
    const raw_stdout = "getStd" ++ "Out(";
    const raw_stderr = "getStd" ++ "Err(";
    const root_gate = "std_opt" ++ "ions: std.Options";
    const root_pin = ".log_level = if (gate.fine_logs) .debug e" ++ "lse .warn";
    const quorum_gate = "const log = if (gate.fine_" ++ "logs) std.log.scoped(.superblock_quorums) else quiet_log;";

    // The census: every fine-grain site is declared, two ways — a site
    // the sources carry that the census does not declare is a print
    // nobody gated; a declared count no source carries is a census
    // gone stale.
    for (census_files) |entry| {
        const below = census_count(entry.source, debug_site) +
            census_count(entry.source, info_site);
        if (below != entry.below_warn) {
            return census_fail(
                "fine-grain census: {s} carries {d} below-warn sites, the census declares {d} — declare or delete them",
                .{ entry.name, below, entry.below_warn },
            );
        }
        if (std.mem.eql(u8, entry.name, census_quorum_file)) {
            const warns = census_count(entry.source, warn_site);
            if (warns != entry.fine_warn) {
                return census_fail(
                    "fine-grain census: {s} carries {d} fine-warn sites, the census declares {d} — declare or delete them",
                    .{ entry.name, warns, entry.fine_warn },
                );
            }
        }
        // A raw debug print anywhere in the module bypasses every gate.
        if (census_count(entry.source, raw_print) != 0) {
            return census_fail(
                "fine-grain census: {s} carries a raw debug print outside every gate",
                .{entry.name},
            );
        }
    }
    for (census_owned) |name| {
        for (census_files) |entry| {
            if (!std.mem.eql(u8, entry.name, name)) continue;
            if (census_count(entry.source, raw_stdout) != 0 or
                census_count(entry.source, raw_stderr) != 0)
            {
                return census_fail(
                    "fine-grain census: {s} (crate-owned) writes to a raw stream outside every gate",
                    .{name},
                );
            }
        }
    }

    // The module root's level pin: without it a Debug-mode cdylib (the
    // build the Rust suite links) prints every below-warn site, raw, to
    // stderr. Name every ungated site on the way out.
    const root = census_files[0].source;
    var gates_missing = false;
    if (std.mem.indexOf(u8, root, root_gate) == null or
        std.mem.indexOf(u8, root, root_pin) == null)
    {
        gates_missing = true;
        for (census_files) |entry| {
            if (entry.below_warn != 0) {
                std.log.scoped(.census).warn(
                    "fine-grain census: the module root pins no std.log level — {s} carries {d} below-warn sites that print raw in every Debug-mode build",
                    .{ entry.name, entry.below_warn },
                );
            }
        }
    }

    // The vendored quorum file's own gate: its per-copy detail is trace,
    // and the test run prints warn lines through the runner's log fn —
    // only the file's comptime gate reaches them.
    for (census_files) |entry| {
        if (!std.mem.eql(u8, entry.name, census_quorum_file)) continue;
        if (std.mem.indexOf(u8, entry.source, quorum_gate) == null) {
            gates_missing = true;
            std.log.scoped(.census).warn(
                "fine-grain census: {s} gates no fine-grain log — its {d} warn and {d} below-warn sites (the per-copy checksum detail) print in every test run",
                .{ entry.name, entry.fine_warn, entry.below_warn },
            );
        }
    }
    if (gates_missing) return error.TestFineGrainLogCensus;
}

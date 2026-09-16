//! The lifecycle marker store: the uVRR termination obligations' marker
//! (the contract's §4 "quorum of copies" construction) built on the
//! vendored superblock copies.
//!
//! The marker records one lifecycle state (the running sentinel, stopped,
//! flushed) plus the replica's incarnation. Its storage is the vendored
//! TigerBeetle superblock construction, applied the way the contract
//! describes it (`docs/uvrr-termination-obligations-v0.6.1.md` §4, citing
//! Lampson & Sturgis 1979 §5.1, "the good, the complete, or the newest"):
//!
//! - `constants.superblock_copies` (4) copies of a `SuperBlockHeader` in
//!   fixed, sector-aligned zones of one marker file (`copy_size` apart),
//!   each carrying an Aegis checksum (`vsr.checksum`, the on-disk checksum
//!   contract) and a hash-chained `sequence`/`parent` pair — a torn,
//!   misdirected, or rotted copy is detectable rather than trusted.
//! - Quorum writes and quorum reads through the vendored
//!   `superblock_quorums.zig` flexible quorums, verbatim: a write is
//!   verified with the `.verify` threshold (3/4), a read works from the
//!   `.open` threshold (2/4) resolving by highest sequence. A single lying
//!   or stale copy cannot decide the read, and a write that did not reach
//!   its quorum is invisible to it — which is exactly the contract's
//!   marker-write rule: a death partway through a marker write leaves the
//!   advanced copies truthful (a completed write reads as the newer
//!   state) and a non-quorum write invisible (the read resolves to the
//!   older state).
//! - Forced I/O: every quorum write fsyncs the marker file (and the
//!   containing directory when the file is first created) before it
//!   reports success. The write-ordering hook — the marker only after the
//!   data write completes — is the caller's drain discipline: the
//!   adapter's stop path drains the durable-state sink before it writes
//!   `flushed`.
//!
//! Where the lifecycle rides the header: the vendored build carries no VSR
//! state machine, so the marker uses two `VSRState` fields the AOF-only
//! build never drives — `commit_max` carries the incarnation (monotonic:
//! a clean continue keeps it, a dirty boot bumps it, so the header's
//! monotonic checks hold) and `sync_view` (state-sync-only, asserted zero
//! nowhere) carries the lifecycle state. Both are inside the header
//! checksum, so a marker copy is tamper-evident as a whole. A boot
//! classification reads the working quorum's header: `stopped`/`flushed`
//! is a controlled ending, `unflushed` (the running sentinel) is a crash —
//! the adapter's classification logic is unchanged; only its storage
//! moved here.
//!
//! Fail-closed discipline: a write whose verify read-back fails, and a
//! read with no valid working quorum, are errors — the caller refuses
//! rather than guessing an identity. Deleting a rotted marker file is the
//! recovery path: the host then re-seeds from its own compatibility
//! projection (the adapter's single marker file, which lags the copies by
//! at most one transition and can therefore only ever classify more
//! conservatively).
const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const posix = std.posix;

const constants = @import("constants.zig");
const vsr = @import("vsr.zig");
const superblock = @import("vsr/superblock.zig");

const SuperBlockHeader = superblock.SuperBlockHeader;
const Quorums = superblock.Quorums;

/// The marker zone layout: the vendored superblock copies, verbatim sizing.
pub const copies_count = constants.superblock_copies;
pub const copy_size = superblock.superblock_copy_size;
/// The bytes of one copy that the store writes and reads: the header
/// itself (`copy_size` additionally carries the zone's reserved padding).
pub const copy_header_bytes = @sizeOf(SuperBlockHeader);

/// The marker's fixed cluster/replica identity: a marker file is
/// per-replica local storage, so the identity only needs to be stable,
/// nonzero, and equal across copies (the quorum machinery's cross-quorum
/// checks compare them).
const marker_cluster: u128 = 0x6c756e65742d6d61726b6572;
const marker_replica_id: u128 = 0x6d61726b65722d31;

/// The lifecycle marker's states, upstream-style, with the on-disk codes
/// the C ABI (and the adapter's compatibility projection) spell. The
/// running sentinel stays spelled `unflushed` on disk — the contract's
/// `running` — so every existing rig marker boots unchanged.
pub const State = enum(u32) {
    /// The running sentinel: the process has been (or is) operating.
    unflushed = 0,
    /// Termination has begun: the wire was closed before this write, so
    /// the state beneath the marker is final.
    stopped = 1,
    /// The durable-state write completed at the drain point.
    flushed = 2,

    pub fn from_code(code: u32) ?State {
        if (code > @intFromEnum(State.flushed)) return null;
        return @enumFromInt(code);
    }
};

pub const Classified = struct {
    state: State,
    incarnation: u64,
};

pub const Error = error{
    /// No valid marker copy at all: the file is fresh, empty, or fully
    /// rotted. A read reports this so the caller can fall back to its
    /// compatibility projection; a write takes it as license to format.
    NotFound,
    /// Valid copies exist but no read quorum: fail closed.
    QuorumLost,
    /// Two valid copies at the same sequence disagree: the marker forked.
    Fork,
    /// A valid quorum at sequence N+1 does not chain from the quorum at N.
    ParentNotConnected,
    /// A valid quorum exists at sequence N+2+ with no connectable parent.
    ParentSkipped,
    /// The parent quorum's state is not monotonic with the newer quorum.
    VSRStateNotMonotonic,
    /// The working quorum's state code is not a lifecycle state.
    InvalidState,
    /// A write refused: the incarnation would regress the marker.
    IncarnationRegressed,
    /// A write refused: the marker file's copies rotted beyond the read
    /// quorum (delete the file to re-seed from the compatibility
    /// projection).
    Unformatted,
    FileOpenFailed,
    ReadFailed,
    WriteFailed,
    SyncFailed,
    DirectorySyncFailed,
};

/// The working quorum's facts a marker operation needs: the hash-chain
/// position (sequence, checksum) and the marker payload (incarnation,
/// state).
const Working = struct {
    sequence: u64,
    checksum: u128,
    incarnation: u64,
    /// The raw lifecycle-state code as read from the working header
    /// (validated into a `State` by `classify`).
    state: u32,
};

/// The marker store over one marker file: the four-copy superblock zone.
/// Opened, driven, and closed on the caller's thread (the C ABI's
/// single-threaded discipline — no threads are spawned here).
pub const MarkerStore = struct {
    file: std.fs.File,
    /// The owned marker file path (for the first-write directory sync).
    path: []u8,
    /// Whether the marker file already existed when opened.
    existed: bool,
    /// The read-back buffers (one header per copy), sector-aligned.
    reading: []align(constants.sector_size) SuperBlockHeader,

    /// Opens (creating, never truncating) the marker file at `path`.
    pub fn open(path: []const u8, gpa: mem.Allocator) (Error || mem.Allocator.Error)!MarkerStore {
        assert(path.len > 0);
        assert(path.len <= std.fs.max_path_bytes);

        const existed = blk: {
            std.fs.cwd().access(path, .{}) catch break :blk false;
            break :blk true;
        };
        // Never truncate, never re-format in place: the copies are the
        // marker's evidence. (The C ABI surface is single-threaded on the
        // caller's thread — one store per marker file per process.)
        const file = std.fs.cwd().createFile(path, .{
            .read = true,
            .truncate = false,
        }) catch return error.FileOpenFailed;

        errdefer file.close();
        const owned = try gpa.dupe(u8, path);
        errdefer gpa.free(owned);
        const reading = try gpa.alignedAlloc(
            SuperBlockHeader,
            constants.sector_size,
            copies_count,
        );

        return .{
            .file = file,
            .path = owned,
            .existed = existed,
            .reading = reading,
        };
    }

    pub fn close(store: *MarkerStore, gpa: mem.Allocator) void {
        gpa.free(store.path);
        gpa.free(store.reading);
        store.file.close();
    }

    /// One lifecycle transition: quorum-write the marker (sequence + 1,
    /// hash-chained from the working quorum), force it durable, verify the
    /// write's read-back quorum. A fresh marker file formats at sequence
    /// 1; an existing one must present a working quorum to chain from.
    pub fn write(store: *MarkerStore, incarnation: u64, state: State) Error!void {
        const current: ?Working = try store.read_working();
        const sequence: u64 = if (current) |w| w.sequence + 1 else 1;
        const parent: u128 = if (current) |w| w.checksum else 0;
        if (current) |w| {
            if (incarnation < w.incarnation) return error.IncarnationRegressed;
        }
        var header = marker_header(incarnation, state, sequence, parent);
        try store.commit(&header);
    }

    /// The working quorum's classification: the lifecycle state and
    /// incarnation of the highest-sequence valid quorum.
    pub fn classify(store: *MarkerStore) Error!Classified {
        const current = try store.read_working() orelse return error.NotFound;
        const state = State.from_code(current.state) orelse return error.InvalidState;
        return .{ .state = state, .incarnation = current.incarnation };
    }

    /// Reads every copy and resolves the working quorum (the `.open`
    /// threshold, highest sequence). `null` when no copy is valid at all;
    /// every other resolution failure (no quorum, fork, skipped parent) is
    /// a fail-closed error.
    fn read_working(store: *MarkerStore) Error!?Working {
        for (0..copies_count) |index| {
            const buffer = mem.asBytes(&store.reading[index]);
            store.reading[index] = undefined;
            const read = store.file.preadAll(buffer, copy_size * index) catch return error.ReadFailed;
            if (read < copy_header_bytes) {
                // A torn or absent copy: not evidence, not an error — the
                // checksum quorum decides.
                continue;
            }
        }
        var quorums = Quorums{};
        const quorum = quorums.working(store.reading, .open) catch |err| switch (err) {
            error.NotFound => return null,
            else => return err,
        };
        return .{
            .sequence = quorum.header.sequence,
            .checksum = quorum.header.checksum,
            .incarnation = quorum.header.vsr_state.commit_max,
            .state = quorum.header.vsr_state.sync_view,
        };
    }

    /// Writes the copyset (each copy stamped with its zone index — the
    /// checksum excludes the `copy` field, as upstream writes do), forces
    /// the durability (fsync of the file, and of the containing directory
    /// when the marker file is first created), then verifies the write by
    /// reading back the `.verify` threshold (3/4) and requiring it to
    /// resolve to the written header.
    fn commit(store: *MarkerStore, header: *SuperBlockHeader) Error!void {
        assert(header.copy == 0);
        header.set_checksum();
        const expected_checksum = header.checksum;

        for (0..copies_count) |index| {
            header.copy = @intCast(index);
            store.file.pwriteAll(mem.asBytes(header), copy_size * index) catch return error.WriteFailed;
        }
        header.copy = 0;

        posix.fsync(store.file.handle) catch return error.SyncFailed;
        if (!store.existed) {
            fsync_directory(store.path) catch return error.DirectorySyncFailed;
            store.existed = true;
        }

        for (0..copies_count) |index| {
            const buffer = mem.asBytes(&store.reading[index]);
            store.reading[index] = undefined;
            const read = store.file.preadAll(buffer, copy_size * index) catch return error.ReadFailed;
            if (read < copy_header_bytes) return error.WriteFailed;
        }
        var quorums = Quorums{};
        const quorum = quorums.working(store.reading, .verify) catch return error.WriteFailed;
        if (quorum.header.checksum != expected_checksum) return error.WriteFailed;
    }
};

fn fsync_directory(path: []const u8) Error!void {
    const dirname = std.fs.path.dirname(path) orelse ".";
    // A REAL directory fd: zig 0.14.1's non-iterating openDir opens with
    // O_PATH on Linux, and fsync on an O_PATH fd is EBADF — which zig's
    // posix.fsync spells `unreachable` (.BADF/.INVAL/.ROFS), aborting the
    // process. `.iterate = true` opens O_RDONLY|O_DIRECTORY; the raw fsync
    // below maps every failure (the whole EBADF/EINVAL family included) to
    // the marker's fail-closed error, never unreachable.
    var dir = std.fs.cwd().openDir(dirname, .{ .iterate = true }) catch return error.DirectorySyncFailed;
    defer dir.close();
    const rc = posix.system.fsync(dir.fd);
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        else => return error.DirectorySyncFailed,
    }
}

/// The marker header for one lifecycle transition: the vendored superblock
/// header shape (checksummed as a whole by `set_checksum`), with the
/// marker riding the two `VSRState` fields the AOF-only build never drives
/// (see the module doc).
fn marker_header(incarnation: u64, state: State, sequence: u64, parent: u128) SuperBlockHeader {
    var header = mem.zeroes(SuperBlockHeader);
    header.version = superblock.SuperBlockVersion;
    header.release_format = vsr.Release.minimum;
    header.cluster = marker_cluster;
    header.sequence = sequence;
    header.parent = parent;

    var members: vsr.Members = @splat(0);
    members[0] = marker_replica_id;
    var vsr_state = SuperBlockHeader.VSRState.root(.{
        .cluster = marker_cluster,
        .replica_id = marker_replica_id,
        .members = members,
        .replica_count = 1,
        .release = vsr.Release.minimum,
        .view = 0,
    });
    vsr_state.commit_max = incarnation;
    vsr_state.sync_view = @intFromEnum(state);
    header.vsr_state = vsr_state;
    return header;
}

const testing = std.testing;

/// The marker file's path under a test's temporary directory. `buffer`
/// carries the directory prefix plus the suffix, so the returned slice
/// stays valid.
fn tmp_marker_path(tmp: *std.testing.TmpDir, buffer: []u8) ![]const u8 {
    const dir = try tmp.dir.realpath(".", buffer);
    const suffix = try std.fmt.bufPrint(buffer[dir.len..], "/marker.superblock", .{});
    return buffer[0 .. dir.len + suffix.len];
}

fn opened(gpa: mem.Allocator, path: []const u8) !MarkerStore {
    return try MarkerStore.open(path, gpa);
}

test "marker: quorum write and classify round trip across lifecycle transitions" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(testing.allocator, ".");
    defer testing.allocator.free(path);
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try std.fmt.bufPrint(&buf, "{s}/marker.superblock", .{path});

    var store = try opened(testing.allocator, file_path);
    defer store.close(testing.allocator);

    // A fresh marker formats at sequence 1.
    try store.write(7, .unflushed);
    try testing.expectEqual(Classified{ .state = .unflushed, .incarnation = 7 }, try store.classify());

    // Each transition advances the sequence and re-resolves cleanly.
    try store.write(7, .stopped);
    try testing.expectEqual(Classified{ .state = .stopped, .incarnation = 7 }, try store.classify());
    try store.write(7, .flushed);
    try testing.expectEqual(Classified{ .state = .flushed, .incarnation = 7 }, try store.classify());
    // A later life's bump: the incarnation advances, the sentinel returns.
    try store.write(8, .unflushed);
    try testing.expectEqual(Classified{ .state = .unflushed, .incarnation = 8 }, try store.classify());
}

test "marker: a fresh file formats; an existing file must present a working quorum" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    // A store over a fresh (absent) file formats at sequence 1, parent 0.
    var fresh = try opened(testing.allocator, file_path);
    try fresh.write(3, .flushed);
    try testing.expectEqual(Classified{ .state = .flushed, .incarnation = 3 }, try fresh.classify());
    fresh.close(testing.allocator);

    // Reopening sees the durable copies and chains from them (sequence 3).
    var reopened = try opened(testing.allocator, file_path);
    defer reopened.close(testing.allocator);
    try reopened.write(4, .unflushed);
    try testing.expectEqual(
        Classified{ .state = .unflushed, .incarnation = 4 },
        try reopened.classify(),
    );
}

test "marker: a rotted or torn copy cannot decide the read" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    var store = try opened(testing.allocator, file_path);
    try store.write(7, .flushed);
    store.close(testing.allocator);

    // Rot one copy: garbage over its zone (the checksum must fail).
    var garbage: [copy_header_bytes]u8 = undefined;
    for (&garbage) |*byte| {
        byte.* = 0xA5; // deterministic rot; NOT a valid header
    }
    var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
    defer file.close();
    try file.pwriteAll(&garbage, copy_size * 2);

    var reopened = try opened(testing.allocator, file_path);
    defer reopened.close(testing.allocator);
    try testing.expectEqual(
        Classified{ .state = .flushed, .incarnation = 7 },
        try reopened.classify(),
    );

    // A torn copy (never fully written: the zone reads short) decides
    // nothing either.
    try file.setEndPos(copy_size * 2);
    var reopened2 = try opened(testing.allocator, file_path);
    defer reopened2.close(testing.allocator);
    try testing.expectEqual(
        Classified{ .state = .flushed, .incarnation = 7 },
        try reopened2.classify(),
    );
}

test "marker: a stale copy cannot drag the classification back (min progress)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    var store = try opened(testing.allocator, file_path);
    try store.write(5, .unflushed);
    // Snapshot one copy at the older generation.
    const stale = try testing.allocator.alloc(u8, copy_header_bytes);
    defer testing.allocator.free(stale);
    {
        var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_only });
        defer file.close();
        _ = try file.preadAll(stale, copy_size * 1);
    }
    // The next transition: the stop path's flush, a full quorum write.
    try store.write(5, .flushed);
    store.close(testing.allocator);

    // Restore one copy to the older generation: a valid, stale copy. The
    // working read resolves to the higher sequence — the advanced copies
    // are truthful, the stale one cannot outvote them.
    var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
    defer file.close();
    try file.pwriteAll(stale, copy_size * 1);

    var reopened = try opened(testing.allocator, file_path);
    defer reopened.close(testing.allocator);
    try testing.expectEqual(
        Classified{ .state = .flushed, .incarnation = 5 },
        try reopened.classify(),
    );
}

test "marker: a single advanced copy without a quorum cannot fake a clean stop" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    var store = try opened(testing.allocator, file_path);
    try store.write(5, .unflushed);
    // Snapshot copies 1..3 of the running sentinel (sequence 1), each to
    // its own buffer (the copies are spaced copy_size apart; the headers
    // are read back per slot).
    const older = try testing.allocator.alloc(
        [copy_header_bytes]u8,
        copies_count - 1,
    );
    defer testing.allocator.free(older);
    {
        var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_only });
        defer file.close();
        for (1..copies_count) |index| {
            _ = try file.preadAll(&older[index - 1], copy_size * index);
        }
    }
    try store.write(5, .stopped);
    store.close(testing.allocator);

    // A death after exactly ONE copy of the stopped write: restore copies
    // 1..3 to the running sentinel, each to its own slot. The advanced
    // copy is truthful but holds no quorum, so the read resolves to the
    // running sentinel: the boot classifies DIRTY, never clean.
    var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
    defer file.close();
    for (1..copies_count) |index| {
        try file.pwriteAll(&older[index - 1], copy_size * index);
    }

    var reopened = try opened(testing.allocator, file_path);
    defer reopened.close(testing.allocator);
    try testing.expectEqual(
        Classified{ .state = .unflushed, .incarnation = 5 },
        try reopened.classify(),
    );
}

test "marker: a forged fork fails closed" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    var store = try opened(testing.allocator, file_path);
    try store.write(9, .flushed);
    store.close(testing.allocator);

    // Forge copy 0: same sequence, contradictory state, recomputed
    // checksum — a copy that lies while passing its checksum. The read
    // fails closed (error.Fork) instead of letting it decide.
    var forged: SuperBlockHeader = undefined;
    {
        var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
        defer file.close();
        _ = try file.preadAll(mem.asBytes(&forged), copy_size * 0);
        assert(forged.copy == 0);
        forged.vsr_state.sync_view = @intFromEnum(State.unflushed);
        forged.set_checksum();
        try file.pwriteAll(mem.asBytes(&forged), copy_size * 0);
    }

    var reopened = try opened(testing.allocator, file_path);
    defer reopened.close(testing.allocator);
    try testing.expectError(error.Fork, reopened.classify());
}

test "marker: a write refuses a regressing incarnation and an unquorum-able file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    var store = try opened(testing.allocator, file_path);
    try store.write(9, .flushed);
    try testing.expectError(error.IncarnationRegressed, store.write(8, .stopped));
    try testing.expectEqual(
        Classified{ .state = .flushed, .incarnation = 9 },
        try store.classify(),
    );
    store.close(testing.allocator);

    // A file whose copies rotted beyond the read quorum refuses a write
    // (fail closed) rather than silently re-formatting over evidence.
    {
        var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
        defer file.close();
        var garbage: [copy_header_bytes]u8 = @splat(0xA5);
        for (0..3) |index| try file.pwriteAll(&garbage, copy_size * index);
    }
    var rotted = try opened(testing.allocator, file_path);
    defer rotted.close(testing.allocator);
    try testing.expectError(error.QuorumLost, rotted.write(9, .stopped));
    try testing.expectError(error.QuorumLost, rotted.classify());
}

// The rig's andon shape: the first boot over a wiped state dir. The state
// dir exists (wiped), the marker file does not — the first quorum write
// creates it and must fsync the containing directory through a REAL
// directory fd (an O_PATH fd would abort the boot, zig spelling
// fsync's .BADF `unreachable`).
test "marker: first boot over a wiped state dir boots clean (empty dir)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    var store = try opened(testing.allocator, file_path);
    defer store.close(testing.allocator);
    try store.write(7, .unflushed);
    try testing.expectEqual(
        Classified{ .state = .unflushed, .incarnation = 7 },
        try store.classify(),
    );
}

// The whole state tree is absent and the host creates it during the
// boot; the first quorum write then dir-syncs the freshly created
// directory.
test "marker: first boot on a missing state dir boots clean (parent created)" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("state");
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const root = try tmp.dir.realpath(".", &buf);
    const suffix = try std.fmt.bufPrint(buf[root.len..], "/state/marker.superblock", .{});
    const file_path = buf[0 .. root.len + suffix.len];

    var store = try opened(testing.allocator, file_path);
    defer store.close(testing.allocator);
    try store.write(3, .flushed);
    try testing.expectEqual(
        Classified{ .state = .flushed, .incarnation = 3 },
        try store.classify(),
    );
}

// The boot with the marker file already present (`existed`): the dir
// fsync is skipped, the classification reads the durable copies, and the
// stop-path writes chain from them. Already passing — pinned.
test "marker: a survivor boot over an existing marker chains unchanged" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    {
        var first = try opened(testing.allocator, file_path);
        defer first.close(testing.allocator);
        try first.write(5, .unflushed);
    }
    // The survivor boot: the marker's copies are present, the boot reads
    // them, and the stop path chains from them.
    var survivor = try opened(testing.allocator, file_path);
    defer survivor.close(testing.allocator);
    try testing.expectEqual(
        Classified{ .state = .unflushed, .incarnation = 5 },
        try survivor.classify(),
    );
    try survivor.write(5, .flushed);
    try testing.expectEqual(
        Classified{ .state = .flushed, .incarnation = 5 },
        try survivor.classify(),
    );
    // A third boot over the stopped copies keeps the chain.
    var again = try opened(testing.allocator, file_path);
    defer again.close(testing.allocator);
    try testing.expectEqual(
        Classified{ .state = .flushed, .incarnation = 5 },
        try again.classify(),
    );
}

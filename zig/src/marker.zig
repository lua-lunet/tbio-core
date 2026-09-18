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
//! rather than guessing an identity. THE BOOT-READ LAW: every block read
//! validates its checksum before any classification logic, and a bad
//! checksum on ANY copy is a loud log and the `ChecksumRot` refusal —
//! the boot never classifies past a bad block, never clears or repairs
//! one, and never falls back to another store. A tear is the spread
//! writes being inconsistent across the copies (checksum-valid copies at
//! differing states) — not a bad checksum on any single write — and it
//! resolves by the stated thresholds (`.verify` 3/4 write, `.open` 2/4
//! read), with the non-unanimity logged in full at the moment of
//! resolution: which copies, their states, their sequences. A unanimous
//! read logs nothing special. The FFI boundary cannot panic across the
//! ABI, so the store refuses with `ChecksumRot`, the C ABI spells a
//! distinct code, and the host adapter panics on it — the panic stays in
//! the host process, loud. Deleting a rotted marker file is the recovery
//! path: the host then re-seeds from its own compatibility projection
//! (the adapter's single marker file, which lags the copies by
//! at most one transition and can therefore only ever classify more
//! conservatively).
//!
//! No-hang discipline: every call opens, drives, and closes its own file
//! on the caller's thread — one bounded blocking read per copy, one
//! fsync, no locks, no retries, no threads — so the boot read cannot
//! hang: every path from process boot to classification terminates or
//! fails loud.
//!
//! The readable block: the operator's law is that no state is a bare
//! integer a human must memorise. Each copy's header carries the
//! lifecycle state twice — the numeric code in `vsr_state.sync_view` and
//! a fixed-width, space-padded name (`"flushed         "`) in the
//! header's spare `state_string` bytes (the vendored `SuperBlockHeader`'s
//! former reserved tail, inside the checksum) — both stamped at compile
//! time from the one `state_strings`/`state_names` table, so a write can
//! never stamp disagreeing halves. Every read enforces the agreement: a
//! checksum-valid copy whose string disagrees with its numeric state is
//! checksum-class corruption under the boot-read law (the
//! `StateStringDisagreement` refusal, spelled `CORRUPT` across the FFI,
//! the host adapter panics on it — never cleared, never repaired, never
//! quorum-decided). The logs print the states' names, never their codes.
const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const posix = std.posix;

const constants = @import("constants.zig");
const vsr = @import("vsr.zig");
const superblock = @import("vsr/superblock.zig");

const log = std.log.scoped(.marker);

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

    /// The state's name, for every surface a human reads: `state=flushed`,
    /// never `state=2`. The on-disk code and every comparison stay
    /// numeric; the name is stated next to the numbering it names so the
    /// two cannot drift apart. The on-disk spelling is the contract's:
    /// the running sentinel is spelled `unflushed`.
    pub fn name(self: State) []const u8 {
        return state_names[@intFromEnum(self)];
    }
};

/// The lifecycle states' names, indexed by the on-disk state code — the
/// one table every human surface (the logs, the on-disk string, the
/// inspect export's consumers) spells the states from.
pub const state_names = [_][]const u8{ "unflushed", "stopped", "flushed" };

/// The name a state code spells, or `null` for a code outside the
/// lifecycle.
pub fn state_name(code: u32) ?[]const u8 {
    if (code >= state_names.len) return null;
    return state_names[code];
}

/// The states' fixed-width, space-padded on-disk strings, precomputed at
/// compile time from `state_names`: the marker header's `state_string`
/// field is stamped from this table — the same table the numeric field's
/// names come from — so the block's string and its numeric state can
/// never disagree at write time, and a hexdump reads the state directly.
pub const state_strings: [state_names.len][SuperBlockHeader.state_string_len]u8 = blk: {
    var out: [state_names.len][SuperBlockHeader.state_string_len]u8 = undefined;
    for (state_names, 0..) |name, index| {
        @memset(&out[index], ' ');
        @memcpy(out[index][0..name.len], name);
    }
    break :blk out;
};

/// The string stamped for a state code, or `null` for a code outside the
/// lifecycle.
pub fn state_string(code: u32) ?*const [SuperBlockHeader.state_string_len]u8 {
    if (code >= state_names.len) return null;
    return &state_strings[code];
}

/// The human word for a state code, for the log lines: the name when the
/// code is a lifecycle state, `invalid(<code>)` otherwise — never a bare
/// integer for a human to memorise. `buffer` carries the fallback's
/// rendering when the code is outside the lifecycle.
fn state_word(buffer: []u8, code: u32) []const u8 {
    if (state_name(code)) |name| return name;
    return std.fmt.bufPrint(buffer, "invalid({d})", .{code}) catch "invalid";
}

/// The block's state-string bytes as a log-safe slice: printable bytes
/// pass, anything else renders as a dot — a rotted or forged string is
/// logged, never raw.
fn as_readable_string(bytes: *const [SuperBlockHeader.state_string_len]u8) []const u8 {
    for (bytes) |byte| {
        if (!std.ascii.isPrint(byte) and byte != ' ') return "<unreadable>";
    }
    return bytes;
}

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
    /// A readable, checksum-valid copy whose on-disk state string
    /// disagrees with its numeric state field: checksum-class corruption.
    /// THE BOOT-READ LAW — fully logged, then refused; never cleared,
    /// never repaired, never quorum-decided. The FFI spells it as the
    /// same distinct code as `ChecksumRot` and the host adapter panics
    /// on it.
    StateStringDisagreement,
    /// A write refused: the incarnation would regress the marker.
    IncarnationRegressed,
    /// A write refused: the marker file's copies rotted beyond the read
    /// quorum (delete the file to re-seed from the compatibility
    /// projection).
    Unformatted,
    /// A readable copy failed its checksum: THE BOOT-READ LAW — fully
    /// logged, then refused. Never cleared, never repaired, never fallen
    /// back, never decided by quorum; the FFI spells it as a distinct
    /// code and the host adapter panics on it.
    ChecksumRot,
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
    /// threshold, highest sequence). `null` when no copy is readable at
    /// all; every other resolution failure (no quorum, fork, skipped
    /// parent) is a fail-closed error. Every readable copy's checksum is
    /// validated before any classification logic: a checksum failure on
    /// ANY copy is a loud log and the `ChecksumRot` refusal — never
    /// cleared, never repaired, never quorum-decided. A non-unanimous
    /// resolution is logged in full (which copies, their states, their
    /// sequences); a unanimous read logs nothing special.
    fn read_working(store: *MarkerStore) Error!?Working {
        var readable: [copies_count]bool = @splat(false);
        for (0..copies_count) |index| {
            const buffer = mem.asBytes(&store.reading[index]);
            store.reading[index] = undefined;
            const read = store.file.preadAll(buffer, copy_size * index) catch return error.ReadFailed;
            if (read < copy_header_bytes) {
                // A torn or absent copy: not evidence, not an error — the
                // checksum quorum decides. The slot is zeroed so the
                // quorum machinery sees a deterministic invalid header,
                // never stale bytes from an earlier read.
                store.reading[index] = mem.zeroes(SuperBlockHeader);
                continue;
            }
            readable[index] = true;
            // THE BOOT-READ LAW: the checksum validates before any
            // classification logic, and a failure on ANY copy is a loud
            // refusal — never cleared, never repaired, never fallen back.
            if (!store.reading[index].valid_checksum()) {
                var word_buf: [32]u8 = undefined;
                log.warn("marker: copy {}/{}: BAD CHECKSUM — the boot read refuses; " ++
                    "the block is never cleared, never repaired, never quorum-decided " ++
                    "(checksum={x:0>32} sequence={} state={s} state_string=\"{s}\" incarnation={} copy_field={})", .{
                    index,
                    copies_count,
                    store.reading[index].checksum,
                    store.reading[index].sequence,
                    state_word(&word_buf, store.reading[index].vsr_state.sync_view),
                    as_readable_string(&store.reading[index].state_string),
                    store.reading[index].vsr_state.commit_max,
                    store.reading[index].copy,
                });
                return error.ChecksumRot;
            }
            // The string half of the state agrees with the numeric half,
            // or the copy is corruption: a checksum-valid copy whose
            // padded name disagrees with its numeric state is refused
            // exactly like a bad checksum (checksum-class, THE BOOT-READ
            // LAW) — a forged copy can recompute a checksum, but it
            // cannot make the block's two halves agree.
            const code = store.reading[index].vsr_state.sync_view;
            if (state_string(code)) |expected| {
                if (!mem.eql(u8, &store.reading[index].state_string, expected)) {
                    log.warn("marker: copy {}/{}: STATE STRING DISAGREES WITH THE NUMERIC " ++
                        "STATE — checksum-class corruption, the boot read refuses; the block " ++
                        "is never cleared, never repaired, never quorum-decided " ++
                        "(sequence={} state={s} state_string=\"{s}\" incarnation={})", .{
                        index,
                        copies_count,
                        store.reading[index].sequence,
                        state_name(code).?,
                        as_readable_string(&store.reading[index].state_string),
                        store.reading[index].vsr_state.commit_max,
                    });
                    return error.StateStringDisagreement;
                }
            }
        }
        var quorums = Quorums{};
        const quorum = quorums.working(store.reading, .open) catch |err| switch (err) {
            error.NotFound => return null,
            else => return err,
        };
        log_non_unanimous(store.reading, &readable, quorum);
        return .{
            .sequence = quorum.header.sequence,
            .checksum = quorum.header.checksum,
            .incarnation = quorum.header.vsr_state.commit_max,
            .state = quorum.header.vsr_state.sync_view,
        };
    }

    /// The non-unanimity log at the moment of resolution: when the
    /// working quorum resolved but the copies are not unanimous (a torn
    /// spread — readable copies at differing states, or absent ones), the
    /// full spread is logged: which copies, their states, their
    /// sequences, and which of them the resolution carries. A unanimous
    /// read logs nothing special.
    fn log_non_unanimous(
        headers: []const SuperBlockHeader,
        readable: []const bool,
        quorum: anytype,
    ) void {
        var unanimous = true;
        for (0..copies_count) |index| {
            if (!readable[index] or quorum.slots[index] == null) unanimous = false;
        }
        if (unanimous) return;
        var word_buf: [32]u8 = undefined;
        log.warn(
            "marker: NON-UNANIMOUS spread resolved by thresholds: sequence={} " ++
                "state={s} incarnation={} checksum={x:0>32} carried by {} of {} copies",
            .{
                quorum.header.sequence,
                state_word(&word_buf, quorum.header.vsr_state.sync_view),
                quorum.header.vsr_state.commit_max,
                quorum.header.checksum,
                quorum.copies.count(),
                copies_count,
            },
        );
        for (0..copies_count) |index| {
            if (!readable[index]) {
                log.warn("marker: copy {}/{}: ABSENT (torn zone; not evidence)", .{
                    index, copies_count,
                });
                continue;
            }
            var member_word_buf: [32]u8 = undefined;
            const member = quorum.slots[index] != null;
            log.warn(
                "marker: copy {}/{}: {s} sequence={} state={s} state_string=\"{s}\" incarnation={} " ++
                    "checksum={x:0>32} {s}",
                .{
                    index,
                    copies_count,
                    if (member) @as([]const u8, "RESOLVED") else @as([]const u8, "outvoted"),
                    headers[index].sequence,
                    state_word(&member_word_buf, headers[index].vsr_state.sync_view),
                    as_readable_string(&headers[index].state_string),
                    headers[index].vsr_state.commit_max,
                    headers[index].checksum,
                    if (member)
                        @as([]const u8, "")
                    else
                        @as([]const u8, "(not carried by the resolution)"),
                },
            );
        }
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
            // THE BOOT-READ LAW at the verify read-back: a readable copy
            // whose checksum does not verify is storage rot — fully
            // logged, then refused. Never retried, never repaired.
            if (!store.reading[index].valid_checksum()) {
                var word_buf: [32]u8 = undefined;
                log.warn("marker: copy {}/{}: BAD CHECKSUM at the write's verify read-back — " ++
                    "the write refuses; the block is never cleared, never repaired " ++
                    "(checksum={x:0>32} sequence={} state={s} incarnation={})", .{
                    index,
                    copies_count,
                    store.reading[index].checksum,
                    store.reading[index].sequence,
                    state_word(&word_buf, store.reading[index].vsr_state.sync_view),
                    store.reading[index].vsr_state.commit_max,
                });
                return error.ChecksumRot;
            }
        }
        var quorums = Quorums{};
        const quorum = quorums.working(store.reading, .verify) catch return error.WriteFailed;
        if (quorum.header.checksum != expected_checksum) return error.WriteFailed;
    }

    /// The `lunet_locks_nuke` admin tool's deliberate reset: a FRESH format at sequence 1 —
    /// four copies of the named `(incarnation, state)`, parent 0, forced
    /// I/O, verify read-back. This is an explicit operator action over
    /// the evidence (confirmed by the tool's own review gate), never a
    /// boot-read repair: no read path formats over anything.
    pub fn format(store: *MarkerStore, incarnation: u64, state: State) Error!void {
        var header = marker_header(incarnation, state, 1, 0);
        try store.commit(&header);
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
    // The readable half of the state: stamped from the same const table
    // the numeric field's names come from, so the block's string and its
    // numeric state can never disagree at write time (the read enforces
    // the same agreement on every copy).
    header.state_string = state_strings[@intFromEnum(state)];
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

test "marker: a rotted copy fails the read loud (ChecksumRot), never heals" {
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

    var before: [copy_header_bytes]u8 = undefined;
    {
        var reader = try std.fs.cwd().openFile(file_path, .{});
        defer reader.close();
        _ = try reader.preadAll(&before, copy_size * 2);
    }

    // THE BOOT-READ LAW: a checksum failure on ANY copy is a loud refusal
    // (error.ChecksumRot → the FFI's distinct code → the adapter panics).
    // Never quorum-decided, never cleared, never repaired: the rotted
    // bytes stand unchanged after the refused read.
    var reopened = try opened(testing.allocator, file_path);
    defer reopened.close(testing.allocator);
    try testing.expectError(error.ChecksumRot, reopened.classify());
    try testing.expectError(error.ChecksumRot, reopened.write(7, .stopped));

    var after: [copy_header_bytes]u8 = undefined;
    {
        var reader = try std.fs.cwd().openFile(file_path, .{});
        defer reader.close();
        _ = try reader.preadAll(&after, copy_size * 2);
    }
    try testing.expectEqualSlices(u8, &before, &after);
}

test "marker: a torn copy (never fully written) decides nothing" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    var store = try opened(testing.allocator, file_path);
    try store.write(7, .flushed);
    store.close(testing.allocator);

    // A torn copy (never fully written: the zone reads short) decides
    // nothing either — absence is not corruption, the checksum quorum
    // decides among the readable copies.
    var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
    defer file.close();
    try file.setEndPos(copy_size * 2);
    var reopened = try opened(testing.allocator, file_path);
    defer reopened.close(testing.allocator);
    try testing.expectEqual(
        Classified{ .state = .flushed, .incarnation = 7 },
        try reopened.classify(),
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
    // checksum — a copy that lies while passing its checksum. Both halves
    // of the state are forged coherently (the numeric field and the
    // string stamped from the same table, exactly as a real forked write
    // would produce): the string/numeric agreement passes, and the read
    // fails closed (error.Fork) instead of letting the copy decide.
    var forged: SuperBlockHeader = undefined;
    {
        var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
        defer file.close();
        _ = try file.preadAll(mem.asBytes(&forged), copy_size * 0);
        assert(forged.copy == 0);
        forged.vsr_state.sync_view = @intFromEnum(State.unflushed);
        forged.state_string = state_strings[@intFromEnum(State.unflushed)];
        forged.set_checksum();
        try file.pwriteAll(mem.asBytes(&forged), copy_size * 0);
    }

    var reopened = try opened(testing.allocator, file_path);
    defer reopened.close(testing.allocator);
    try testing.expectError(error.Fork, reopened.classify());
}

test "marker: a write refuses a regressing incarnation and a rotted file" {
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

    // A file whose copies rotted (bad checksums) refuses a write (fail
    // closed, loud) rather than silently re-formatting over evidence —
    // the boot-read law applies to the write's read of the copies too.
    {
        var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
        defer file.close();
        var garbage: [copy_header_bytes]u8 = @splat(0xA5);
        for (0..3) |index| try file.pwriteAll(&garbage, copy_size * index);
    }
    var rotted = try opened(testing.allocator, file_path);
    defer rotted.close(testing.allocator);
    try testing.expectError(error.ChecksumRot, rotted.write(9, .stopped));
    try testing.expectError(error.ChecksumRot, rotted.classify());
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

// The operator's law, the block half: the state is readable in a raw
// hexdump. Each copy carries the fixed-width space-padded name stamped
// from the same const table the numeric field uses — the padded bytes at
// the header's `state_string` offset spell the state, the field's
// leading bytes are the name, the tail is spaces.
test "marker: the block carries the readable state string" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    const string_offset = @offsetOf(SuperBlockHeader, "state_string");
    try testing.expectEqual(@as(usize, 16), SuperBlockHeader.state_string_len);

    const lifecycle = [_]State{ .unflushed, .stopped, .flushed };
    for (lifecycle) |state| {
        var store = try opened(testing.allocator, file_path);
        errdefer store.close(testing.allocator);
        try store.write(7, state);
        store.close(testing.allocator);

        var copy: [copy_header_bytes]u8 = undefined;
        {
            var file = try std.fs.cwd().openFile(file_path, .{});
            defer file.close();
            _ = try file.preadAll(&copy, 0);
        }
        const stamped = copy[string_offset..][0..SuperBlockHeader.state_string_len];
        try testing.expectEqualSlices(u8, state_strings[@intFromEnum(state)][0..], stamped);
        try testing.expectEqualStrings(state.name(), std.mem.trim(u8, stamped, " "));
        for (stamped[state.name().len..]) |byte| {
            try testing.expectEqual(@as(u8, ' '), byte);
        }
    }

    // A fresh write of the next transition keeps the same discipline (the
    // string is re-stamped from the table, never stale).
    var store = try opened(testing.allocator, file_path);
    defer store.close(testing.allocator);
    try store.write(8, .flushed);
    try testing.expectEqual(
        Classified{ .state = .flushed, .incarnation = 8 },
        try store.classify(),
    );
}

// The string/numeric disagreement is checksum-class corruption: a copy
// whose checksum was recomputed over disagreeing halves is refused loud
// (StateStringDisagreement), never quorum-decided, never healed — the
// forged bytes stand unchanged after the refused read.
test "marker: a forged string/numeric disagreement refuses loud, never heals" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const file_path = try tmp_marker_path(&tmp, &buf);

    var store = try opened(testing.allocator, file_path);
    try store.write(9, .flushed);
    store.close(testing.allocator);

    // Forge copy 1: the numeric state says `flushed`, the string says
    // `stopped`, and the checksum is recomputed over the lie — a copy
    // that passes its checksum while contradicting itself.
    var forged: SuperBlockHeader = undefined;
    var before: [copy_header_bytes]u8 = undefined;
    {
        var file = try std.fs.cwd().openFile(file_path, .{ .mode = .read_write });
        defer file.close();
        _ = try file.preadAll(mem.asBytes(&forged), copy_size * 1);
        assert(forged.copy == 1);
        assert(State.from_code(forged.vsr_state.sync_view).? == .flushed);
        @memcpy(&forged.state_string, &state_strings[@intFromEnum(State.stopped)]);
        // The checksum excludes the `copy` field (upstream's own
        // discipline): zero it for the recompute, restore it for the
        // write-back so the forged copy keeps its zone index.
        forged.copy = 0;
        forged.set_checksum();
        forged.copy = 1;
        try file.pwriteAll(mem.asBytes(&forged), copy_size * 1);
        _ = try file.preadAll(&before, copy_size * 1);
    }

    var reopened = try opened(testing.allocator, file_path);
    defer reopened.close(testing.allocator);
    try testing.expectError(error.StateStringDisagreement, reopened.classify());
    try testing.expectError(error.StateStringDisagreement, reopened.write(9, .stopped));

    var after: [copy_header_bytes]u8 = undefined;
    {
        var file = try std.fs.cwd().openFile(file_path, .{});
        defer file.close();
        _ = try file.preadAll(&after, copy_size * 1);
    }
    try testing.expectEqualSlices(u8, &before, &after);
}

// The logs spell states' names, never their codes: the human word for a
// lifecycle code is the name, an out-of-lifecycle code renders as
// invalid(N), never a bare integer.
test "marker: the state words render names, not codes" {
    var buffer: [32]u8 = undefined;
    try testing.expectEqualStrings("unflushed", state_word(&buffer, 0));
    try testing.expectEqualStrings("stopped", state_word(&buffer, 1));
    try testing.expectEqualStrings("flushed", state_word(&buffer, 2));
    try testing.expectEqualStrings("invalid(7)", state_word(&buffer, 7));
    try testing.expectEqualStrings("flushed", State.flushed.name());
}

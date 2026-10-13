//! The WAL lock snapshot store's two-stream double-ring rotating engine
//! (docs/src/wal-snapshot.md in the outer repo is the binding design).
//!
//! One fixed-size, pre-laid-out `.wal` file, 8 MiB, two streams — the
//! ephemeral stream of one-cache-line records and the durable stream of
//! 12-cache-line fat frames — each with two alternating pairs (the copy
//! collection), every ring ~1 MiB from its neighbours so no two rings
//! share an erase block:
//!
//! ```text
//! offset 0      ephemeral pair A data ring     (capacity × 64 B)
//! offset 1 MiB  ephemeral pair A header ring   (capacity × 40 B)
//! offset 2 MiB  ephemeral pair B data ring
//! offset 3 MiB  ephemeral pair B header ring
//! offset 4 MiB  durable pair A data ring       (capacity × 768 B)
//! offset 5 MiB  durable pair A header ring     (capacity × 40 B)
//! offset 6 MiB  durable pair B data ring
//! offset 7 MiB  durable pair B header ring
//! ```
//!
//! One shape per ring. The engine is a sans-IO state machine driven by
//! the caller, generic over its IO (`WalType(IO)`). The C ABI instantiates
//! the seam per platform: the Linux io_uring + eventfd backend
//! (`wal_uring_linux.zig`) and the inline-completion platforms'
//! synchronous backend (`SyncIO`: posix pwrite/pread on top of the
//! vendored `io/common.zig` primitives) — with zero fsyncs in steady
//! state and exactly one fsync on the shutdown flush, the one fsync
//! covering both streams, which share the one file descriptor. The IO
//! seam keeps the format and the logic untouched by the backend.
//!
//! Record — 64 bytes fixed, exactly one cache line, little-endian, and
//! memcpy-exact: the on-disk bytes ARE the struct's bytes (`WalRecord`, an
//! extern struct with zero padding — stamp, expiry, lock id, lease id,
//! holder uuid, lease window, tag, checksum, every field naturally
//! aligned). The round trip is a memcpy in both directions (`mem.asBytes`
//! / `mem.bytesToValue`); the only "special" step is the checksum,
//! computed into the struct's own field on encode and verified on decode.
//! Tag = kind + format version bits; the checksum is the vendored
//! Aegis-128 primitive (`vsr.checksum`) truncated to its low 32 bits —
//! the in-tree checksum of the vendored strip; there is no CRC-32
//! in-tree. Header record — 40 bytes fixed (`WalHeader`: the identity
//! fields, the tag, and its own checksum): the torn-write /
//! misdirected-write detector and the fast scan path. The ephemeral
//! data ring holds the bitwise NOT of the record — every byte flipped —
//! as the redundant second copy: the read path un-flips it and demands
//! byte-exact agreement with the header twin plus the checksum. The
//! layout is pinned by comptime asserts on every build (size, every
//! offset, alignment, no padding); little-endian is baked by the memcpy
//! on both release targets (x86_64, aarch64 — both LE); a big-endian
//! host would fail the round trip loudly.
//!
//! The durable stream's fat frame — 768 B, 12 cache lines, one budget:
//! CL0 the same 64-byte header record (unflipped; kinds live|kept|delete),
//! CL1-5 the name (a u16 byte length + the name bytes, zero-filled),
//! CL6-7 the counters and tags (taken_at_ms, renew_count, a u16 tag-byte
//! length + the tag bytes, zero-filled), CL8-11 the consistency area (a
//! 32-byte SHA-256 content hash at a fixed offset, the rest
//! zero-reserved). The frame checksum spans the WHOLE 768 B frame,
//! computed with the checksum field zeroed — an ephemeral header and a
//! durable header are checksum-distinguishable without any type bit.
//!
//! Capacity is a fixed record count per ring, an operator knob (default
//! 1024 per stream). A generation that exceeds capacity is a refused
//! flush: on the shutdown path a failed stop (an error to the caller), on
//! the steady path a refusal counted in `refusals` with the serving state
//! unaffected. Never a silent partial write, never a truncation.
const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const posix = std.posix;

const common = @import("io/common.zig");
const vsr = @import("vsr.zig");
const stdx = @import("stdx");

const MiB = stdx.MiB;

// ---------------------------------------------------------------------------
// The format.
// ---------------------------------------------------------------------------

/// The record's binding layout, byte offsets into the memcpy-exact struct
/// (the on-disk bytes ARE the struct's bytes). Every offset is pinned by
/// the comptime asserts below — a layout drift is a compile error.
pub const stamp_offset: u32 = 0;
pub const expiry_offset: u32 = 8;
pub const lock_id_offset: u32 = 16;
pub const lease_id_offset: u32 = 24;
pub const holder_offset: u32 = 32;
pub const lease_ms_offset: u32 = 48;
pub const tag_offset: u32 = 56;
/// The 4-byte checksum's on-disk offset in a data record — the byte a
/// fault-injection test flips. The checksum covers exactly the bytes
/// before it.
pub const checksum_data_offset: u32 = 60;
/// The byte size of the identity prefix the two rings share: stamp,
/// expiry, lock id, lease id.
pub const identity_size: u32 = 32;

/// The 64-byte data record and the 40-byte header record, bytes — one
/// full cache line and its identity header's compact form.
pub const record_size: u32 = 64;
pub const header_record_size: u32 = 40;
/// The header record's tag and checksum offsets (its identity prefix is
/// the record's `identity_size` bytes).
const header_tag_offset: u32 = 32;
const header_checksum_offset: u32 = 36;

/// The two streams: the ephemeral hot path and the durable named locks.
/// Their id spaces are separated by the streams themselves — an ephemeral
/// lock is addressed by its caller-supplied u64, a durable lock's u64 is
/// assigned by the creating consensus write (its slot).
pub const Stream = enum(u1) {
    ephemeral,
    durable,
};

/// One cache line, bytes — the record's size and the fat frame's unit.
const cache_line: u32 = 64;

/// One ring span: a pair's data ring and header ring sit one span apart.
const ring_span: u64 = MiB;

/// The fixed 8 MiB layout: two streams × two pairs × (data ring + header
/// ring), every offset fixed. A stream's pair base is the stream's own
/// 4 MiB half plus the pair index × 2 MiB; the header ring rides one span
/// above its data ring.
pub const file_size: u64 = 8 * MiB;

/// The record count per ring — one operator knob for both streams,
/// default 1024.
pub const capacity_default: u32 = 1024;
/// Both of a pair's rings live inside one 1 MiB span each; the durable
/// data ring (capacity × 768 B) is the binding constraint.
pub const ring_capacity_max: u32 = MiB / fat_frame_size;

// -- the durable fat frame's geometry ---------------------------------------
/// The fat frame: 12 cache lines, 768 bytes, one budget.
pub const fat_frame_size: u32 = 768;
pub const fat_frame_cl: u32 = 12;
/// The frame's bytes past the CL0 header record.
pub const fat_frame_data_size: u32 = fat_frame_size - record_size;

/// CL1-5 — the name: a u16 byte length, then the name bytes, zero-filled.
pub const fat_name_area_offset: u32 = 1 * cache_line;
pub const fat_name_len_offset: u32 = fat_name_area_offset;
pub const fat_name_offset: u32 = fat_name_area_offset + 2;
pub const fat_name_capacity: u32 = 5 * cache_line - 2;

/// CL6-7 — counters and tag bytes: taken_at_ms (u64), renew_count (u32),
/// a u16 tag-bytes length, then the tag bytes, zero-filled.
pub const fat_counters_offset: u32 = 6 * cache_line;
pub const fat_taken_at_offset: u32 = fat_counters_offset;
pub const fat_renew_count_offset: u32 = fat_counters_offset + 8;
pub const fat_tag_len_offset: u32 = fat_counters_offset + 12;
pub const fat_tag_bytes_offset: u32 = fat_counters_offset + 14;
pub const fat_tag_bytes_capacity: u32 = 2 * cache_line - 14;

/// CL8-11 — the consistency area: a 32-byte SHA-256 content hash at a
/// fixed offset, the rest zero-reserved.
pub const fat_sha_offset: u32 = 8 * cache_line;
pub const fat_sha_size: u32 = 32;

comptime {
    // One cache line: the record is exactly 64 bytes, struct alignment 8,
    // and every ring base is MiB-aligned — so every record boundary sits
    // on a 64-byte line.
    assert(record_size == 64);
    assert(record_size % 8 == 0);
    assert(MiB % record_size == 0);
    // The fat frame's budget: 12 CL, the name and tags areas land inside
    // their cache lines, the sha fits its consistency area, and the whole
    // frame is 8-aligned.
    assert(fat_frame_size == fat_frame_cl * cache_line);
    assert(fat_frame_size % 8 == 0);
    assert(fat_frame_data_size == fat_frame_size - record_size);
    assert(fat_name_offset + fat_name_capacity == fat_counters_offset);
    assert(fat_tag_bytes_offset + fat_tag_bytes_capacity == fat_sha_offset);
    assert(fat_sha_offset + fat_sha_size <= fat_frame_size);
    assert(fat_counters_offset % cache_line == 0);
    assert(fat_sha_offset % cache_line == 0);
    // The capacity knob binds on the durable data ring: 1 MiB holds
    // `ring_capacity_max` whole frames (256 B of span slack; the frames
    // are offset-fixed, never 768-aligned in the file). The ephemeral
    // data ring and both header rings fit the same count.
    assert(@as(u64, ring_capacity_max) * fat_frame_size <= MiB);
    assert(@as(u64, ring_capacity_max + 1) * fat_frame_size > MiB);
    assert(MiB / record_size >= ring_capacity_max);
    assert(MiB / header_record_size >= ring_capacity_max);
    assert(capacity_default <= ring_capacity_max);
}

/// The clock-drift safety threshold of the read path: the reader may sit
/// behind or ahead of the leader's clock, so a record is expired only once
/// `now` is past `expiry` by more than this much (default 3 s).
pub const drift_threshold_ns_default: u64 = 3 * std.time.ns_per_s;

/// The record kind, encoded in the tag's low bits.
pub const Kind = enum(u8) {
    live = 1,
    tombstone = 2,
};

/// The format version, encoded in the tag's second byte.
pub const format_version: u8 = 1;

/// The ephemeral tag codec: the kind's code in the low nibble, the
/// format-version bits in the second byte. `tag_decode` is the decode
/// half and the structure check at once — a tag from another format
/// version, or an unknown kind code, is not a record.
pub fn tag_encode(kind: Kind) u32 {
    return @intFromEnum(kind) | (@as(u32, format_version) << 8);
}

pub fn tag_decode(tag: u32) ?Kind {
    if ((tag >> 8) != format_version) return null;
    if ((tag & 0xF0) != 0) return null;
    return switch (tag & 0x0F) {
        1 => .live,
        2 => .tombstone,
        else => null,
    };
}

/// The checksum of a record: the vendored Aegis-128 primitive (`vsr.checksum`)
/// truncated to its low 32 bits, over the record's pre-checksum bytes.
fn wal_checksum(bytes: []const u8) u32 {
    return @truncate(vsr.checksum(bytes));
}

/// The 64-byte data record: layout-exact and memcpy-round-trippable — the
/// on-disk bytes ARE this struct's bytes. Zero padding, every field
/// naturally aligned, struct alignment 8. The `tag` carries the raw
/// on-disk tag (the kind's code plus the format-version bits — the
/// constructors stamp it); the `checksum` is stamped by `record_encode`
/// into the struct's own field and verified by `record_decode`.
pub const WalRecord = extern struct {
    /// The ns write stamp: the epoch selector, wall clock of the write.
    stamp: u64 = 0,
    /// Absolute, always in the leader's clock.
    expiry: u64 = 0,
    lock_id: u64 = 0,
    lease_id: u64 = 0,
    /// The holder's uuid bytes.
    holder: [16]u8 = @splat(0),
    /// The granted window in milliseconds.
    lease_ms: u64 = 0,
    tag: u32 = 0,
    checksum: u32 = 0,

    /// A live record: acquire/renew.
    pub fn live(
        stamp: u64,
        expiry: u64,
        lock_id: u64,
        lease_id: u64,
        holder: [16]u8,
        lease_ms: u64,
    ) WalRecord {
        return .{
            .stamp = stamp,
            .expiry = expiry,
            .lock_id = lock_id,
            .lease_id = lease_id,
            .holder = holder,
            .lease_ms = lease_ms,
            .tag = tag_encode(.live),
        };
    }

    /// A tombstone: the release record. Tombstones are records too; a
    /// natural expiry writes nothing — the lock is simply absent from the
    /// next generation.
    pub fn tombstone(stamp: u64, lock_id: u64, lease_id: u64) WalRecord {
        return .{
            .stamp = stamp,
            .expiry = 0,
            .lock_id = lock_id,
            .lease_id = lease_id,
            .tag = tag_encode(.tombstone),
        };
    }

    /// The record's kind (its tag's kind code). Sound only for a record
    /// whose tag the codec validated (decode) or a constructor built.
    pub fn kind(self: WalRecord) Kind {
        return tag_decode(self.tag).?;
    }

    /// The record's identity header, as the header ring carries it.
    fn header_of(self: WalRecord) WalHeader {
        return .{
            .stamp = self.stamp,
            .expiry = self.expiry,
            .lock_id = self.lock_id,
            .lease_id = self.lease_id,
            .tag = self.tag,
        };
    }

    comptime {
        assert(@sizeOf(WalRecord) == record_size);
        assert(@alignOf(WalRecord) == 8);
        assert(@offsetOf(WalRecord, "stamp") == stamp_offset);
        assert(@offsetOf(WalRecord, "expiry") == expiry_offset);
        assert(@offsetOf(WalRecord, "lock_id") == lock_id_offset);
        assert(@offsetOf(WalRecord, "lease_id") == lease_id_offset);
        assert(@offsetOf(WalRecord, "holder") == holder_offset);
        assert(@offsetOf(WalRecord, "lease_ms") == lease_ms_offset);
        assert(@offsetOf(WalRecord, "tag") == tag_offset);
        assert(@offsetOf(WalRecord, "checksum") == checksum_data_offset);
        assert(stdx.no_padding(WalRecord));
    }
};

/// The 40-byte header record: the identity prefix (stamp, expiry, lock id,
/// lease id — byte-equal with the data record's), the tag, and its own
/// checksum. The torn-write / misdirected-write detector and the fast
/// scan path.
pub const WalHeader = extern struct {
    stamp: u64 = 0,
    expiry: u64 = 0,
    lock_id: u64 = 0,
    lease_id: u64 = 0,
    tag: u32 = 0,
    checksum: u32 = 0,

    comptime {
        assert(@sizeOf(WalHeader) == header_record_size);
        assert(@alignOf(WalHeader) == 8);
        assert(@offsetOf(WalHeader, "tag") == header_tag_offset);
        assert(@offsetOf(WalHeader, "checksum") == header_checksum_offset);
        assert(stdx.no_padding(WalHeader));
    }
};

/// The ephemeral data ring's redundant-copy flip: the data slot holds the
/// bitwise NOT of the record — every byte flipped — the torn-write /
/// misdirected-write detector, the same shape as TigerBeetle's redundant
/// `wal_headers` write. The flip is its own inverse: the read path
/// un-flips and demands byte-exact agreement with the header twin plus
/// the record checksum.
pub fn not_flip(bytes: []u8) void {
    for (bytes) |*byte| byte.* = ~byte.*;
}

/// Encode one record into its 64-byte on-disk form: the checksum computed
/// into the struct's own field, then the struct's bytes copied out —
/// memcpy-exact, no per-field packing anywhere.
pub fn record_encode(out: *[record_size]u8, record: WalRecord) void {
    var stamped = record;
    stamped.checksum = 0;
    stamped.checksum = wal_checksum(mem.asBytes(&stamped)[0..checksum_data_offset]);
    @memcpy(out, mem.asBytes(&stamped));
}

/// Decode + validate one on-disk data record: memcpy in, checksum
/// verified, tag validated. The C ABI's submit wire format (the caller
/// serializes records; the ABI validates them here — data checksum, tag
/// version and kind, all of it).
pub fn record_decode(bytes: *const [record_size]u8) !WalRecord {
    const record = mem.bytesToValue(WalRecord, bytes);
    if (record.checksum != wal_checksum(bytes[0..checksum_data_offset]))
        return error.CorruptRecord;
    if (tag_decode(record.tag) == null) return error.CorruptRecord;
    return record;
}

/// Encode one identity header into its 40-byte on-disk form: the
/// checksum stamped into the struct's own field (the checksum field is
/// zero for the computation), then the struct's bytes copied out —
/// memcpy-exact, the same mechanics as the data record. The header
/// ring's only write path.
fn header_record_of(record: WalRecord) WalHeader {
    var header = record.header_of();
    header.checksum = 0;
    header.checksum = wal_checksum(mem.asBytes(&header)[0..header_checksum_offset]);
    return header;
}

/// Decode + validate one on-disk header record: memcpy in, checksum
/// verified, tag validated. The header ring carries both streams' header
/// records, so the tag's kind code may be either stream's (1 = live in
/// both, 2 = tombstone | kept, 3 = delete); the stream's own scan applies
/// its kind decode — a kind foreign to the ring is that scan's refusal.
fn header_record_decode(bytes: *const [header_record_size]u8) !WalHeader {
    const header = mem.bytesToValue(WalHeader, bytes);
    if (header.checksum != wal_checksum(bytes[0..header_checksum_offset]))
        return error.CorruptRecord;
    if (!header_tag_valid(header.tag)) return error.CorruptRecord;
    return header;
}

/// The header ring's tag structure check: the version bits must be
/// current and the kind code one of the streams' kinds.
fn header_tag_valid(tag: u32) bool {
    if ((tag >> 8) != format_version) return false;
    if ((tag & 0xF0) != 0) return false;
    return switch (tag & 0x0F) {
        1, 2, 3 => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// The durable stream: kinds and fat frame.
// ---------------------------------------------------------------------------

/// The durable stream's record kinds, encoded in the tag's low bits (the
/// same tag format as the ephemeral stream: kind code | format-version
/// bits; the streams' id spaces are separated by the streams themselves,
/// and the frame-spanning checksum distinguishes a durable header from an
/// ephemeral one without any type bit). live: acquire/create; **kept**:
/// released but not destroyed — the record survives with its identity;
/// **delete**: the real tombstone — the lock is destroyed, the record
/// leaves.
pub const DurableKind = enum(u8) {
    live = 1,
    kept = 2,
    delete = 3,
};

/// The durable tag codec — the ephemeral codec's shape over the durable
/// kinds (the version bits and the structure check identical).
pub fn tag_encode_durable(kind: DurableKind) u32 {
    return @intFromEnum(kind) | (@as(u32, format_version) << 8);
}

pub fn tag_decode_durable(tag: u32) ?DurableKind {
    if ((tag >> 8) != format_version) return null;
    if ((tag & 0xF0) != 0) return null;
    return switch (tag & 0x0F) {
        1 => .live,
        2 => .kept,
        3 => .delete,
        else => null,
    };
}

/// A durable header record: the caller's fields with the durable kind's
/// tag stamped (the format-version bits included).
pub fn durable_record(
    kind: DurableKind,
    stamp: u64,
    expiry: u64,
    lock_id: u64,
    lease_id: u64,
    holder: [16]u8,
    lease_ms: u64,
) WalRecord {
    return .{
        .stamp = stamp,
        .expiry = expiry,
        .lock_id = lock_id,
        .lease_id = lease_id,
        .holder = holder,
        .lease_ms = lease_ms,
        .tag = tag_encode_durable(kind),
    };
}

/// The 768-byte fat frame: layout-exact, 12 cache lines. CL0 the header
/// record (the same `WalRecord`, unflipped, its tag a durable kind);
/// CL1-5 the name; CL6-7 the counters and tag bytes; CL8-11 the
/// consistency area. The frame's checksum rides the header's own checksum
/// field and spans the WHOLE frame, computed with the checksum field
/// zeroed — the property that makes a durable header and an ephemeral
/// one checksum-distinguishable without any type bit.
pub const FatFrame = extern struct {
    header: WalRecord = .{},
    data: [fat_frame_data_size]u8 = @splat(0),

    /// The name bytes (the u16 length's span). Zero length = no name.
    pub fn name(self: *const FatFrame) []const u8 {
        const len = mem.readInt(
            u16,
            self.data[fat_name_len_offset - record_size ..][0..2],
            .little,
        );
        return self.data[fat_name_offset - record_size ..][0..len];
    }

    /// The counters' taken-at wall clock, milliseconds.
    pub fn taken_at_ms(self: *const FatFrame) u64 {
        return mem.readInt(
            u64,
            self.data[fat_taken_at_offset - record_size ..][0..8],
            .little,
        );
    }

    /// The counters' renew count: how many lease renewals carried the
    /// record since its take.
    pub fn renew_count(self: *const FatFrame) u32 {
        return mem.readInt(
            u32,
            self.data[fat_renew_count_offset - record_size ..][0..4],
            .little,
        );
    }

    /// The tag bytes (the u16 length's span; sorted, deduplicated).
    pub fn tag_bytes(self: *const FatFrame) []const u8 {
        const len = mem.readInt(
            u16,
            self.data[fat_tag_len_offset - record_size ..][0..2],
            .little,
        );
        return self.data[fat_tag_bytes_offset - record_size ..][0..len];
    }

    /// The frame header's durable kind (sound for a frame the codec
    /// decoded or a constructor built).
    pub fn kind(self: *const FatFrame) DurableKind {
        return tag_decode_durable(self.header.tag).?;
    }

    comptime {
        assert(@sizeOf(FatFrame) == fat_frame_size);
        assert(@alignOf(FatFrame) == 8);
        assert(@offsetOf(FatFrame, "header") == 0);
        assert(@offsetOf(FatFrame, "data") == record_size);
        assert(stdx.no_padding(FatFrame));
    }
};

/// One durable change, the submit path's input: the header record (its
/// tag carries the durable kind, version bits stamped via
/// `tag_encode_durable` or `durable_record`), the name, the counters,
/// and the tag bytes.
pub const DurableChange = struct {
    record: WalRecord,
    name: []const u8 = &.{},
    taken_at_ms: u64 = 0,
    renew_count: u32 = 0,
    tag_bytes: []const u8 = &.{},
};

/// The frame codec's refusals: `InvalidRecord` — a zero lock id or a tag
/// outside the durable kinds (a caller mistake, never on-disk rot);
/// `RecordTooLarge` — a name or tag bytes over its budget.
pub const FrameEncodeError = error{ InvalidRecord, RecordTooLarge };

/// Encode one durable change into its 768-byte on-disk fat frame: the
/// header with its checksum field zeroed, the name area, the counters
/// and tag bytes area, the SHA-256 content hash over CL0-7 into the
/// consistency area, then the frame checksum — the low 32 bits of the
/// vendored Aegis-128 primitive over the WHOLE frame with the checksum
/// field zeroed — stamped into the header's own field.
pub fn frame_encode(out: *[fat_frame_size]u8, change: DurableChange) FrameEncodeError!void {
    if (change.record.lock_id == 0) return error.InvalidRecord;
    if (tag_decode_durable(change.record.tag) == null) return error.InvalidRecord;
    if (change.name.len > fat_name_capacity) return error.RecordTooLarge;
    if (change.tag_bytes.len > fat_tag_bytes_capacity) return error.RecordTooLarge;

    var frame: FatFrame = .{};
    frame.header = change.record;
    frame.header.checksum = 0;

    mem.writeInt(
        u16,
        frame.data[fat_name_len_offset - record_size ..][0..2],
        @intCast(change.name.len),
        .little,
    );
    @memcpy(
        frame.data[fat_name_offset - record_size ..][0..change.name.len],
        change.name,
    );

    const counters = frame.data[fat_counters_offset - record_size .. fat_sha_offset - record_size];
    mem.writeInt(u64, counters[0..8], change.taken_at_ms, .little);
    mem.writeInt(u32, counters[8..12], change.renew_count, .little);
    mem.writeInt(u16, counters[12..14], @intCast(change.tag_bytes.len), .little);
    @memcpy(counters[14..][0..change.tag_bytes.len], change.tag_bytes);

    // Both integrity layers are one computation, shared with the
    // compaction re-stamp: the stamp's write, the SHA-256 content hash
    // over CL0-7, and the frame checksum — the same stamps the flush
    // path re-stamps with.
    frame_restamp(&frame, change.record.stamp);
    @memcpy(out, mem.asBytes(&frame));
}

/// Decode + validate one on-disk fat frame: memcpy in, the frame
/// checksum verified (the zeroed field, the whole 768 bytes), the
/// durable tag validated, the declared name/tag lengths inside their
/// budget, the SHA-256 content hash verified. The decoded frame keeps
/// the on-disk checksum in its field.
pub fn frame_decode(bytes: *const [fat_frame_size]u8) !FatFrame {
    var frame = mem.bytesToValue(FatFrame, bytes);
    const stored_checksum = frame.header.checksum;
    // Both integrity layers were computed with the checksum field zeroed:
    // verify them in that state, then restore the on-disk field.
    frame.header.checksum = 0;
    const zeroed = mem.asBytes(&frame);
    const checksum_ok = stored_checksum == wal_checksum(zeroed);

    var sha: [fat_sha_size]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(zeroed[0..fat_sha_offset], &sha, .{});
    const sha_ok = mem.eql(u8, &sha, bytes[fat_sha_offset..][0..fat_sha_size]);

    frame.header.checksum = stored_checksum;
    if (!checksum_ok or !sha_ok) return error.CorruptRecord;
    if (tag_decode_durable(frame.header.tag) == null) return error.CorruptRecord;
    if (mem.readInt(u16, frame.data[fat_name_len_offset - record_size ..][0..2], .little) >
        fat_name_capacity) return error.CorruptRecord;
    if (mem.readInt(u16, frame.data[fat_tag_len_offset - record_size ..][0..2], .little) >
        fat_tag_bytes_capacity) return error.CorruptRecord;
    return frame;
}

/// Re-stamp one in-memory frame (compaction's copied generation, the
/// shutdown flush's generation): the write clock moves into the header,
/// the SHA-256 content hash and the frame checksum recompute — the
/// header's checksum field zeroed for both, per the frame's own
/// convention.
pub fn frame_restamp(frame: *FatFrame, stamp: u64) void {
    frame.header.stamp = stamp;
    const bytes = mem.asBytes(frame);
    frame.header.checksum = 0;
    var sha: [fat_sha_size]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes[0..fat_sha_offset], &sha, .{});
    @memcpy(bytes[fat_sha_offset..][0..fat_sha_size], &sha);
    frame.header.checksum = wal_checksum(bytes);
}

// ---------------------------------------------------------------------------
// The IO seam: the sync backend this build drives the engine through.
// ---------------------------------------------------------------------------

/// The synchronous page-cached blocking IO backend. Plain posix
/// pwrite/pread, on top of the vendored `io/common.zig` primitives, with
/// one blocking fsync (the shutdown generation's only fsync). The async
/// backends replace this type; the engine's format and logic never change.
pub const SyncIO = struct {
    fd: posix.fd_t,
    /// The fsyncs completed through this handle — the "exactly one" audit
    /// of the shutdown flush, and honest instrumentation of the backend.
    fsync_count: usize = 0,

    /// Open (create or open, never truncate) the fixed-size `.wal` file.
    /// A fresh file is pre-sized to `file_size`; an existing file must
    /// already be exactly `file_size` — anything else is refused (the
    /// layout's every offset is fixed; there is no negotiation). The open
    /// takes the file's exclusive lock non-blocking: the engine has
    /// exactly one owner, and a second opener fails fast instead of
    /// waiting.
    pub fn open(path: []const u8) !SyncIO {
        const dir_path = std.fs.path.dirname(path) orelse ".";
        const dir_fd = try posix.open(dir_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        defer posix.close(dir_fd);

        // The vendored open's shape: create without truncation, exclusive
        // lock, fsync the file and its parent directory, once.
        const dir = std.fs.Dir{ .fd = dir_fd };
        const file = try dir.createFile(std.fs.path.basename(path), .{
            .read = true,
            .truncate = false,
            .exclusive = false,
            .lock = .exclusive,
            .lock_nonblocking = true,
        });
        errdefer file.close();

        try file.sync();
        try posix.fsync(dir_fd);

        const size = (try file.stat()).size;
        if (size == 0) {
            try file.setEndPos(file_size);
        } else if (size != file_size) {
            return error.WalFileFormat;
        }
        return .{ .fd = file.handle };
    }

    /// Closes the file descriptor. A dirty close drops the in-flight
    /// state by contract (the documented loss window) — the durability
    /// the caller wanted belongs to the shutdown flush's `fsync`.
    pub fn close(self: SyncIO) void {
        common.aof_blocking_close(self.fd);
    }

    /// One blocking pwrite at the fixed offset (the record's slot knows
    /// it). The write is page-cached: no fsync, per the zero-fsync
    /// ruling — the shutdown generation's `fsync` is the only one.
    pub fn write_at(self: *SyncIO, bytes: []const u8, offset: u64) !void {
        const file = std.fs.File{ .handle = self.fd };
        try file.pwriteAll(bytes, offset);
    }

    /// A blocking pread that answers only when the whole span landed
    /// (short reads are the read path's torn-record evidence, never a
    /// silent partial copy).
    pub fn pread_all(self: *SyncIO, buffer: []u8, offset: u64) !usize {
        return common.aof_blocking_pread_all(self.fd, buffer, offset);
    }

    /// The one blocking fsync (the shutdown generation). Mirrors the
    /// vendored blocking backend's `fsync` error surface.
    pub fn fsync(self: *SyncIO) !void {
        const rc = posix.system.fsync(self.fd);
        switch (posix.errno(rc)) {
            .SUCCESS, .INTR => {},
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .ROFS => return error.AccessDenied,
            else => |err| return posix.unexpectedErrno(err),
        }
        self.fsync_count += 1;
    }
};

// ---------------------------------------------------------------------------
// The engine.
// ---------------------------------------------------------------------------

/// A stream's alternating pairs: A and B, the rotating two-copy
/// collection. Writes land in the active pair; compaction copies the
/// live set forward into `other` and the pair flips.
pub const Pair = enum(u1) {
    a,
    b,

    /// The pair a compaction copies into (the active pair's alternate).
    fn other(self: Pair) Pair {
        return @enumFromInt(@intFromEnum(self) ^ 1);
    }
};

/// A stream's ring bases: the stream's own 4 MiB half, each pair's 2 MiB
/// block, the header ring one span above its data ring.
fn stream_base(stream: Stream) u64 {
    return @as(u64, @intFromEnum(stream)) * 4 * ring_span;
}

/// The data-ring base offset of one stream's pair.
pub fn data_base(stream: Stream, pair: Pair) u64 {
    return stream_base(stream) + @as(u64, @intFromEnum(pair)) * 2 * ring_span;
}

/// The header-ring base offset of one stream's pair.
pub fn header_base(stream: Stream, pair: Pair) u64 {
    return data_base(stream, pair) + ring_span;
}

/// One slot's frame offset in the durable data ring.
pub fn frame_offset(stream: Stream, pair: Pair, slot: u32) u64 {
    return data_base(stream, pair) + @as(u64, slot) * fat_frame_size;
}

comptime {
    // The layout's own arithmetic: the largest capacity's every ring ends
    // inside the 8 MiB file.
    assert(data_base(.durable, .b) + @as(u64, ring_capacity_max) * fat_frame_size <= file_size);
    assert(header_base(.durable, .b) + @as(u64, ring_capacity_max) * header_record_size <= file_size);
    assert(data_base(.ephemeral, .b) + @as(u64, ring_capacity_max) * record_size <=
        data_base(.durable, .a));
    // The record header sits at the frame's front; the name/counters/sha
    // areas are the frame-data offsets the codec addresses.
    assert(fat_name_len_offset - record_size == 0);
    assert(fat_counters_offset - record_size == 320);
    assert(fat_sha_offset - record_size == 448);
}

/// The operator knob.
pub const Config = struct {
    /// Fixed record count per ring.
    capacity: u32 = capacity_default,
    /// The read path's clock-drift safety threshold.
    drift_threshold_ns: u64 = drift_threshold_ns_default,
};

/// The engine's readable counters (the status surface; the design doc's
/// "knowledge of last sync"). Plain loop-owned integers: the caller is
/// sans-IO and single-threaded, and drives every call from one thread.
pub const Status = struct {
    /// Generations fully written since open.
    completed_generations: u64,
    /// Records landed since open.
    completed_records: u64,
    /// Nanosecond timestamp of the last completed write.
    last_completed_unix_ns: u64,
    /// Submissions outstanding (0 or 1 generation's worth); always 0
    /// between calls on the synchronous backend.
    in_flight: u32,
    /// Writes refused (capacity) since open — the steady path's refusals
    /// and the flush path's failed stops alike.
    refusals: u64,
};

/// One ephemeral live-set entry. The `header` is the entry's on-disk
/// header twin (the hydration's twin agreement: the identity prefix
/// byte-equal, the tag equal as a field); the `slot` is the record's
/// position in the active pair at the time it entered the map — used by
/// the load path's hydration, never after.
const EphemeralEntry = struct {
    record: WalRecord,
    header: WalHeader,
    slot: u32,
};

/// One durable live-set entry: the whole decoded fat frame (the identity,
/// the name, the counters, the tag bytes), its header-ring twin, and its
/// slot. Kept records are entries like any other — they ride compaction's
/// copied live set with the live ones.
const DurableEntry = struct {
    frame: FatFrame,
    header: WalHeader,
    slot: u32,
};

/// One stream's rotating state: the active pair (the newest generation;
/// the write path), the forward position — the next record index to
/// write, compaction fires when this reaches `capacity` — and the
/// in-memory live set (the engine's own knowledge of the stream's lock
/// table, last record per lock id, drops applied). Rebuilt on open by the
/// stream's scan; maintained by every submit.
fn StreamState(comptime Entry: type) type {
    return struct {
        active: Pair = .a,
        position: u32 = 0,
        live: std.AutoHashMapUnmanaged(u64, Entry) = .{},

        fn deinit(self: *@This(), allocator: mem.Allocator) void {
            self.live.deinit(allocator);
        }
    };
}

const EphemeralState = StreamState(EphemeralEntry);
const DurableState = StreamState(DurableEntry);

/// The two-stream double-ring rotating WAL engine. Opened against a
/// fixed-size `.wal` file; on open it selects each stream's epoch (the
/// newest generation's pair, per stream) and loads both active pairs'
/// live sets. The caller then drives steady ticks (`submit` /
/// `submit_durable`, one record per changed lock per stream) and the
/// shutdown flush (`flush`, both streams' full live sets + exactly one
/// fsync total — the streams share the one file descriptor).
pub fn WalType(comptime IO: type) type {
    comptime {
        assert(@hasDecl(IO, "write_at"));
        assert(@hasDecl(IO, "pread_all"));
        assert(@hasDecl(IO, "fsync"));
    }

    return struct {
        const Engine = @This();

        io: IO,
        allocator: mem.Allocator,
        capacity: u32,
        drift_ns: u64,

        /// The ephemeral stream's rotating state (the hot path).
        eph: EphemeralState = .{},
        /// The durable stream's rotating state (the named locks).
        dur: DurableState = .{},

        completed_generations: u64 = 0,
        completed_records: u64 = 0,
        last_completed_unix_ns: u64 = 0,
        refusals: u64 = 0,
        in_flight: u32 = 0,

        /// One stream's state, typed by the stream. Comptime stream
        /// parameter: the branch is resolved at compile time, no runtime
        /// stream dispatch anywhere on the paths.
        fn stream_state(self: *Engine, comptime stream: Stream) if (stream == .ephemeral) *EphemeralState else *DurableState {
            return if (stream == .ephemeral) &self.eph else &self.dur;
        }

        /// Open + select both streams' epochs + load both live sets.
        /// `now_ns` is the reader's clock (the expiry skip's reference
        /// point). Either stream's content refusal refuses the open.
        pub fn open(allocator: mem.Allocator, io: IO, config: Config, now_ns: u64) !Engine {
            if (config.capacity == 0 or config.capacity > ring_capacity_max) {
                return error.WalInvalidConfig;
            }

            var wal = Engine{
                .io = io,
                .allocator = allocator,
                .capacity = config.capacity,
                .drift_ns = config.drift_threshold_ns,
            };
            errdefer wal.deinit();

            try wal.select_epoch(.ephemeral);
            try wal.scan(.ephemeral, now_ns);
            try wal.select_epoch(.durable);
            try wal.scan(.durable, now_ns);
            return wal;
        }

        pub fn deinit(self: *Engine) void {
            self.eph.deinit(self.allocator);
            self.dur.deinit(self.allocator);
        }

        /// The counters' snapshot — the engine's own submit-time view;
        /// the C ABI's `WalStatus` (completion-driven, per stream) is the
        /// exposed truth.
        pub fn status(self: *const Engine) Status {
            return .{
                .completed_generations = self.completed_generations,
                .completed_records = self.completed_records,
                .last_completed_unix_ns = self.last_completed_unix_ns,
                .in_flight = self.in_flight,
                .refusals = self.refusals,
            };
        }

        /// The ephemeral stream's live-set size.
        pub fn live_count(self: *const Engine) usize {
            return self.eph.live.count();
        }

        /// The ephemeral live set's record for `lock_id`, or null.
        pub fn live_get(self: *const Engine, lock_id: u64) ?WalRecord {
            if (self.eph.live.get(lock_id)) |entry| return entry.record;
            return null;
        }

        /// The durable stream's live-set size (live and kept records
        /// alike).
        pub fn dur_live_count(self: *const Engine) usize {
            return self.dur.live.count();
        }

        /// The durable live set's decoded fat frame for `lock_id`, or
        /// null.
        pub fn dur_live_get(self: *const Engine, lock_id: u64) ?FatFrame {
            if (self.dur.live.get(lock_id)) |entry| return entry.frame;
            return null;
        }

        /// The ephemeral stream's active pair's next slot (the position
        /// the write path lands in).
        pub fn eph_position(self: *const Engine) u32 {
            return self.eph.position;
        }

        /// The durable stream's active pair's next slot.
        pub fn dur_position(self: *const Engine) u32 {
            return self.dur.position;
        }

        /// The ephemeral live set encoded as on-disk data records into
        /// `buf` — the C ABI's load wire format, byte-identical to the
        /// submit path's input (one 64-byte record per live lock).
        /// Returns the byte count (0 = the live set is empty);
        /// `error.WalBufferTooSmall` when `buf` cannot hold the whole set
        /// — never a partial copy.
        pub fn live_encode(self: *const Engine, buf: []u8) !usize {
            const need = self.eph.live.count() * record_size;
            if (buf.len < need) return error.WalBufferTooSmall;

            var written: usize = 0;
            var it = self.eph.live.iterator();
            while (it.next()) |entry| {
                record_encode(buf[written..][0..record_size], entry.value_ptr.record);
                written += record_size;
            }
            return written;
        }

        /// The durable stream's live set encoded as on-disk fat frames
        /// into `buf` — the C ABI's durable load wire format, byte-identical
        /// to the durable submit path's input (one 768-byte frame per live
        /// lock, live and kept kinds alike). Returns the byte count (0 =
        /// the live set is empty); `error.WalBufferTooSmall` when `buf`
        /// cannot hold the whole set — never a partial copy.
        pub fn dur_live_encode(self: *const Engine, buf: []u8) !usize {
            const need = self.dur.live.count() * fat_frame_size;
            if (buf.len < need) return error.WalBufferTooSmall;

            var written: usize = 0;
            var it = self.dur.live.iterator();
            while (it.next()) |entry| {
                @memcpy(
                    buf[written..][0..fat_frame_size],
                    mem.asBytes(&entry.value_ptr.frame),
                );
                written += fat_frame_size;
            }
            return written;
        }

        /// The ephemeral stream's steady-tick write: one record forward
        /// through the active pair — a live record for acquire/renew, a
        /// tombstone for release. Page-cached, zero fsync. When the pair
        /// is full, the compaction fires first (the copy collection) and
        /// the pairs flip. When the record would still not fit (the live
        /// set has filled the ring), the write is refused and counted; the
        /// serving state is unaffected.
        pub fn submit(self: *Engine, record: WalRecord, now_ns: u64) !void {
            assert(self.in_flight == 0);
            if (record.lock_id == 0) return error.InvalidRecord;
            if (tag_decode(record.tag) == null) return error.InvalidRecord;

            self.in_flight = 1;
            defer self.in_flight = 0;

            const st = &self.eph;
            if (st.position == self.capacity) try self.compact(.ephemeral, now_ns);
            if (st.position == self.capacity) {
                // The live set fills the ring: no slot exists for the
                // record. A counted refusal, never a silent partial write.
                self.refusals += 1;
                return error.WalCapacity;
            }

            try self.write_ephemeral(record, st.position, st.active);
            switch (record.kind()) {
                .live => try st.live.put(self.allocator, record.lock_id, .{
                    .record = record,
                    .header = header_record_of(record),
                    .slot = st.position,
                }),
                .tombstone => _ = st.live.remove(record.lock_id),
            }
            st.position += 1;
            self.completed_records += 1;
            self.last_completed_unix_ns = now_ns;
        }

        /// The durable stream's steady-tick write: one fat frame forward
        /// through the active pair — live for acquire/create, kept for a
        /// release that leaves the record standing (the record survives,
        /// it stays in the live set and rides compaction), delete for the
        /// destruction. The frame is encoded here — the one codec stamps
        /// the sha and the frame checksum — written, and mirrored into the
        /// engine's own live set. Compaction and capacity honesty follow
        /// the ephemeral stream's rules, per stream.
        pub fn submit_durable(self: *Engine, change: DurableChange, now_ns: u64) !void {
            assert(self.in_flight == 0);
            if (change.record.lock_id == 0) return error.InvalidRecord;
            const kind = tag_decode_durable(change.record.tag) orelse return error.InvalidRecord;
            if (change.name.len > fat_name_capacity) return error.RecordTooLarge;
            if (change.tag_bytes.len > fat_tag_bytes_capacity) return error.RecordTooLarge;

            self.in_flight = 1;
            defer self.in_flight = 0;

            const st = &self.dur;
            if (st.position == self.capacity) try self.compact(.durable, now_ns);
            if (st.position == self.capacity) {
                self.refusals += 1;
                return error.WalCapacity;
            }

            var bytes: [fat_frame_size]u8 = undefined;
            try frame_encode(&bytes, change);
            const frame = mem.bytesToValue(FatFrame, &bytes);
            const header_record = header_record_of(frame.header);

            try self.write_durable(&bytes, header_record, st.position, st.active);
            switch (kind) {
                .live, .kept => try st.live.put(self.allocator, frame.header.lock_id, .{
                    .frame = frame,
                    .header = header_record,
                    .slot = st.position,
                }),
                .delete => _ = st.live.remove(frame.header.lock_id),
            }
            st.position += 1;
            self.completed_records += 1;
            self.last_completed_unix_ns = now_ns;
        }

        /// The host's generation boundary: the caller marks the tick's
        /// batch complete once every changed lock's record has been
        /// submitted.
        /// Marks one generation fully submitted (the engine's own
        /// submit-time bookkeeping; the ABI's completion counters are
        /// the exposed truth).
        pub fn complete_generation(self: *Engine) void {
            self.completed_generations += 1;
        }

        /// The shutdown flush: both streams' own live sets written forward
        /// through their active pairs in the foreground, then exactly one
        /// fsync — the one fsync covers both streams (they share the one
        /// file descriptor). Capacity overrun here is a failure — the
        /// failed stop of the law — never a silent partial write.
        pub fn flush(self: *Engine, now_ns: u64) !void {
            const records = try self.allocator.alloc(WalRecord, self.eph.live.count());
            defer self.allocator.free(records);

            var i: usize = 0;
            var it = self.eph.live.iterator();
            while (it.next()) |entry| : (i += 1) {
                records[i] = entry.value_ptr.record;
            }

            const frames = try self.allocator.alloc(FatFrame, self.dur.live.count());
            defer self.allocator.free(frames);

            var j: usize = 0;
            var dit = self.dur.live.iterator();
            while (dit.next()) |entry| : (j += 1) {
                frames[j] = entry.value_ptr.frame;
            }

            return self.flush_streams(records, frames, now_ns);
        }

        /// The shutdown flush over caller-supplied live sets (the C ABI's
        /// flush path: the host's lock table is the authority and passes
        /// the sets it wants durable — the ephemeral set as records, the
        /// durable set as frames). Same shape as `flush`: both sets
        /// written forward through their active pairs in the foreground,
        /// then exactly one fsync; a capacity overrun on either stream is
        /// the failed stop. Records and frames are re-stamped with
        /// `now_ns` (the shutdown generation's own stamp) and the engine's
        /// in-memory live sets are untouched.
        pub fn flush_records(
            self: *Engine,
            records: []const WalRecord,
            frames: []const FatFrame,
            now_ns: u64,
        ) !void {
            return self.flush_streams(records, frames, now_ns);
        }

        /// The flush's shared body: the ephemeral set through the
        /// ephemeral pair, the durable set through the durable pair, one
        /// fsync total. Per-stream capacity honesty
        /// (`position + live ≤ capacity`); the refusal is counted once and
        /// nothing lands.
        fn flush_streams(
            self: *Engine,
            eph_records: []const WalRecord,
            dur_frames: []const FatFrame,
            now_ns: u64,
        ) !void {
            assert(self.in_flight == 0);

            if (@as(u64, self.eph.position) + eph_records.len > self.capacity or
                @as(u64, self.dur.position) + dur_frames.len > self.capacity)
            {
                self.refusals += 1;
                return error.WalCapacity;
            }

            self.in_flight = 1;
            defer self.in_flight = 0;

            var slot = self.eph.position;
            for (eph_records) |record| {
                var stamped = record;
                stamped.stamp = now_ns; // the shutdown generation's own stamp
                try self.write_ephemeral(stamped, slot, self.eph.active);
                self.completed_records += 1;
                slot += 1;
            }
            self.eph.position = slot;

            var frame_slot = self.dur.position;
            for (dur_frames) |source| {
                var frame = source;
                frame_restamp(&frame, now_ns);
                var bytes: [fat_frame_size]u8 = undefined;
                @memcpy(&bytes, mem.asBytes(&frame));
                try self.write_durable(
                    &bytes,
                    header_record_of(frame.header),
                    frame_slot,
                    self.dur.active,
                );
                self.completed_records += 1;
                frame_slot += 1;
            }
            self.dur.position = frame_slot;

            try self.io.fsync();

            self.completed_generations += 1;
            self.last_completed_unix_ns = now_ns;
        }

        // -- the write machinery ------------------------------------------------

        /// One ephemeral record's pair write: the NOT-flipped data slot,
        /// then the header slot. Data first, then header: the header ring
        /// is the detector — a header record present implies its data twin
        /// was written.
        fn write_ephemeral(self: *Engine, record: WalRecord, slot: u32, pair: Pair) !void {
            assert(slot < self.capacity);

            var data: [record_size]u8 = undefined;
            record_encode(&data, record);
            not_flip(&data);
            try self.io.write_at(&data, data_base(.ephemeral, pair) + @as(u64, slot) * record_size);

            const header_record = header_record_of(record);
            try self.io.write_at(
                mem.asBytes(&header_record),
                header_base(.ephemeral, pair) + @as(u64, slot) * header_record_size,
            );
        }

        /// One durable frame's pair write: the 768-byte fat frame as one
        /// data-ring write (the frame is the unit), then the header slot.
        fn write_durable(
            self: *Engine,
            frame_bytes: *const [fat_frame_size]u8,
            header_record: WalHeader,
            slot: u32,
            pair: Pair,
        ) !void {
            assert(slot < self.capacity);

            try self.io.write_at(frame_bytes, frame_offset(.durable, pair, slot));
            try self.io.write_at(
                mem.asBytes(&header_record),
                header_base(.durable, pair) + @as(u64, slot) * header_record_size,
            );
        }

        /// Compaction on fill, per stream: the stream's current live set
        /// serialized into the inactive pair from its start — for the
        /// durable stream including the kept records, which are live-set
        /// entries like any other — then the pairs flip. The copied
        /// generation is re-stamped with the copy's write time — the epoch
        /// selector is the write clock, and the compacted pair must always
        /// win the epoch selection over the pair it replaced. The copied
        /// generation lands as contiguous runs: one data-ring write and
        /// one header-ring write (the durable data run is 768 B × N whole
        /// frames, one op). The copied pair's header tail is zeroed so the
        /// scan's zero-termination stays exact past the copied records.
        fn compact(self: *Engine, comptime stream: Stream, now_ns: u64) !void {
            const st = self.stream_state(stream);
            assert(st.position == self.capacity);
            assert(st.live.count() <= self.capacity);

            const target = st.active.other();
            const count: usize = st.live.count();
            const is_ephemeral = stream == .ephemeral;
            const unit: usize = if (is_ephemeral) record_size else fat_frame_size;

            const data_run = try self.allocator.alloc(u8, count * unit);
            defer self.allocator.free(data_run);
            const header_run = try self.allocator.alloc(u8, count * header_record_size);
            defer self.allocator.free(header_run);

            var data_written: usize = 0;
            var header_written: usize = 0;
            var it = st.live.iterator();
            while (it.next()) |entry| {
                if (is_ephemeral) {
                    var record = entry.value_ptr.record;
                    record.stamp = now_ns;
                    record_encode(data_run[data_written..][0..record_size], record);
                    not_flip(data_run[data_written..][0..record_size]);
                    const header_record = header_record_of(record);
                    @memcpy(
                        header_run[header_written..][0..header_record_size],
                        mem.asBytes(&header_record),
                    );
                } else {
                    var frame = entry.value_ptr.frame;
                    frame_restamp(&frame, now_ns);
                    @memcpy(
                        data_run[data_written..][0..fat_frame_size],
                        mem.asBytes(&frame),
                    );
                    const header_record = header_record_of(frame.header);
                    @memcpy(
                        header_run[header_written..][0..header_record_size],
                        mem.asBytes(&header_record),
                    );
                }
                data_written += unit;
                header_written += header_record_size;
                self.completed_records += 1;
            }

            try self.io.write_at(
                data_run,
                if (is_ephemeral)
                    data_base(.ephemeral, target)
                else
                    frame_offset(.durable, target, 0),
            );
            try self.io.write_at(header_run, header_base(stream, target));
            try self.zero_header_tail(stream, target, @intCast(count));

            st.active = target;
            st.position = @intCast(count);
        }

        fn zero_header_tail(
            self: *Engine,
            comptime stream: Stream,
            pair: Pair,
            from_slot: u32,
        ) !void {
            if (from_slot >= self.capacity) return;

            var zeros = std.mem.zeroes([4096]u8);
            var remaining: u64 = @as(u64, self.capacity - from_slot) * header_record_size;
            var offset = header_base(stream, pair) + @as(u64, from_slot) * header_record_size;
            while (remaining > 0) {
                const chunk: usize = @intCast(@min(remaining, zeros.len));
                try self.io.write_at(zeros[0..chunk], offset);
                offset += chunk;
                remaining -= chunk;
            }
        }

        // -- the read machinery -------------------------------------------------

        /// A record is expired once `now` is past `expiry` by more than the
        /// clock-drift threshold (the reader may sit behind or ahead of the
        /// leader's clock).
        fn expired_at(self: *const Engine, expiry: u64, now_ns: u64) bool {
            return (expiry +| self.drift_ns) < now_ns;
        }

        /// Epoch selection, per stream: the first header record of each
        /// pair's header ring; the newest ns stamp names the active
        /// generation. Both empty = cold start (the engine then behaves as
        /// if it never existed). An exact stamp tie is unorderable wall
        /// clock — pair A wins the tie, deterministically.
        fn select_epoch(self: *Engine, comptime stream: Stream) !void {
            const stamp_a = try self.pair_epoch(stream, .a);
            const stamp_b = try self.pair_epoch(stream, .b);
            self.stream_state(stream).active = if (stamp_a == null and stamp_b == null)
                .a // cold start
            else if (stamp_a == null)
                .b
            else if (stamp_b == null)
                .a
            else if (stamp_a.? >= stamp_b.?)
                .a
            else
                .b;
        }

        /// One pair's epoch, per stream: its first header record's stamp,
        /// null when the pair has never been written.
        fn pair_epoch(self: *Engine, comptime stream: Stream, pair: Pair) !?u64 {
            var slot: [header_record_size]u8 = undefined;
            const got = try self.io.pread_all(&slot, header_base(stream, pair));
            if (got < header_record_size) return error.TornRecord;
            if (mem.allEqual(u8, &slot, 0)) return null;
            const header = header_record_decode(&slot) catch return error.CorruptRecord;
            return header.stamp;
        }

        /// The scan, per stream: a forward scan of the active pair's
        /// header ring only — the fast path is tiny headers, and only the
        /// live set is ever lifted.
        fn scan(self: *Engine, comptime stream: Stream, now_ns: u64) !void {
            switch (comptime stream) {
                .ephemeral => try self.scan_ephemeral(now_ns),
                .durable => try self.scan_durable(now_ns),
            }
        }

        /// The ephemeral stream's scan. The ring is zero-terminated (every
        /// pair's header tail is zeroed past its live content at
        /// compaction, and a fresh file is zero). Records already expired
        /// (beyond the drift threshold) drop their lock — a natural expiry
        /// writes nothing, and an expired record never lets an older
        /// record resurrect. Last record per lock id wins; a tombstone
        /// drops the lock. Survivors hydrate from the data ring — the data
        /// slot is the record's bitwise NOT, un-flipped on read — each
        /// demanding its header checksum, its data checksum, and twin
        /// agreement between the rings: the 32-byte identity prefix
        /// (stamp, expiry, lock id, lease id) byte-equal across both
        /// rings, and the tag checked as a field (its offsets differ
        /// between the records).
        fn scan_ephemeral(self: *Engine, now_ns: u64) !void {
            const st = &self.eph;
            var slot: u32 = 0;
            var found_end = false;
            while (slot < self.capacity) : (slot += 1) {
                var record_bytes: [header_record_size]u8 = undefined;
                const got = try self.io.pread_all(
                    &record_bytes,
                    header_base(.ephemeral, st.active) + @as(u64, slot) * header_record_size,
                );
                if (got < header_record_size) return error.TornRecord;
                if (mem.allEqual(u8, &record_bytes, 0)) {
                    found_end = true;
                    break;
                }
                const header = header_record_decode(&record_bytes) catch
                    return error.CorruptRecord;

                if (self.expired_at(header.expiry, now_ns)) {
                    _ = st.live.remove(header.lock_id);
                    continue;
                }
                const kind = tag_decode(header.tag) orelse return error.CorruptRecord;
                switch (kind) {
                    .live => try st.live.put(self.allocator, header.lock_id, .{
                        .record = .{
                            .stamp = header.stamp,
                            .expiry = header.expiry,
                            .lock_id = header.lock_id,
                            .lease_id = header.lease_id,
                            .tag = header.tag,
                        },
                        .header = header,
                        .slot = slot,
                    }),
                    .tombstone => _ = st.live.remove(header.lock_id),
                }
            }
            st.position = if (found_end) slot else self.capacity;

            // Hydrate the survivors from the data ring: the data slot is
            // the record's bitwise NOT — un-flip, then the header
            // checksum + data checksum + twin agreement, or refuse.
            var it = st.live.iterator();
            while (it.next()) |entry| {
                var data: [record_size]u8 = undefined;
                const got = try self.io.pread_all(
                    &data,
                    data_base(.ephemeral, st.active) + @as(u64, entry.value_ptr.slot) * record_size,
                );
                if (got < record_size) return error.TornRecord;
                not_flip(&data);
                const record = record_decode(&data) catch return error.CorruptRecord;

                // Twin agreement: the identity prefix byte-equal across the
                // rings, the tag equal as a field.
                const identity = mem.asBytes(&record)[0..identity_size];
                const header_identity = mem.asBytes(&entry.value_ptr.header)[0..identity_size];
                if (!mem.eql(u8, identity, header_identity) or
                    record.tag != entry.value_ptr.header.tag) return error.CorruptRecord;

                entry.value_ptr.record = record;
            }
        }

        /// The durable stream's scan: the same zero-terminated forward
        /// scan of the active pair's header ring. Kinds: live and kept
        /// keep the lock (a kept record is released, not destroyed — it
        /// carries no expiry and is never dropped here), delete drops it;
        /// last record per lock id wins. A durable record expires only
        /// when it carries an expiry (0 = none). Survivors hydrate from
        /// the durable data ring: the whole 12-CL fat frame, its frame
        /// checksum and sha verified, and twin agreement between the CL0
        /// header and the header ring's record — the identity prefix
        /// byte-equal, the tag equal as a field.
        fn scan_durable(self: *Engine, now_ns: u64) !void {
            const st = &self.dur;
            var slot: u32 = 0;
            var found_end = false;
            while (slot < self.capacity) : (slot += 1) {
                var record_bytes: [header_record_size]u8 = undefined;
                const got = try self.io.pread_all(
                    &record_bytes,
                    header_base(.durable, st.active) + @as(u64, slot) * header_record_size,
                );
                if (got < header_record_size) return error.TornRecord;
                if (mem.allEqual(u8, &record_bytes, 0)) {
                    found_end = true;
                    break;
                }
                const header = header_record_decode(&record_bytes) catch
                    return error.CorruptRecord;

                if (header.expiry != 0 and self.expired_at(header.expiry, now_ns)) {
                    _ = st.live.remove(header.lock_id);
                    continue;
                }
                const kind = tag_decode_durable(header.tag) orelse return error.CorruptRecord;
                switch (kind) {
                    .live, .kept => try st.live.put(self.allocator, header.lock_id, .{
                        .frame = .{},
                        .header = header,
                        .slot = slot,
                    }),
                    .delete => _ = st.live.remove(header.lock_id),
                }
            }
            st.position = if (found_end) slot else self.capacity;

            var it = st.live.iterator();
            while (it.next()) |entry| {
                var frame_bytes: [fat_frame_size]u8 = undefined;
                const got = try self.io.pread_all(
                    &frame_bytes,
                    frame_offset(.durable, st.active, entry.value_ptr.slot),
                );
                if (got < fat_frame_size) return error.TornRecord;
                const frame = frame_decode(&frame_bytes) catch return error.CorruptRecord;

                // Twin agreement: the CL0 header's identity prefix
                // byte-equal with the header ring's record, the tag equal
                // as a field.
                const identity = mem.asBytes(&frame.header)[0..identity_size];
                const header_identity = mem.asBytes(&entry.value_ptr.header)[0..identity_size];
                if (!mem.eql(u8, identity, header_identity) or
                    frame.header.tag != entry.value_ptr.header.tag) return error.CorruptRecord;

                entry.value_ptr.frame = frame;
            }
        }
    };
}

/// The synchronous-backend engine instantiation — the type the engine's
/// own tests drive; the C ABI instantiates the seam per platform.
pub const Wal = WalType(SyncIO);

// ---------------------------------------------------------------------------
// Tests (deterministic, defensive).
// ---------------------------------------------------------------------------

const testing = std.testing;

const Holder: [16]u8 = "holder-uuid-0001".*;
const Window: u64 = 30_000;

fn test_open(
    allocator: mem.Allocator,
    path: []const u8,
    config: Config,
    now_ns: u64,
) !struct { io: SyncIO, wal: Wal } {
    const io = try SyncIO.open(path);
    errdefer io.close();
    const wal = try Wal.open(allocator, io, config, now_ns);
    return .{ .io = io, .wal = wal };
}

fn tmp_wal_path(allocator: mem.Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    const abs = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(abs);
    return try std.fs.path.join(allocator, &.{ abs, "snapshot.wal" });
}

/// Write one raw byte at a fixed file offset (the fault injection the
/// corruption tests use).
fn poke(path: []const u8, offset: u64, byte: u8) !void {
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();
    try file.pwriteAll(&.{byte}, offset);
}

/// Write raw zero bytes at a fixed file offset.
fn poke_zeros(path: []const u8, offset: u64, count: usize) !void {
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();
    var zeros = std.mem.zeroes([4096]u8);
    try file.pwriteAll(zeros[0..count], offset);
}

/// Copy raw bytes from one file offset to another (the byte swap the
/// twin-agreement tests use: two individually valid records whose twins
/// disagree).
fn copy_bytes(path: []const u8, from: u64, to: u64, len: usize) !void {
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();
    var buf: [4096]u8 = undefined;
    const got = try file.preadAll(buf[0..len], from);
    try file.pwriteAll(buf[0..got], to);
}

test "wal: cold start is empty" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try testing.expectEqual(Pair.a, opened.wal.eph.active);
        try testing.expectEqual(@as(u32, 0), opened.wal.eph.position);
        try testing.expectEqual(@as(usize, 0), opened.wal.live_count());
        const status = opened.wal.status();
        try testing.expectEqual(@as(u64, 0), status.completed_generations);
        try testing.expectEqual(@as(u64, 0), status.completed_records);
        try testing.expectEqual(@as(u64, 0), status.refusals);
        try testing.expectEqual(@as(u32, 0), status.in_flight);
    }

    // Reopening the same file stays cold.
    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();
    try testing.expectEqual(Pair.a, reopened.wal.eph.active);
    try testing.expectEqual(@as(usize, 0), reopened.wal.live_count());
}

test "wal: record encode/decode round trip and checksum rejection" {
    const record = WalRecord.live(42, 100, 7, 8, Holder, Window);
    var data: [record_size]u8 = undefined;
    record_encode(&data, record);

    const decoded = try record_decode(&data);
    try testing.expectEqual(record.stamp, decoded.stamp);
    try testing.expectEqual(record.expiry, decoded.expiry);
    try testing.expectEqual(record.lock_id, decoded.lock_id);
    try testing.expectEqual(record.lease_id, decoded.lease_id);
    try testing.expectEqual(record.kind(), decoded.kind());
    try testing.expectEqualSlices(u8, &record.holder, &decoded.holder);
    try testing.expectEqual(record.lease_ms, decoded.lease_ms);

    // A flipped bit anywhere in the covered bytes breaks the checksum.
    inline for (.{ 3, 20, 40 }) |offset| {
        var broken: [record_size]u8 = undefined;
        record_encode(&broken, record);
        broken[offset] ^= 0xFF;
        try testing.expectError(error.CorruptRecord, record_decode(&broken));
    }
    // A flipped checksum byte is a rejection too.
    data[checksum_data_offset + 1] ^= 0x01;
    try testing.expectError(error.CorruptRecord, record_decode(&data));

    // The header record's own round trip and rejection: the write path
    // (the checksum-stamped header) decodes back to the identity the
    // record was built from.
    const stamped = header_record_of(WalRecord.tombstone(7, 9, 10));
    const header = try header_record_decode(mem.asBytes(&stamped));
    try testing.expectEqual(@as(u64, 7), header.stamp);
    try testing.expectEqual(@as(u64, 9), header.lock_id);
    try testing.expectEqual(@as(u64, 10), header.lease_id);
    try testing.expectEqual(Kind.tombstone, tag_decode(header.tag).?);
    var header_record: [header_record_size]u8 = undefined;
    @memcpy(&header_record, mem.asBytes(&stamped));
    header_record[10] ^= 0x80;
    try testing.expectError(error.CorruptRecord, header_record_decode(&header_record));

    // A tag from another format version, or outside the kind codes, is not
    // a record.
    try testing.expect(tag_decode(0) == null);
    try testing.expect(tag_decode(0x0103) == null); // unknown kind
    try testing.expect(tag_decode(0x0201) == null); // a future format version
    var bogus = record;
    var bogus_bytes: [record_size]u8 = undefined;
    bogus.tag = 0x0201; // a future format version
    record_encode(&bogus_bytes, bogus);
    try testing.expectError(error.CorruptRecord, record_decode(&bogus_bytes));
    bogus.tag = 3; // an unknown kind in the current version
    record_encode(&bogus_bytes, bogus);
    try testing.expectError(error.CorruptRecord, record_decode(&bogus_bytes));
}

test "wal: the record is layout-exact, memcpy-round-trippable" {
    // The struct IS the on-disk layout: zero padding, struct alignment 8,
    // size 64 — one cache line. Pinned at comptime by the struct's own
    // assert block; here the byte image proves every field sits at its
    // binding offset and the round trip through the bytes is the struct.
    const rec = WalRecord{
        .stamp = 0x0102030405060708,
        .expiry = 0x1112131415161718,
        .lock_id = 0x2122232425262728,
        .lease_id = 0x3132333435363738,
        .holder = "holder-uuid-0001".*,
        .lease_ms = 0x4142434445464748,
        .tag = 0x5152,
        .checksum = 0x6162,
    };
    const bytes = mem.asBytes(&rec);
    try testing.expectEqual(rec.stamp, mem.readInt(u64, bytes[0..8], .little));
    try testing.expectEqual(rec.expiry, mem.readInt(u64, bytes[8..16], .little));
    try testing.expectEqual(rec.lock_id, mem.readInt(u64, bytes[16..24], .little));
    try testing.expectEqual(rec.lease_id, mem.readInt(u64, bytes[24..32], .little));
    try testing.expectEqualSlices(u8, &rec.holder, bytes[32..48]);
    try testing.expectEqual(rec.lease_ms, mem.readInt(u64, bytes[48..56], .little));
    try testing.expectEqual(rec.tag, mem.readInt(u32, bytes[56..60], .little));
    try testing.expectEqual(rec.checksum, mem.readInt(u32, bytes[60..64], .little));

    const back = mem.bytesToValue(WalRecord, bytes);
    try testing.expectEqual(rec, back);

    // The header record: 40 bytes — the identity prefix shared with the
    // data record, its own tag and checksum.
    const hdr = WalHeader{
        .stamp = 0x0102030405060708,
        .expiry = 0x1112131415161718,
        .lock_id = 0x2122232425262728,
        .lease_id = 0x3132333435363738,
        .tag = 0x5152,
        .checksum = 0x6162,
    };
    const header_bytes = mem.asBytes(&hdr);
    try testing.expectEqualSlices(
        u8,
        mem.asBytes(&rec)[0..identity_size],
        header_bytes[0..identity_size],
    );
    try testing.expectEqual(hdr.tag, mem.readInt(u32, header_bytes[32..36], .little));
    try testing.expectEqual(hdr.checksum, mem.readInt(u32, header_bytes[36..40], .little));
    try testing.expectEqual(hdr, mem.bytesToValue(WalHeader, header_bytes));
}

test "wal: the fat frame codec — round trip byte-exact, budget shapes, zero fill" {
    const change = DurableChange{
        .record = durable_record(.live, 42, 100, 9, 90, Holder, Window),
        .name = "/locks/turbine-7",
        .taken_at_ms = 1_700_000_000_123,
        .renew_count = 5,
        .tag_bytes = "lane-a\x00lane-b",
    };
    var bytes: [fat_frame_size]u8 = undefined;
    try frame_encode(&bytes, change);

    const frame = try frame_decode(&bytes);
    try testing.expectEqual(@as(u64, 42), frame.header.stamp);
    try testing.expectEqual(@as(u64, 100), frame.header.expiry);
    try testing.expectEqual(@as(u64, 9), frame.header.lock_id);
    try testing.expectEqual(DurableKind.live, frame.kind());
    try testing.expectEqualSlices(u8, change.name, frame.name());
    try testing.expectEqual(change.taken_at_ms, frame.taken_at_ms());
    try testing.expectEqual(change.renew_count, frame.renew_count());
    try testing.expectEqualSlices(u8, change.tag_bytes, frame.tag_bytes());
    try testing.expectEqualSlices(u8, &Holder, &frame.header.holder);
    try testing.expectEqual(@as(u64, Window), frame.header.lease_ms);
    try testing.expect(frame.header.checksum != 0);

    // The codec is deterministic: re-encoding the decoded frame's parts
    // reproduces the on-disk bytes bit for bit.
    var again: [fat_frame_size]u8 = undefined;
    try frame_encode(&again, .{
        .record = frame.header,
        .name = frame.name(),
        .taken_at_ms = frame.taken_at_ms(),
        .renew_count = frame.renew_count(),
        .tag_bytes = frame.tag_bytes(),
    });
    try testing.expectEqualSlices(u8, &bytes, &again);

    // The budget's shapes: unused name/tag bytes are zero, and the
    // consistency area past the sha is zero-reserved.
    const name_end = fat_name_offset + change.name.len;
    try testing.expect(mem.allEqual(
        u8,
        bytes[name_end..fat_counters_offset],
        0,
    ));
    const tags_end = fat_tag_bytes_offset + change.tag_bytes.len;
    try testing.expect(mem.allEqual(u8, bytes[tags_end..fat_sha_offset], 0));
    try testing.expect(mem.allEqual(u8, bytes[fat_sha_offset + fat_sha_size ..], 0));

    // A name and tags of exactly the capacity encode and decode.
    const full_name = [_]u8{'n'} ** fat_name_capacity;
    const full_tags = [_]u8{'t'} ** fat_tag_bytes_capacity;
    var full: [fat_frame_size]u8 = undefined;
    try frame_encode(&full, .{
        .record = change.record,
        .name = &full_name,
        .tag_bytes = &full_tags,
    });
    const full_frame = try frame_decode(&full);
    try testing.expectEqualSlices(u8, &full_name, full_frame.name());
    try testing.expectEqualSlices(u8, &full_tags, full_frame.tag_bytes());

    // One byte over either budget is refused; so are a zero lock id and
    // a tag that is not a durable kind.
    try testing.expectError(
        error.RecordTooLarge,
        frame_encode(&bytes, .{ .record = change.record, .name = full_name ++ "x" }),
    );
    try testing.expectError(
        error.RecordTooLarge,
        frame_encode(&bytes, .{ .record = change.record, .tag_bytes = full_tags ++ "x" }),
    );
    var zero_lock = change;
    zero_lock.record.lock_id = 0;
    try testing.expectError(error.InvalidRecord, frame_encode(&bytes, zero_lock));
    var unknown_kind = change;
    unknown_kind.record.tag = tag_encode(.live) | 4; // kind code 4: no stream's kind
    try testing.expectError(error.InvalidRecord, frame_encode(&bytes, unknown_kind));
    unknown_kind.record.tag = tag_encode(.tombstone) | (9 << 8); // a future format version
    try testing.expectError(error.InvalidRecord, frame_encode(&bytes, unknown_kind));
}

test "wal: the fat frame checksum spans the whole 768 bytes" {
    const change = DurableChange{
        .record = durable_record(.kept, 7, 0, 3, 30, Holder, Window),
        .name = "/locks/kept-lock",
    };
    var bytes: [fat_frame_size]u8 = undefined;
    try frame_encode(&bytes, change);

    // A rotted byte in the deep consistency area (CL9, the zero-reserved
    // tail) refuses: the frame checksum covers the whole 768 bytes.
    var deep = bytes;
    deep[fat_frame_size - 1] ^= 0xFF;
    try testing.expectError(error.CorruptRecord, frame_decode(&deep));

    // A rotted name byte and a rotted sha byte refuse too.
    var rotted_name = bytes;
    rotted_name[fat_name_offset] ^= 0x01;
    try testing.expectError(error.CorruptRecord, frame_decode(&rotted_name));
    var rotted_sha = bytes;
    rotted_sha[fat_sha_offset] ^= 0x01;
    try testing.expectError(error.CorruptRecord, frame_decode(&rotted_sha));

    // A checksum-distinguishability probe: the frame's CL0 header, taken
    // alone as an ephemeral record, is NOT an ephemeral record — its
    // checksum field carries the 768-byte frame checksum and the 60-byte
    // ephemeral checksum refuses it.
    var cl0: [record_size]u8 = undefined;
    @memcpy(&cl0, bytes[0..record_size]);
    try testing.expectError(error.CorruptRecord, record_decode(&cl0));

    // A rotted checksum field itself is a refusal (the stored value is
    // compared, not recomputed into).
    var rotted_checksum = bytes;
    rotted_checksum[checksum_data_offset] ^= 0x01;
    try testing.expectError(error.CorruptRecord, frame_decode(&rotted_checksum));
}

test "wal: the fat frame layout is exact, 12 cache lines" {
    const change = DurableChange{
        .record = durable_record(.live, 1, 2, 3, 4, Holder, 5),
        .name = "x",
    };
    var bytes: [fat_frame_size]u8 = undefined;
    try frame_encode(&bytes, change);

    // The frame IS the struct's bytes: CL0 is the header record's own
    // bytes (its checksum stamped frame-wide), the name rides CL1 at its
    // fixed offset, the counters ride CL6.
    var cl0: [record_size]u8 = undefined;
    @memcpy(&cl0, bytes[0..record_size]);
    var expected: [record_size]u8 = undefined;
    record_encode(&expected, change.record);
    try testing.expect(!mem.eql(u8, &cl0, &expected)); // frame-wide checksum
    try testing.expectEqualSlices(u8, expected[0..checksum_data_offset], cl0[0..checksum_data_offset]);

    try testing.expectEqual(
        @as(u16, 1),
        mem.readInt(u16, bytes[fat_name_len_offset..][0..2], .little),
    );
    try testing.expectEqual(@as(u8, 'x'), bytes[fat_name_offset]);
    try testing.expectEqual(@as(u64, 0), mem.readInt(u64, bytes[fat_taken_at_offset..][0..8], .little));
    try testing.expectEqual(@as(u32, 0), mem.readInt(u32, bytes[fat_renew_count_offset..][0..4], .little));
    try testing.expectEqual(@as(u16, 0), mem.readInt(u16, bytes[fat_tag_len_offset..][0..2], .little));

    // Re-stamping moves the stamp and recomputes both layers; the frame
    // still decodes.
    var frame = try frame_decode(&bytes);
    frame_restamp(&frame, 999);
    try testing.expectEqual(@as(u64, 999), frame.header.stamp);
    var restamped: [fat_frame_size]u8 = undefined;
    @memcpy(&restamped, mem.asBytes(&frame));
    const back = try frame_decode(&restamped);
    try testing.expectEqual(@as(u64, 999), back.header.stamp);
    try testing.expectEqualSlices(u8, change.name, back.name());
}

test "wal: cache-line geometry — every record boundary is on a 64-byte line" {
    comptime {
        assert(record_size == 64);
        assert(@sizeOf(WalRecord) == record_size);
        // Every pair's data ring base is MiB-aligned and 64 divides 1 MiB,
        // so every slot's record offset is 64-byte aligned.
        for (.{ Pair.a, Pair.b }) |pair| {
            assert(data_base(.ephemeral, pair) % record_size == 0);
        }
    }
}

test "wal: forward write then scan read-back equals the written set" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now + 1, now + 20_000_000_000, 2, 102, Holder, Window), now + 1);
        try opened.wal.submit(WalRecord.live(now + 2, now + 30_000_000_000, 3, 103, Holder, Window), now + 2);
        try testing.expectEqual(@as(usize, 3), opened.wal.live_count());
        try testing.expectEqual(@as(u32, 3), opened.wal.eph.position);
        try testing.expectEqual(@as(u64, 3), opened.wal.status().completed_records);
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(@as(usize, 3), reopened.wal.live_count());
    for ([_]u64{ 1, 2, 3 }, [_]u64{ 101, 102, 103 }) |lock_id, lease_id| {
        const record = reopened.wal.live_get(lock_id).?;
        try testing.expectEqual(Kind.live, record.kind());
        try testing.expectEqual(lease_id, record.lease_id);
        try testing.expectEqualSlices(u8, &Holder, &record.holder);
        try testing.expectEqual(@as(u64, Window), record.lease_ms);
    }
    try testing.expectEqual(now, reopened.wal.live_get(1).?.stamp);
    try testing.expectEqual(now + 2, reopened.wal.live_get(3).?.stamp);
    try testing.expectEqual(@as(u32, 3), reopened.wal.eph.position);
}

test "wal: tombstone drops the lock" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 2, 102, Holder, Window), now);
        try testing.expectEqual(@as(usize, 2), opened.wal.live_count());

        try opened.wal.submit(WalRecord.tombstone(now + 1, 1, 101), now + 1);
        try testing.expectEqual(@as(usize, 1), opened.wal.live_count());
        try testing.expect(opened.wal.live_get(1) == null);
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();
    try testing.expect(reopened.wal.live_get(1) == null);
    try testing.expect(reopened.wal.live_get(2) != null);
}

test "wal: expiry skip with drift threshold" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        // Expired far past the threshold: skipped.
        try opened.wal.submit(
            WalRecord.live(now, now - 10 * std.time.ns_per_s, 1, 101, Holder, Window),
            now,
        );
        // Expired within the threshold (the reader may sit ahead): kept.
        try opened.wal.submit(
            WalRecord.live(now, now - 1 * std.time.ns_per_s, 2, 102, Holder, Window),
            now,
        );
        // Not expired: kept.
        try opened.wal.submit(
            WalRecord.live(now, now + 5 * std.time.ns_per_s, 3, 103, Holder, Window),
            now,
        );
        // A lock whose newest record is expired is absent — an expired
        // record never lets an older record resurrect.
        try opened.wal.submit(
            WalRecord.live(now, now + 10 * std.time.ns_per_s, 4, 104, Holder, Window),
            now,
        );
        try opened.wal.submit(
            WalRecord.live(now, now - 10 * std.time.ns_per_s, 4, 104, Holder, Window),
            now,
        );
        // The in-memory live set mirrors the written records; the expiry
        // skip is the read path's job.
        try testing.expectEqual(@as(usize, 4), opened.wal.live_count());
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expect(reopened.wal.live_get(1) == null);
    try testing.expect(reopened.wal.live_get(2) != null);
    try testing.expect(reopened.wal.live_get(3) != null);
    try testing.expect(reopened.wal.live_get(4) == null);
    try testing.expectEqual(@as(u32, 5), reopened.wal.eph.position);
}

test "wal: compaction fires at capacity, pairs flip, epoch selects the compacted pair" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{ .capacity = 4 }, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 2, 102, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 105, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 3, 103, Holder, Window), now);
        try testing.expectEqual(@as(u32, 4), opened.wal.eph.position);
        try testing.expectEqual(@as(usize, 3), opened.wal.live_count());

        // This submit fills pair A: the compaction fires first, the live
        // set {1, 2, 3} is copied into pair B, the pairs flip, then the
        // record lands on the flipped pair.
        try opened.wal.submit(WalRecord.live(now + 1, now + 10_000_000_000, 4, 104, Holder, Window), now + 1);
        try testing.expectEqual(Pair.b, opened.wal.eph.active);
        try testing.expectEqual(@as(u32, 4), opened.wal.eph.position);
        try testing.expectEqual(@as(usize, 4), opened.wal.live_count());
    }

    // Reopen: the epoch selection must name the compacted pair.
    var reopened = try test_open(allocator, path, .{ .capacity = 4 }, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(Pair.b, reopened.wal.eph.active);
    try testing.expectEqual(@as(usize, 4), reopened.wal.live_count());
    try testing.expectEqual(@as(u64, 105), reopened.wal.live_get(1).?.lease_id);
    try testing.expect(reopened.wal.live_get(4) != null);
    // Compaction re-stamps: every copied record carries the compaction's
    // write clock (the epoch selector's freshness is exactly that).
    try testing.expectEqual(@as(u64, now + 1), reopened.wal.live_get(1).?.stamp);
    try testing.expectEqual(@as(u64, now + 1), reopened.wal.live_get(2).?.stamp);
    try testing.expectEqual(@as(u64, now + 1), reopened.wal.live_get(3).?.stamp);
}

test "wal: an epoch stamp tie selects pair A, deterministically" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        // One live record in pair A; pair B's header slot 0 gets the
        // byte-identical record (the same stamp, valid checksums) —
        // an exact tie, the unorderable wall clock the epoch rule
        // resolves to pair A.
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try copy_bytes(
            path,
            header_base(.ephemeral, .a),
            header_base(.ephemeral, .b),
            header_record_size,
        );
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(Pair.a, reopened.wal.eph.active);
    try testing.expectEqual(@as(u32, 1), reopened.wal.eph.position);
    try testing.expectEqual(@as(usize, 1), reopened.wal.live_count());
    try testing.expectEqual(@as(u64, 101), reopened.wal.live_get(1).?.lease_id);
}

test "wal: compaction zeroes the target pair's header tail — a stale live record cannot resurrect" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{ .capacity = 4 }, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        // Pair A's first generation: live1, live9, its tombstone, live2 —
        // slot 3 (the pair's last slot) holds a live record for lock 2.
        // The live set is {1, 2} at position 4.
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 9, 109, Holder, Window), now);
        try opened.wal.submit(
            WalRecord{ .stamp = now, .expiry = 0, .lock_id = 9, .lease_id = 0, .tag = tag_encode(.tombstone) },
            now,
        );
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 2, 102, Holder, Window), now);
        try testing.expectEqual(@as(u32, 4), opened.wal.eph.position);
        try testing.expectEqual(@as(usize, 2), opened.wal.live_count());

        // The next submit compacts A→B: {1, 2} copied, live3 lands at
        // B slot 2. Then lock 2's tombstone fills B. The live set is
        // {1, 3} at position 4.
        try opened.wal.submit(WalRecord.live(now + 1, now + 10_000_000_000, 3, 103, Holder, Window), now + 1);
        try opened.wal.submit(
            WalRecord{ .stamp = now + 1, .expiry = 0, .lock_id = 2, .lease_id = 0, .tag = tag_encode(.tombstone) },
            now + 1,
        );
        try testing.expectEqual(@as(usize, 2), opened.wal.live_count());

        // The next submit compacts B→A: {1, 3} copies into A slots 0-1
        // and A's header tail (slots 2-3 — the stale tombstone and, the
        // dangerous one, the stale live record for lock 2) is zeroed;
        // live4 lands at A slot 2.
        try opened.wal.submit(WalRecord.live(now + 2, now + 10_000_000_000, 4, 104, Holder, Window), now + 2);
        try testing.expectEqual(Pair.a, opened.wal.eph.active);
        try testing.expectEqual(@as(u32, 3), opened.wal.eph.position);
        try testing.expectEqual(@as(usize, 3), opened.wal.live_count());
    }

    // Reopen: the scan terminates exactly at the copied content — the
    // stale live record for lock 2 at the zeroed tail slot is not read,
    // lock 2 stays dead.
    var reopened = try test_open(allocator, path, .{ .capacity = 4 }, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(Pair.a, reopened.wal.eph.active);
    try testing.expectEqual(@as(u32, 3), reopened.wal.eph.position);
    try testing.expectEqual(@as(usize, 3), reopened.wal.live_count());
    try testing.expect(reopened.wal.live_get(2) == null);
    try testing.expect(reopened.wal.live_get(4) != null);
}

test "wal: capacity overrun is a counted refusal, serving state unaffected" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{ .capacity = 2 }, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 2, 102, Holder, Window), now);

        // The live set fills the ring: the third lock cannot fit.
        try testing.expectError(
            error.WalCapacity,
            opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 3, 103, Holder, Window), now),
        );
        try testing.expectEqual(@as(u64, 1), opened.wal.status().refusals);
        try testing.expectEqual(@as(usize, 2), opened.wal.live_count());
        try testing.expect(opened.wal.live_get(3) == null);
    }

    // The refused record is nowhere on disk: a reopen reads exactly the
    // served set.
    var reopened = try test_open(allocator, path, .{ .capacity = 2 }, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();
    try testing.expectEqual(@as(usize, 2), reopened.wal.live_count());
    try testing.expect(reopened.wal.live_get(3) == null);
}

test "wal: header/data disagreement refused" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
    }

    // Corrupt the data ring twin's payload: the hydration refuses.
    try poke(path, data_base(.ephemeral, .a) + holder_offset, 0xFF);
    {
        const opened = test_open(allocator, path, .{}, now);
        try testing.expectError(error.CorruptRecord, opened);
        if (opened) |bad| {
            var b = bad;
            b.io.close();
            b.wal.deinit();
        } else |_| {}
    }

    // Corrupt the header ring record: the scan refuses.
    try poke(path, header_base(.ephemeral, .a) + 5, 0xFF);
    {
        const opened = test_open(allocator, path, .{}, now);
        try testing.expectError(error.CorruptRecord, opened);
        if (opened) |bad| {
            var b = bad;
            b.io.close();
            b.wal.deinit();
        } else |_| {}
    }
}

test "wal: twin disagreement with both checksums valid refused, both streams" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        // Two live records per stream: slots 0 and 1.
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 2, 102, Holder, Window), now);
        try opened.wal.submit_durable(durable_change(.live, now, 5, "/five"), now);
        try opened.wal.submit_durable(durable_change(.live, now, 6, "/six"), now);
    }

    // Swap the ephemeral header ring's slots 0 and 1: both headers are
    // individually checksum-valid, but each slot's header twin (the
    // other lock) disagrees with the data record under it — the identity
    // prefix mismatch is the refusal.
    try copy_bytes(
        path,
        header_base(.ephemeral, .a),
        header_base(.ephemeral, .a) + 2 * header_record_size,
        header_record_size,
    );
    try copy_bytes(
        path,
        header_base(.ephemeral, .a) + 1 * header_record_size,
        header_base(.ephemeral, .a),
        header_record_size,
    );
    try copy_bytes(
        path,
        header_base(.ephemeral, .a) + 2 * header_record_size,
        header_base(.ephemeral, .a) + 1 * header_record_size,
        header_record_size,
    );
    {
        const opened = test_open(allocator, path, .{}, now);
        try testing.expectError(error.CorruptRecord, opened);
        if (opened) |bad| {
            var b = bad;
            b.io.close();
            b.wal.deinit();
        } else |_| {}
    }

    // The durable stream's same shape: valid frames under mismatched
    // header-ring records. Both copies intact, the hydration's twin
    // agreement refuses.
    try copy_bytes(
        path,
        header_base(.durable, .a),
        header_base(.durable, .a) + 2 * header_record_size,
        header_record_size,
    );
    try copy_bytes(
        path,
        header_base(.durable, .a) + 1 * header_record_size,
        header_base(.durable, .a),
        header_record_size,
    );
    try copy_bytes(
        path,
        header_base(.durable, .a) + 2 * header_record_size,
        header_base(.durable, .a) + 1 * header_record_size,
        header_record_size,
    );
    {
        const opened = test_open(allocator, path, .{}, now);
        try testing.expectError(error.CorruptRecord, opened);
        if (opened) |bad| {
            var b = bad;
            b.io.close();
            b.wal.deinit();
        } else |_| {}
    }
}

test "wal: torn tail refused" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
    }

    // A truncated file is not the fixed layout: refused at open.
    {
        const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
        defer file.close();
        try file.setEndPos(header_base(.ephemeral, .a) + 20);
    }
    const opened = test_open(allocator, path, .{}, now);
    try testing.expectError(error.WalFileFormat, opened);
    if (opened) |bad| {
        var b = bad;
        b.io.close();
        b.wal.deinit();
    } else |_| {}
}

test "wal: zeroed data record under a live header refused" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
    }

    // Zero the data twin: the header checksum is valid but the data
    // checksum is not — the hydration refuses.
    try poke_zeros(path, data_base(.ephemeral, .a), record_size);
    const opened = test_open(allocator, path, .{}, now);
    try testing.expectError(error.CorruptRecord, opened);
    if (opened) |bad| {
        var b = bad;
        b.io.close();
        b.wal.deinit();
    } else |_| {}
}

test "wal: the ephemeral data ring holds the record's bitwise NOT" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
    }

    // The raw data slot is the NOT of the encoded record: flipping the
    // file's bytes back reproduces the record byte-exact, and the flip is
    // its own inverse (a second pass restores the raw slot).
    const file = try std.fs.cwd().openFile(path, .{ .mode = .read_write });
    defer file.close();
    var raw: [record_size]u8 = undefined;
    _ = try file.preadAll(&raw, data_base(.ephemeral, .a));
    var unflipped = raw;
    not_flip(&unflipped);
    const record = try record_decode(&unflipped);
    try testing.expectEqual(@as(u64, 1), record.lock_id);
    try testing.expectEqual(Kind.live, record.kind());
    var reference: [record_size]u8 = undefined;
    record_encode(&reference, record);
    try testing.expectEqualSlices(u8, &reference, &unflipped);

    // A torn flip (one raw byte rotted in place) un-flips to a rotted
    // record: the hydration refuses at open.
    try poke(path, data_base(.ephemeral, .a) + 20, raw[20] ^ 0x01);
    const torn = test_open(allocator, path, .{}, now);
    try testing.expectError(error.CorruptRecord, torn);
    if (torn) |bad| {
        var b = bad;
        b.io.close();
        b.wal.deinit();
    } else |_| {}

    // The all-zero data slot under a live header un-flips to all-0xFF:
    // refused too (the misdirected-write shape).
    try poke_zeros(path, data_base(.ephemeral, .a), record_size);
    const zeroed = test_open(allocator, path, .{}, now);
    try testing.expectError(error.CorruptRecord, zeroed);
    if (zeroed) |bad| {
        var b = bad;
        b.io.close();
        b.wal.deinit();
    } else |_| {}
}

test "wal: shutdown flush lands the full set and fsyncs exactly once" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    const flushed_at: u64 = now + 1_000_000_000;
    {
        var opened = try test_open(allocator, path, .{ .capacity = 12 }, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 2, 102, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 3, 103, Holder, Window), now);
        opened.wal.complete_generation();
        try testing.expectEqual(@as(usize, 0), opened.wal.io.fsync_count);

        try opened.wal.flush(flushed_at);
        try testing.expectEqual(@as(usize, 1), opened.wal.io.fsync_count);
        // The steady tick's generation, then the shutdown generation.
        try testing.expectEqual(@as(u64, 2), opened.wal.status().completed_generations);
        try testing.expectEqual(flushed_at, opened.wal.status().last_completed_unix_ns);
        try testing.expectEqual(@as(u32, 0), opened.wal.status().in_flight);
        try testing.expectEqual(@as(u32, 6), opened.wal.eph.position);
    }

    var reopened = try test_open(allocator, path, .{ .capacity = 12 }, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(@as(usize, 3), reopened.wal.live_count());
    for ([_]u64{ 1, 2, 3 }) |lock_id| {
        const record = reopened.wal.live_get(lock_id).?;
        try testing.expectEqual(Kind.live, record.kind());
        try testing.expectEqual(flushed_at, record.stamp);
        try testing.expectEqualSlices(u8, &Holder, &record.holder);
    }

    // A second shutdown on the reloaded engine flushes the same way.
    try reopened.wal.flush(flushed_at + 1);
    try testing.expectEqual(@as(usize, 1), reopened.wal.io.fsync_count);
    try testing.expectEqual(@as(u64, 1), reopened.wal.status().completed_generations);
}

test "wal: shutdown flush overrun is a failed stop" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    var opened = try test_open(allocator, path, .{ .capacity = 2 }, now);
    defer opened.io.close();
    defer opened.wal.deinit();

    try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
    try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 2, 102, Holder, Window), now);

    // The full live set does not fit the pair's remaining capacity: the
    // flush is refused, no fsync, nothing landed.
    try testing.expectError(error.WalCapacity, opened.wal.flush(now));
    try testing.expectEqual(@as(u64, 1), opened.wal.status().refusals);
    try testing.expectEqual(@as(usize, 0), opened.wal.io.fsync_count);
    try testing.expectEqual(@as(u64, 0), opened.wal.status().completed_generations);
}

test "wal: tombstone written and released lock absent after flush and reopen" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 2, 102, Holder, Window), now);
        try opened.wal.submit(WalRecord.tombstone(now + 1, 1, 101), now + 1);
        try opened.wal.flush(now + 2);
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();
    try testing.expect(reopened.wal.live_get(1) == null);
    try testing.expect(reopened.wal.live_get(2) != null);
}

test "wal: config outside the ring geometry refused" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    var io = try SyncIO.open(path);
    defer io.close();
    try testing.expectError(
        error.WalInvalidConfig,
        Wal.open(allocator, io, .{ .capacity = 0 }, 0),
    );
    try testing.expectError(
        error.WalInvalidConfig,
        Wal.open(allocator, io, .{ .capacity = ring_capacity_max + 1 }, 0),
    );
}

test "wal: live_encode exports the set as submit-path records" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    var opened = try test_open(allocator, path, .{}, now);
    defer opened.io.close();
    defer opened.wal.deinit();

    // Empty set: zero bytes, no error.
    try testing.expectEqual(@as(usize, 0), try opened.wal.live_encode(&.{}));

    try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
    try opened.wal.submit(WalRecord.live(now, now + 20_000_000_000, 2, 102, Holder, Window), now);

    // Too small: refused whole, never a partial copy.
    var small: [record_size - 1]u8 = undefined;
    try testing.expectError(error.WalBufferTooSmall, opened.wal.live_encode(&small));

    // Exactly sized: two 72-byte records, each decodes back to its lock.
    var out: [2 * record_size]u8 = undefined;
    const written = try opened.wal.live_encode(&out);
    try testing.expectEqual(@as(usize, 2 * record_size), written);

    var seen: usize = 0;
    for (0..2) |i| {
        const decoded = try record_decode(out[i * record_size ..][0..record_size]);
        try testing.expect(decoded.lock_id == 1 or decoded.lock_id == 2);
        seen += 1;
        if (decoded.lock_id == 1) {
            try testing.expectEqual(@as(u64, 101), decoded.lease_id);
        } else {
            try testing.expectEqual(@as(u64, 102), decoded.lease_id);
        }
    }
    try testing.expectEqual(@as(usize, 2), seen);
}

test "wal: flush_records writes a caller-supplied set and re-stamps it" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    const flushed_at: u64 = now + 500_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        const records = [_]WalRecord{
            WalRecord.live(42, now + 10_000_000_000, 1, 101, Holder, Window),
            WalRecord.live(42, now + 10_000_000_000, 2, 102, Holder, Window),
        };
        try opened.wal.flush_records(&records, &.{}, flushed_at);
        try testing.expectEqual(@as(usize, 1), opened.wal.io.fsync_count);
        try testing.expectEqual(@as(u64, 1), opened.wal.status().completed_generations);
        try testing.expectEqual(@as(u32, 2), opened.wal.eph.position);
        // The engine's in-memory live set is untouched by a caller-set flush.
        try testing.expectEqual(@as(usize, 0), opened.wal.live_count());
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(@as(usize, 2), reopened.wal.live_count());
    for ([_]u64{ 1, 2 }, [_]u64{ 101, 102 }) |lock_id, lease_id| {
        const record = reopened.wal.live_get(lock_id).?;
        try testing.expectEqual(Kind.live, record.kind());
        try testing.expectEqual(flushed_at, record.stamp);
        try testing.expectEqual(lease_id, record.lease_id);
        try testing.expectEqualSlices(u8, &Holder, &record.holder);
    }
}

test "wal: flush_records overrun is a failed stop" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    var opened = try test_open(allocator, path, .{ .capacity = 2 }, now);
    defer opened.io.close();
    defer opened.wal.deinit();

    const records = [_]WalRecord{
        WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window),
        WalRecord.live(now, now + 10_000_000_000, 2, 102, Holder, Window),
        WalRecord.live(now, now + 10_000_000_000, 3, 103, Holder, Window),
    };
    try testing.expectError(error.WalCapacity, opened.wal.flush_records(&records, &.{}, now));
    try testing.expectEqual(@as(u64, 1), opened.wal.status().refusals);
    try testing.expectEqual(@as(usize, 0), opened.wal.io.fsync_count);
}

// ---------------------------------------------------------------------------
// The durable stream: fat frames, kept records, per-stream machinery.
// ---------------------------------------------------------------------------

/// One durable change for the tests: the identity fields plus a name and
/// a tag byte set, taken-at and renew counters.
fn durable_change(
    kind: DurableKind,
    stamp: u64,
    lock_id: u64,
    name: []const u8,
) DurableChange {
    return .{
        .record = durable_record(kind, stamp, 0, lock_id, lock_id * 10, Holder, 0),
        .name = name,
        .taken_at_ms = 1_700_000_000_000 + lock_id,
        .renew_count = 2,
        .tag_bytes = "lane-a",
    };
}

test "wal: durable submit then reopen — the live set hydrates from the fat frames" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit_durable(durable_change(.live, now, 9, "/locks/turbine-9"), now);
        try opened.wal.submit_durable(durable_change(.live, now + 1, 11, "/locks/turbine-11"), now + 1);
        try testing.expectEqual(@as(usize, 2), opened.wal.dur_live_count());
        try testing.expectEqual(@as(u32, 2), opened.wal.dur_position());
        // The cold durable stream's epoch: pair A.
        try testing.expectEqual(Pair.a, opened.wal.dur.active);
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(@as(usize, 2), reopened.wal.dur_live_count());
    const frame = reopened.wal.dur_live_get(9).?;
    try testing.expectEqual(DurableKind.live, frame.kind());
    try testing.expectEqual(@as(u64, now), frame.header.stamp);
    try testing.expectEqualSlices(u8, "/locks/turbine-9", frame.name());
    try testing.expectEqual(@as(u64, 1_700_000_000_009), frame.taken_at_ms());
    try testing.expectEqual(@as(u32, 2), frame.renew_count());
    try testing.expectEqualSlices(u8, "lane-a", frame.tag_bytes());
    try testing.expectEqualSlices(u8, &Holder, &frame.header.holder);
    const other = reopened.wal.dur_live_get(11).?;
    try testing.expectEqualSlices(u8, "/locks/turbine-11", other.name());
}

test "wal: durable kept survives, delete drops, last record wins" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        // Lock 1: live then deleted. Lock 2: live then kept (released but
        // not destroyed). Lock 3: live.
        try opened.wal.submit_durable(durable_change(.live, now, 1, "/one"), now);
        try opened.wal.submit_durable(durable_change(.live, now, 2, "/two"), now);
        try opened.wal.submit_durable(durable_change(.live, now, 3, "/three"), now);
        try opened.wal.submit_durable(durable_change(.delete, now + 1, 1, ""), now + 1);
        try opened.wal.submit_durable(durable_change(.kept, now + 2, 2, "/two"), now + 2);
        try testing.expectEqual(@as(usize, 2), opened.wal.dur_live_count());
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    // The delete dropped lock 1; the kept record stands for lock 2 — and
    // an expiry-less kept record is never dropped by the expiry skip.
    try testing.expect(reopened.wal.dur_live_get(1) == null);
    const kept = reopened.wal.dur_live_get(2).?;
    try testing.expectEqual(DurableKind.kept, kept.kind());
    try testing.expectEqual(@as(u64, now + 2), kept.header.stamp);
    try testing.expect(reopened.wal.dur_live_get(3) != null);
}

test "wal: durable compaction includes kept records and flips the pair" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{ .capacity = 4 }, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit_durable(durable_change(.live, now, 1, "/one"), now);
        try opened.wal.submit_durable(durable_change(.live, now, 2, "/two"), now);
        try opened.wal.submit_durable(durable_change(.kept, now, 2, "/two"), now);
        try opened.wal.submit_durable(durable_change(.live, now, 3, "/three"), now);
        try testing.expectEqual(@as(u32, 4), opened.wal.dur_position());

        // This submit fills pair A: the compaction copies the live set —
        // including the kept record — into pair B, the pairs flip, then
        // the record lands on the flipped pair.
        try opened.wal.submit_durable(durable_change(.live, now + 1, 4, "/four"), now + 1);
        try testing.expectEqual(Pair.b, opened.wal.dur.active);
        try testing.expectEqual(@as(u32, 4), opened.wal.dur_position());
    }

    // Reopen: the epoch selection must name the compacted durable pair,
    // and the kept record survives the copy.
    var reopened = try test_open(allocator, path, .{ .capacity = 4 }, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(Pair.b, reopened.wal.dur.active);
    try testing.expectEqual(@as(usize, 4), reopened.wal.dur_live_count());
    try testing.expectEqual(DurableKind.kept, reopened.wal.dur_live_get(2).?.kind());
    try testing.expectEqualSlices(u8, "/four", reopened.wal.dur_live_get(4).?.name());
}

test "wal: durable capacity overrun is a counted refusal" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    var opened = try test_open(allocator, path, .{ .capacity = 2 }, now);
    defer opened.io.close();
    defer opened.wal.deinit();

    try opened.wal.submit_durable(durable_change(.live, now, 1, "/one"), now);
    try opened.wal.submit_durable(durable_change(.live, now, 2, "/two"), now);

    try testing.expectError(
        error.WalCapacity,
        opened.wal.submit_durable(durable_change(.live, now, 3, "/three"), now),
    );
    try testing.expectEqual(@as(u64, 1), opened.wal.status().refusals);
    try testing.expectEqual(@as(usize, 2), opened.wal.dur_live_count());
    try testing.expect(opened.wal.dur_live_get(3) == null);
}

test "wal: durable frame corruption refuses at open" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();
        try opened.wal.submit_durable(durable_change(.live, now, 7, "/seven"), now);
    }

    // A rotted byte deep in the frame's consistency area: the frame
    // checksum spans the whole 768 bytes — the hydration refuses.
    try poke(path, frame_offset(.durable, .a, 0) + fat_frame_size - 1, 0xFF);
    const rotted = test_open(allocator, path, .{}, now);
    try testing.expectError(error.CorruptRecord, rotted);
    if (rotted) |bad| {
        var b = bad;
        b.io.close();
        b.wal.deinit();
    } else |_| {}

    // A rotted durable header-ring record: the scan refuses.
    try poke(path, header_base(.durable, .a) + 5, 0xFF);
    const headered = test_open(allocator, path, .{}, now);
    try testing.expectError(error.CorruptRecord, headered);
    if (headered) |bad| {
        var b = bad;
        b.io.close();
        b.wal.deinit();
    } else |_| {}
}

test "wal: durable expiry skip — an expiring live record drops, an expiry-less one stands" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        // An expiring durable live record, expired far past the threshold.
        var expiring = durable_change(.live, now, 1, "/one");
        expiring.record.expiry = now - 10 * std.time.ns_per_s;
        try opened.wal.submit_durable(expiring, now);
        // An expiry-less live record: never dropped by the skip.
        try opened.wal.submit_durable(durable_change(.live, now, 2, "/two"), now);
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expect(reopened.wal.dur_live_get(1) == null);
    try testing.expect(reopened.wal.dur_live_get(2) != null);
}

test "wal: the shutdown flush covers both streams with exactly one fsync" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    const flushed_at: u64 = now + 1_000_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit(WalRecord.live(now, now + 10_000_000_000, 1, 101, Holder, Window), now);
        try opened.wal.submit_durable(durable_change(.live, now, 9, "/nine"), now);
        opened.wal.complete_generation();

        try opened.wal.flush(flushed_at);
        // One fsync total: the two streams share the one file descriptor.
        try testing.expectEqual(@as(usize, 1), opened.wal.io.fsync_count);
        try testing.expectEqual(@as(u64, 4), opened.wal.status().completed_records);
        try testing.expectEqual(@as(u64, 2), opened.wal.status().completed_generations);
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(@as(usize, 1), reopened.wal.live_count());
    try testing.expectEqual(@as(usize, 1), reopened.wal.dur_live_count());
    try testing.expectEqual(flushed_at, reopened.wal.live_get(1).?.stamp);
    try testing.expectEqual(flushed_at, reopened.wal.dur_live_get(9).?.header.stamp);
    try testing.expectEqualSlices(u8, "/nine", reopened.wal.dur_live_get(9).?.name());
}

test "wal: flush_records lands the caller's sets, both streams" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    const flushed_at: u64 = now + 500_000_000;
    {
        var opened = try test_open(allocator, path, .{}, now);
        defer opened.io.close();
        defer opened.wal.deinit();

        try opened.wal.submit_durable(durable_change(.live, now, 5, "/five"), now);
        try opened.wal.submit_durable(durable_change(.kept, now, 6, "/six"), now);

        const records = [_]WalRecord{
            WalRecord.live(42, now + 10_000_000_000, 1, 101, Holder, Window),
        };
        // The caller's durable set: the mirror's own frames, as the C ABI
        // passes them (the host table's view of the durable locks).
        const frames = [_]FatFrame{
            opened.wal.dur_live_get(5).?,
            opened.wal.dur_live_get(6).?,
        };
        try opened.wal.flush_records(&records, &frames, flushed_at);
        try testing.expectEqual(@as(usize, 1), opened.wal.io.fsync_count);
    }

    var reopened = try test_open(allocator, path, .{}, now);
    defer reopened.io.close();
    defer reopened.wal.deinit();

    try testing.expectEqual(@as(usize, 1), reopened.wal.live_count());
    try testing.expectEqual(@as(usize, 2), reopened.wal.dur_live_count());
    try testing.expectEqual(flushed_at, reopened.wal.dur_live_get(5).?.header.stamp);
    try testing.expectEqual(DurableKind.kept, reopened.wal.dur_live_get(6).?.kind());
}

test "wal: submit_durable refusals — zero lock id, oversize name and tags" {
    const allocator = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp_wal_path(allocator, &tmp);
    defer allocator.free(path);

    const now: u64 = 1_000_000_000_000;
    var opened = try test_open(allocator, path, .{}, now);
    defer opened.io.close();
    defer opened.wal.deinit();

    var zero_lock = durable_change(.live, now, 1, "/one");
    zero_lock.record.lock_id = 0;
    try testing.expectError(error.InvalidRecord, opened.wal.submit_durable(zero_lock, now));

    const full_name = [_]u8{'n'} ** fat_name_capacity;
    var long_name = durable_change(.live, now, 1, &full_name);
    long_name.name = full_name ++ "x";
    try testing.expectError(error.RecordTooLarge, opened.wal.submit_durable(long_name, now));

    const full_tags = [_]u8{'t'} ** fat_tag_bytes_capacity;
    var long_tags = durable_change(.live, now, 1, "/one");
    long_tags.tag_bytes = full_tags ++ "x";
    try testing.expectError(error.RecordTooLarge, opened.wal.submit_durable(long_tags, now));

    // Nothing landed on any refusal.
    try testing.expectEqual(@as(usize, 0), opened.wal.dur_live_count());
    try testing.expectEqual(@as(u32, 0), opened.wal.dur_position());
}

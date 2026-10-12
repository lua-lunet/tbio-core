//! The copy canary: the cross-ABI interop proof for the WAL record's
//! C layout (docs/src/wal-snapshot.md, "The seams"). A Rust driver fills
//! one caller-owned slot with the real `WalRecord` struct carrying
//! wide-bit unique sentinels, calls `wal_canary_bump_copy` twice across
//! three caller-owned slots, and verifies the last slot byte-exact and
//! field-true. What it kills: a future debugger logging the struct inside
//! Zig and seeing junk, or a value crossing the boundary and silently
//! losing bits — in prod. It proves the actual size, shape, C field math
//! and endianness, on the build, on every architecture the cdylib is
//! built for (the Rust driver test runs wherever cargo runs; a
//! big-endian host would fail loudly — a feature).
//!
//! **The ownership contract:** caller-owned, always. All three slots are
//! one caller-owned array; this module allocates nothing, frees nothing,
//! and may touch only the slots handed to it, only for the duration of
//! the call. The same contract the WAL ABI already follows (`buf` /
//! `out_len` in both directions; the engine owns no memory across a
//! call). The canary is deliberately **memory-only** — no disk, no
//! flush; the disk round trip is a later integration concern. What it
//! proves is that the bytes that cross the boundary are the bytes a
//! memcpy would carry, and the fields the engine reads are the fields
//! the host wrote.
//!
//! The scenario: slot 0 (sentinels) → `wal_canary_bump_copy` → slot 1
//! (bump fields +1) → again → slot 2 (bump fields +2). The bump is the
//! proof that a plain copy cannot fake: the Zig side must interpret the
//! fields — as the struct, never as offset math on raw bytes — to bump
//! exactly the right two of them by exactly 1 per copy.
//!
//! Sentinels are **unsigned-only** (`u64` / `u32` / `[u8;16]` — never
//! `i32`/`i64` anywhere in the record) with comptime headroom asserts:
//! `sentinel + bump_count < maxInt(T)`, so neither increment can wrap
//! even in a release build (where a plain `+` on unsigned overflow wraps
//! silently — the footgun this design kills; the export itself uses
//! `std.math.add` checked increments and returns an error code, never a
//! wrap). The sentinel constants here are mirrored by the Rust driver
//! test (`tests/wal_snapshot_test.rs` in the advisory-lock crate); the
//! two sides asserting the same wide values is the proof.

const std = @import("std");
const mem = std.mem;
const assert = std.debug.assert;

const wal_snapshot = @import("wal_snapshot.zig");

const record_size = wal_snapshot.record_size;

// ---------------------------------------------------------------------------
// The sentinels (mirrored by the Rust driver test; keep both sides equal).
// ---------------------------------------------------------------------------

/// The bump count the full scenario applies: two copies, +1 each.
pub const bump_count: u64 = 2;

/// The shared wide prefix every u64 sentinel carries: high bits set wide,
/// low byte distinguishes the field. The low values are spaced apart so
/// the +2 the two bumps apply cannot make any two fields collide (the
/// distinctness the test asserts).
pub const sentinel_head: u64 = 0x7B1D_5EED_0000_0000;

pub const stamp_sentinel: u64 = sentinel_head | 1;
pub const expiry_sentinel: u64 = sentinel_head | 10;
pub const lock_id_sentinel: u64 = sentinel_head | 20;
pub const lease_id_sentinel: u64 = sentinel_head | 30;
pub const lease_ms_sentinel: u64 = sentinel_head | 40;
pub const tag_sentinel: u32 = 0x7FFF_FFF1;
pub const checksum_sentinel: u32 = 0x7FFF_FFF2;
pub const holder_sentinel: [16]u8 = .{
    0x01, 0x02, 0x03, 0x04,
    0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c,
    0x0d, 0x0e, 0x0f, 0x10,
};

comptime {
    // Headroom: neither of the two bumps can wrap any bumped sentinel,
    // even in a release build (where unsigned overflow wraps silently).
    // The u32 sentinels never bump, but the same property is asserted —
    // the design carries no value anywhere near a wrap.
    assert(stamp_sentinel + bump_count < std.math.maxInt(u64));
    assert(lease_id_sentinel + bump_count < std.math.maxInt(u64));
    assert(expiry_sentinel + bump_count < std.math.maxInt(u64));
    assert(lock_id_sentinel + bump_count < std.math.maxInt(u64));
    assert(lease_ms_sentinel + bump_count < std.math.maxInt(u64));
    assert(tag_sentinel + bump_count < std.math.maxInt(u32));
    assert(checksum_sentinel + bump_count < std.math.maxInt(u32));

    // The alignment the export's buffer checks assume: the record struct
    // is 8-aligned and a whole number of 8-byte words (the shared
    // module's own comptime asserts pin the rest — size 64, every offset,
    // no padding — and run on every build).
    assert(@alignOf(wal_snapshot.WalRecord) == 8);
    assert(record_size % 8 == 0);
    assert(record_size == 64);
}

// ---------------------------------------------------------------------------
// The export.
// ---------------------------------------------------------------------------

// The errno-style result codes (the errno values; the call sites return
// them negated, so a refusal is the documented negative: -EINVAL etc).
const EINVAL: c_int = 22;
const EOVERFLOW: c_int = 75;

/// Copy one 64-byte record from `src` to `dst` and bump the bump fields
/// (`stamp` and `lease_id`) by exactly 1: the fields are read as the
/// struct (`mem.bytesToValue`), incremented with `std.math.add` (a wrap
/// is an error code, never a silent wrap), and written back as the
/// struct's bytes. The caller owns both buffers end to end — this module
/// allocates nothing and touches nothing beyond the 64 bytes handed to
/// it, only for the duration of the call.
///
/// Buffers must be 8-byte aligned and disjoint (the copy is `@memcpy`,
/// which requires no overlap — checked, not assumed). Returns 0 on
/// success, `-EINVAL` on a null pointer, a misaligned buffer, or
/// overlapping slots, `-EOVERFLOW` if an increment would wrap
/// (unreachable through the sentinels' comptime headroom — the checked
/// increment is the defensive backstop, never a silent wrap).
export fn wal_canary_bump_copy(src: ?[*]const u8, dst: ?[*]u8) c_int {
    const from = src orelse return -EINVAL;
    const to = dst orelse return -EINVAL;

    const from_addr = @intFromPtr(from);
    const to_addr = @intFromPtr(to);
    if (from_addr % 8 != 0 or to_addr % 8 != 0) return -EINVAL;

    // Disjoint slots only: `@memcpy` is the primitive here (a plain,
    // shape-exact copy — `copyForwards` is for overlapping ranges, which
    // are refused, never tolerated).
    const disjoint = from_addr + record_size <= to_addr or
        to_addr + record_size <= from_addr;
    if (!disjoint) return -EINVAL;

    @memcpy(to[0..record_size], from[0..record_size]);

    // The bump: interpret as the struct, never as offset math on raw
    // bytes — this is the field-true reading the canary exists to prove.
    var record = mem.bytesToValue(wal_snapshot.WalRecord, to[0..record_size]);
    record.stamp = std.math.add(u64, record.stamp, 1) catch return -EOVERFLOW;
    record.lease_id = std.math.add(u64, record.lease_id, 1) catch return -EOVERFLOW;
    @memcpy(to[0..record_size], mem.asBytes(&record));

    return 0;
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sentinel_record() wal_snapshot.WalRecord {
    return .{
        .stamp = stamp_sentinel,
        .expiry = expiry_sentinel,
        .lock_id = lock_id_sentinel,
        .lease_id = lease_id_sentinel,
        .holder = holder_sentinel,
        .lease_ms = lease_ms_sentinel,
        .tag = tag_sentinel,
        .checksum = checksum_sentinel,
    };
}

test "wal canary: the comptime sentinel headroom holds at runtime values too" {
    // The comptime block above pins the headroom; this restates the
    // runtime fact the design relies on: wide, positive, far from any
    // wrap, and distinct.
    const sentinels = [_]u64{
        stamp_sentinel,    expiry_sentinel,   lock_id_sentinel,
        lease_id_sentinel, lease_ms_sentinel,
    };
    for (sentinels) |value| {
        try testing.expect(value + bump_count < std.math.maxInt(u64));
        try testing.expect(value > 0);
    }
    try testing.expect(tag_sentinel != checksum_sentinel);
}

test "wal canary: three caller-owned slots, bumped copies stay byte-exact and field-true" {
    var slots: [3][record_size]u8 align(8) = undefined;
    const sentinel = sentinel_record();
    @memcpy(slots[0][0..record_size], mem.asBytes(&sentinel));

    // Two copies, each bumping exactly the two bump fields by 1.
    try testing.expectEqual(@as(c_int, 0), wal_canary_bump_copy(&slots[0], &slots[1]));
    try testing.expectEqual(@as(c_int, 0), wal_canary_bump_copy(&slots[1], &slots[2]));

    // Slot 0 untouched: the caller's memory is never written behind its
    // back.
    try testing.expectEqualSlices(u8, mem.asBytes(&sentinel), &slots[0]);

    // Slot 1: the bumped fields are sentinel + 1 EXACTLY (a wrap or a
    // lost bit is a loud failure); everything else byte-equal.
    const one = mem.bytesToValue(wal_snapshot.WalRecord, &slots[1]);
    try testing.expectEqual(stamp_sentinel + 1, one.stamp);
    try testing.expectEqual(lease_id_sentinel + 1, one.lease_id);
    try testing.expectEqual(expiry_sentinel, one.expiry);
    try testing.expectEqual(lock_id_sentinel, one.lock_id);
    try testing.expectEqual(lease_ms_sentinel, one.lease_ms);
    try testing.expectEqual(tag_sentinel, one.tag);
    try testing.expectEqual(checksum_sentinel, one.checksum);
    try testing.expectEqualSlices(u8, &holder_sentinel, &one.holder);

    // Slot 2: byte-exact against the locally computed expectation — the
    // struct's bytes survived two copies through the ABI's shape.
    var expected = sentinel;
    expected.stamp = stamp_sentinel + bump_count;
    expected.lease_id = lease_id_sentinel + bump_count;
    try testing.expectEqualSlices(u8, mem.asBytes(&expected), &slots[2]);

    // Distinctness: no two fields collide after the bumps (the wide
    // prefix plus distinct low bits, +1/+2).
    const two = mem.bytesToValue(wal_snapshot.WalRecord, &slots[2]);
    const wide = [_]u64{ two.stamp, two.expiry, two.lock_id, two.lease_id, two.lease_ms };
    for (wide, 0..) |a, i| for (wide[i + 1 ..]) |b| {
        try testing.expect(a != b);
    };
    try testing.expect(two.tag != two.checksum);
}

test "wal canary: refusals — null, overlap, misalignment" {
    var slots: [3][record_size]u8 align(8) = undefined;
    const base: [*]const u8 = &slots[0];
    const mutable_base: [*]u8 = &slots[0];

    // Nulls are refused, never dereferenced.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_bump_copy(null, &slots[1]));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_bump_copy(&slots[0], null));

    // Overlapping slots are refused (dst inside src's span, and the
    // mirror direction), even though both pointers are aligned.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_bump_copy(&slots[0], mutable_base + 8));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_bump_copy(base + 8, &slots[0]));

    // Adjacent slots (64 bytes apart, the real scenario) are NOT
    // overlap: they copy fine.
    try testing.expectEqual(@as(c_int, 0), wal_canary_bump_copy(&slots[0], &slots[1]));

    // Misaligned buffers are refused: the struct's own alignment is 8.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_bump_copy(base + 1, &slots[1]));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_bump_copy(&slots[0], mutable_base + record_size + 4));
}

// ---------------------------------------------------------------------------
// The fat-frame canary: the same three-slot copy-and-bump over the
// durable stream's 768-byte fat frame. Sentinels ride the header fields
// AND the frame's payload areas — a wide-bit taken-at counter, a
// wide-bit renew counter, wide-bit u16 lengths in the name and
// tag-bytes areas, and the areas' byte content itself — and the bump
// moves the two counter fields (plus the header's stamp and lease id,
// the record canary's own bump pair) by exactly 1 per copy, read as the
// struct, never as offset math. The frame's size/alignment asserts pin
// the mirror exactly like the record's.
// ---------------------------------------------------------------------------

pub const fat_taken_at_sentinel: u64 = sentinel_head | 50;
pub const fat_renew_sentinel: u32 = 0x7FFF_FFF3;
pub const fat_name_len_sentinel: u16 = 0x7BEF;
pub const fat_tag_len_sentinel: u16 = 0x5EED;
/// The name area's byte pattern (the bytes are the sentinel; the bump
/// never touches them — the byte-exactness of an area is part of the
/// proof).
pub const fat_name_sentinel: [8]u8 = .{
    0xF0, 0xF1, 0xF2, 0xF3,
    0xF4, 0xF5, 0xF6, 0xF7,
};
pub const fat_tag_sentinel: [8]u8 = .{
    0xA0, 0xA1, 0xA2, 0xA3,
    0xA4, 0xA5, 0xA6, 0xA7,
};

comptime {
    assert(fat_taken_at_sentinel + bump_count < std.math.maxInt(u64));
    assert(fat_renew_sentinel + bump_count < std.math.maxInt(u32));
    // The u16 length sentinels never bump, but the same no-wrap property
    // is asserted — the design carries no value anywhere near a wrap.
    assert(fat_name_len_sentinel + @as(u16, @intCast(bump_count)) < std.math.maxInt(u16));
    assert(fat_tag_len_sentinel + @as(u16, @intCast(bump_count)) < std.math.maxInt(u16));

    // The fat frame's own layout pin: 768 bytes, 8-aligned, header at 0,
    // data at the record's size — the mirror's contract, restated here.
    assert(wal_snapshot.fat_frame_size == @sizeOf(wal_snapshot.FatFrame));
    assert(@alignOf(wal_snapshot.FatFrame) == 8);
}

/// Copy one 768-byte fat frame from `src` to `dst` and bump the four
/// bump fields — the header's `stamp` and `lease_id`, the counter area's
/// `taken_at_ms` and `renew_count` — by exactly 1, each read as the
/// struct's own field and incremented with `std.math.add` (a wrap is an
/// error code, never a silent wrap). Caller-owned memory end to end:
/// nothing is allocated, nothing is touched beyond the 768 bytes handed
/// to it, only for the duration of the call. 0 on success, `-EINVAL` on
/// a null pointer, a misaligned buffer, or overlapping slots,
/// `-EOVERFLOW` if an increment would wrap.
export fn wal_canary_fat_bump_copy(src: ?[*]const u8, dst: ?[*]u8) c_int {
    const from = src orelse return -EINVAL;
    const to = dst orelse return -EINVAL;

    const from_addr = @intFromPtr(from);
    const to_addr = @intFromPtr(to);
    if (from_addr % 8 != 0 or to_addr % 8 != 0) return -EINVAL;

    const disjoint = from_addr + wal_snapshot.fat_frame_size <= to_addr or
        to_addr + wal_snapshot.fat_frame_size <= from_addr;
    if (!disjoint) return -EINVAL;

    @memcpy(to[0..wal_snapshot.fat_frame_size], from[0..wal_snapshot.fat_frame_size]);

    var frame = mem.bytesToValue(wal_snapshot.FatFrame, to[0..wal_snapshot.fat_frame_size]);
    frame.header.stamp = std.math.add(u64, frame.header.stamp, 1) catch return -EOVERFLOW;
    frame.header.lease_id = std.math.add(u64, frame.header.lease_id, 1) catch return -EOVERFLOW;
    frame.data[wal_snapshot.fat_taken_at_offset - wal_snapshot.record_size ..][0..8].* =
        mem.toBytes(std.math.add(u64, frame.taken_at_ms(), 1) catch return -EOVERFLOW);
    frame.data[wal_snapshot.fat_renew_count_offset - wal_snapshot.record_size ..][0..4].* =
        mem.toBytes(std.math.add(u32, frame.renew_count(), 1) catch return -EOVERFLOW);
    @memcpy(to[0..wal_snapshot.fat_frame_size], mem.asBytes(&frame));

    return 0;
}

// ---------------------------------------------------------------------------
// The fat canary's tests.
// ---------------------------------------------------------------------------

/// One sentinel fat frame: the header's sentinels (the record canary's
/// own, unchanged) plus the areas' — wide-bit lengths, the counters'
/// wide-bit sentinels, the name/tag byte patterns, and a fixed byte
/// pattern in the consistency area's tail (nothing the bump touches).
fn sentinel_fat_frame() wal_snapshot.FatFrame {
    var frame = wal_snapshot.FatFrame{ .header = .{
        .stamp = stamp_sentinel,
        .expiry = expiry_sentinel,
        .lock_id = lock_id_sentinel,
        .lease_id = lease_id_sentinel,
        .holder = holder_sentinel,
        .lease_ms = lease_ms_sentinel,
        .tag = tag_sentinel,
        .checksum = checksum_sentinel,
    } };
    mem.writeInt(u16, frame.data[0..2], fat_name_len_sentinel, .little);
    @memcpy(frame.data[2..10], &fat_name_sentinel);
    frame.data[wal_snapshot.fat_taken_at_offset - record_size ..][0..8].* =
        mem.toBytes(fat_taken_at_sentinel);
    frame.data[wal_snapshot.fat_renew_count_offset - record_size ..][0..4].* =
        mem.toBytes(fat_renew_sentinel);
    mem.writeInt(
        u16,
        frame.data[wal_snapshot.fat_tag_len_offset - record_size ..][0..2],
        fat_tag_len_sentinel,
        .little,
    );
    @memcpy(
        frame.data[wal_snapshot.fat_tag_bytes_offset - record_size ..][0..fat_tag_sentinel.len],
        &fat_tag_sentinel,
    );
    @memset(
        frame.data[wal_snapshot.fat_sha_offset - record_size + 8 ..],
        0x5C,
    );
    return frame;
}

test "wal canary fat: the comptime sentinel headroom holds at runtime values too" {
    try testing.expect(fat_taken_at_sentinel + bump_count < std.math.maxInt(u64));
    try testing.expect(fat_taken_at_sentinel != stamp_sentinel);
    try testing.expect(fat_renew_sentinel != tag_sentinel);
    try testing.expect(fat_renew_sentinel != checksum_sentinel);
    try testing.expect(fat_name_len_sentinel != fat_tag_len_sentinel);
}

test "wal canary fat: three caller-owned slots, bumped copies stay byte-exact and field-true" {
    var slots: [3][wal_snapshot.fat_frame_size]u8 align(8) = undefined;
    const sentinel = sentinel_fat_frame();
    @memcpy(slots[0][0..wal_snapshot.fat_frame_size], mem.asBytes(&sentinel));

    // Two copies, each bumping exactly the four bump fields by 1.
    try testing.expectEqual(@as(c_int, 0), wal_canary_fat_bump_copy(&slots[0], &slots[1]));
    try testing.expectEqual(@as(c_int, 0), wal_canary_fat_bump_copy(&slots[1], &slots[2]));

    // Slot 0 untouched: the caller's memory is never written behind its
    // back.
    try testing.expectEqualSlices(u8, mem.asBytes(&sentinel), &slots[0]);

    // Slot 1: the bumped fields are sentinel + 1 EXACTLY; the header's
    // non-bump fields, both area lengths, both areas' bytes and the
    // consistency pattern are byte-equal.
    const one = mem.bytesToValue(wal_snapshot.FatFrame, &slots[1]);
    try testing.expectEqual(stamp_sentinel + 1, one.header.stamp);
    try testing.expectEqual(lease_id_sentinel + 1, one.header.lease_id);
    try testing.expectEqual(fat_taken_at_sentinel + 1, one.taken_at_ms());
    try testing.expectEqual(fat_renew_sentinel + 1, one.renew_count());
    try testing.expectEqual(expiry_sentinel, one.header.expiry);
    try testing.expectEqual(lock_id_sentinel, one.header.lock_id);
    try testing.expectEqual(lease_ms_sentinel, one.header.lease_ms);
    try testing.expectEqual(tag_sentinel, one.header.tag);
    try testing.expectEqual(checksum_sentinel, one.header.checksum);
    try testing.expectEqualSlices(u8, &holder_sentinel, &one.header.holder);
    try testing.expectEqual(
        fat_name_len_sentinel,
        mem.readInt(u16, slots[1][record_size..][0..2], .little),
    );
    try testing.expectEqualSlices(
        u8,
        &fat_name_sentinel,
        slots[1][record_size + 2 ..][0..fat_name_sentinel.len],
    );
    try testing.expectEqual(
        fat_tag_len_sentinel,
        mem.readInt(u16, slots[1][wal_snapshot.fat_tag_len_offset..][0..2], .little),
    );
    try testing.expectEqualSlices(
        u8,
        &fat_tag_sentinel,
        slots[1][wal_snapshot.fat_tag_bytes_offset..][0..fat_tag_sentinel.len],
    );
    for (slots[1][wal_snapshot.fat_sha_offset + 8 ..]) |byte| {
        try testing.expectEqual(@as(u8, 0x5C), byte);
    }

    // Slot 2: byte-exact against the locally computed expectation.
    var expected = sentinel;
    expected.header.stamp = stamp_sentinel + bump_count;
    expected.header.lease_id = lease_id_sentinel + bump_count;
    expected.data[wal_snapshot.fat_taken_at_offset - record_size ..][0..8].* =
        mem.toBytes(fat_taken_at_sentinel + bump_count);
    expected.data[wal_snapshot.fat_renew_count_offset - record_size ..][0..4].* =
        mem.toBytes(fat_renew_sentinel + @as(u32, @intCast(bump_count)));
    try testing.expectEqualSlices(u8, mem.asBytes(&expected), &slots[2]);
}

test "wal canary fat: refusals — null, overlap, misalignment" {
    var slots: [3][wal_snapshot.fat_frame_size]u8 align(8) = undefined;
    const base: [*]const u8 = &slots[0];
    const mutable_base: [*]u8 = &slots[0];
    const size = wal_snapshot.fat_frame_size;

    // Nulls are refused, never dereferenced.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_fat_bump_copy(null, &slots[1]));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_fat_bump_copy(&slots[0], null));

    // Overlapping slots are refused, both directions.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_fat_bump_copy(&slots[0], mutable_base + 8));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_fat_bump_copy(base + 8, &slots[0]));

    // Adjacent slots (768 bytes apart, the real scenario) are NOT
    // overlap: they copy fine.
    try testing.expectEqual(@as(c_int, 0), wal_canary_fat_bump_copy(&slots[0], &slots[1]));

    // Misaligned buffers are refused: the struct's own alignment is 8.
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_fat_bump_copy(base + 1, &slots[1]));
    try testing.expectEqual(@as(c_int, -EINVAL), wal_canary_fat_bump_copy(&slots[0], mutable_base + size + 4));
}

//! The Linux io_uring + eventfd backend for the WAL snapshot engine
//! (docs/src/wal-snapshot.md in the outer repo is the binding design).
//!
//! The host is a sans-IO single-threaded libuv loop. The steady tick
//! queues `pwrite` SQEs through io_uring and carries on: one
//! non-blocking `io_uring_enter` per batch (the ABI calls
//! `submit_batch` once per steady tick), and the ring's **eventfd** —
//! created here and registered with the ring via
//! `IORING_REGISTER_EVENTFD` — wakes the host's poll when completions
//! arrive. The ABI's `wal_pump` reaps CQEs non-blocking on the loop
//! thread; the shutdown generation's `fsync` is the one blocking call:
//! every SQE queued before it completes first (`IOSQE_IO_DRAIN`), the
//! fsync runs, and the call waits for the fsync's own completion.
//!
//! Buffered IO — no O_DIRECT, no alignment dance — per the zero-fsync
//! ruling: steady-state generations are page-cached and never synced.
//!
//! Single-thread contract: every call runs on the caller's loop thread.
//! No threads are spawned and no state is shared; the kernel does the
//! rest asynchronously, and completions are drained by the same thread
//! that submitted them. The counters (`submitted`,
//! `completed_contiguous`, `completion_errors`) are plain loop-owned
//! integers.
//!
//! Buffer ownership: an SQE holds its buffer pointer until its CQE, so
//! every write's bytes are copied into op-owned storage at queue time
//! and freed at reap. Operations are identified by a monotonically
//! increasing id (`user_data`); the op table and the done bitmap are
//! indexed `id % ops_len` — sound because the unreaped window (queued +
//! in-flight) is bounded below `ops_len` by the queue geometry below.
//! Completion order is not assumed: a contiguous watermark advances
//! only over reaped ids in order, so "everything up to id N is done"
//! is exact however the kernel interleaves completions.
//!
//! The SQ ring is entered eagerly at half full (`write_at` checks
//! before queueing), so a batch larger than the ring drains as it
//! fills; `submit_batch` retries the enter after reaping completions
//! when the kernel reports busy (EBUSY/EAGAIN).
const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const linux = std.os.linux;
const assert = std.debug.assert;
const mem = std.mem;

const common = @import("common.zig");
const wal_snapshot = @import("../wal_snapshot.zig");

const log = std.log.scoped(.wal_uring_linux);

comptime {
    // This backend is meaningful only where io_uring exists; everywhere
    // else the ABI uses the synchronous-completion backend.
    if (builtin.os.tag != .linux) {
        @compileError("wal_uring_linux: the io_uring backend is Linux-only");
    }
}

/// One queued/in-flight write's owned buffer. The ephemeral data-ring and
/// header-ring records are 64/40 bytes, the durable frame write is 768
/// bytes (the frame is the unit), the compaction runs are one contiguous
/// buffer per ring, and the zero-tail chunks are 4 KiB — allocations are
/// small and bounded by the ring geometry.
const Op = struct {
    buf: []u8,
};

/// The ring geometry for one engine capacity: worst case, one outstanding
/// steady batch queues through a ring of `entries` SQ slots (drained
/// eagerly at half full) — the ephemeral record's data + header writes and
/// the durable frame's frame + header writes, two SQEs per record per
/// stream — plus one compaction's contiguous runs (one data-ring write and
/// one header-ring write per stream; the durable data run is 768 B × N
/// whole frames, one op) and the two zero tails, while up to twice that
/// many completions sit unreaped in the CQ ring; the op table covers
/// `ops_len = 4 * entries` ids — above the unreaped-window bound of queued
/// + in-flight (< 3 * entries).
pub const Geometry = struct {
    entries: u16,
    ops_len: u32,
};

pub fn geometry_for_capacity(capacity: u32) Geometry {
    assert(capacity >= 1 and capacity <= wal_snapshot.ring_capacity_max);

    const tail_chunks = 2 * (capacity * wal_snapshot.header_record_size / 4096 + 1);
    const sq_need = 4 * @as(u32, capacity) + tail_chunks + 4 + 16;
    const entries: u32 = @max(1024, std.math.ceilPowerOfTwo(u32, sq_need) catch unreachable);

    return .{
        .entries = @intCast(entries),
        .ops_len = entries * 4,
    };
}

/// The io_uring + eventfd IO backend. Satisfies the `WalType(IO)` seam
/// (`write_at`, `pread_all`, `fsync`) and carries the ABI's extra
/// surface (`open`, `close`, `submit_batch`, `pump`, the eventfd, the
/// completion watermarks).
pub const UringIO = struct {
    fd: posix.fd_t,
    ring: linux.IoUring,
    event_fd: posix.fd_t,
    entries: u16,
    ops_len: u32,

    /// The ops table and done bitmap: id % ops_len, sound because the
    /// unreaped window stays below ops_len (see the geometry comment).
    ops: []?Op,
    done: []u64,

    /// Total operations queued since open — each op's id.
    submitted: u64 = 0,
    /// Every op with an id below this watermark has been reaped (in
    /// any order; the watermark advances contiguously).
    completed_contiguous: u64 = 0,
    /// CQEs that completed with a negative result (the write or fsync
    /// did not land). Never silent: the ABI poisons the handle.
    completion_errors: u64 = 0,
    /// enter() failures (everything but EINTR). Never silent.
    enter_errors: u64 = 0,
    /// The negative errno of the latest failed completion.
    last_errno: ?i32 = null,
    /// The fsync audit: blocking fsyncs completed through the ring.
    fsync_count: usize = 0,

    // The one fsync in flight at a time (the shutdown path).
    fsync_id: u64 = 0,
    fsync_res: i32 = 0,

    /// Open (create or open, never truncate) the fixed-size `.wal` file
    /// and build the ring. The open path is deliberately blocking (the
    /// same shape as `SyncIO.open`): exclusive non-blocking flock
    /// (single owner, fails fast), file + parent-dir fsync once, size
    /// check against the fixed 8 MiB two-stream layout. The ring is only
    /// the steady path's machinery.
    pub fn open(path: []const u8, geometry: Geometry) !UringIO {
        const dir_path = std.fs.path.dirname(path) orelse ".";
        const dir_fd = try posix.open(dir_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
        defer posix.close(dir_fd);

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
            try file.setEndPos(wal_snapshot.file_size);
        } else if (size != wal_snapshot.file_size) {
            return error.WalFileFormat;
        }

        var ring = try linux.IoUring.init(geometry.entries, 0);
        errdefer ring.deinit();

        const eventfd_rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
        switch (linux.E.init(eventfd_rc)) {
            .SUCCESS => {},
            else => |err| return posix.unexpectedErrno(err),
        }
        const event_fd: posix.fd_t = @intCast(eventfd_rc);
        errdefer posix.close(event_fd);

        try ring.register_eventfd(event_fd);

        const ops = try std.heap.c_allocator.alloc(?Op, geometry.ops_len);
        errdefer std.heap.c_allocator.free(ops);
        @memset(ops, null);

        const done = try std.heap.c_allocator.alloc(u64, geometry.ops_len / 64);
        errdefer std.heap.c_allocator.free(done);
        @memset(done, 0);

        return .{
            .fd = file.handle,
            .ring = ring,
            .event_fd = event_fd,
            .entries = geometry.entries,
            .ops_len = geometry.ops_len,
            .ops = ops,
            .done = done,
        };
    }

    pub fn close(self: *UringIO) void {
        // A dirty close drops the in-flight state by contract (the
        // documented loss window); free the queued buffers so nothing
        // leaks, then tear the ring down.
        for (self.ops) |maybe_op| {
            if (maybe_op) |op| std.heap.c_allocator.free(op.buf);
        }
        std.heap.c_allocator.free(self.ops);
        std.heap.c_allocator.free(self.done);
        self.ring.deinit();
        posix.close(self.event_fd);
        common.aof_blocking_close(self.fd);
    }

    /// Queue one pwrite SQE. The bytes are copied into op-owned storage
    /// (the SQE holds the pointer until the CQE); the SQ ring is entered
    /// eagerly at half full so a batch larger than the ring drains as it
    /// fills. No enter per write: the batch's one enter is
    /// `submit_batch`, called by the ABI once per steady tick.
    pub fn write_at(self: *UringIO, bytes: []const u8, offset: u64) !void {
        const buf = std.heap.c_allocator.dupe(u8, bytes) catch
            return error.WalBufferAlloc;

        const sqe = self.sqe_slot() catch {
            std.heap.c_allocator.free(buf);
            return error.WalRingFull;
        };
        sqe.prep_write(self.fd, buf, offset);
        sqe.user_data = self.submitted;
        self.ops[@intCast(self.submitted % self.ops_len)] = .{ .buf = buf };
        self.submitted += 1;
    }

    /// One non-blocking enter for everything queued so far — the steady
    /// tick's single syscall. Retries after reaping completions when the
    /// kernel reports the CQ ring busy. Returns the number of SQEs
    /// entered.
    pub fn submit_batch(self: *UringIO) !void {
        var attempts: usize = 0;
        while (attempts < 16) : (attempts += 1) {
            if (self.ring.submit()) |_| {
                return;
            } else |err| switch (err) {
                // The kernel wants completions reaped first:
                error.CompletionQueueOvercommitted,
                error.SystemResources,
                => {
                    _ = self.pump();
                    continue;
                },
                // A signal interrupted the enter; the SQEs are still
                // queued — retry.
                error.SignalInterrupt => continue,
                else => {
                    self.enter_errors += 1;
                    return error.WalEnterFailed;
                },
            }
        }
        self.enter_errors += 1;
        return error.WalEnterFailed;
    }

    /// Non-blocking completion reap: drains every CQE ready now, frees
    /// each op's buffer, advances the contiguous watermark. Returns the
    /// number of completions reaped. Failures are recorded on the
    /// backend (`completion_errors`, `last_errno`), never silent.
    pub fn pump(self: *UringIO) usize {
        var cqes: [64]linux.io_uring_cqe = undefined;
        var total: usize = 0;
        var attempts: usize = 0;
        while (attempts < 16) : (attempts += 1) {
            const n = self.ring.copy_cqes(&cqes, 0) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => {
                    self.enter_errors += 1;
                    return total;
                },
            };
            for (cqes[0..n]) |cqe| self.complete(cqe);
            total += n;
            if (n < cqes.len) break;
        }
        return total;
    }

    /// The shutdown generation's one blocking fsync, through the ring:
    /// every SQE queued before it (the flush's writes and any outstanding
    /// steady batch) completes first (IOSQE_IO_DRAIN — the kernel starts
    /// the fsync only after all previously submitted SQEs complete), the
    /// fsync runs, and this call blocks until the fsync's own CQE.
    pub fn fsync(self: *UringIO) !void {
        self.fsync_id = self.submitted;
        self.fsync_res = 0;

        const sqe = self.sqe_slot() catch return error.WalRingFull;
        sqe.prep_fsync(self.fd, 0);
        sqe.flags |= linux.IOSQE_IO_DRAIN;
        sqe.user_data = self.fsync_id;
        self.submitted += 1;

        try self.submit_batch();

        while (self.completed_contiguous <= self.fsync_id) {
            var cqes: [64]linux.io_uring_cqe = undefined;
            const n = self.ring.copy_cqes(&cqes, 1) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => return error.WalEnterFailed,
            };
            for (cqes[0..n]) |cqe| self.complete(cqe);
        }

        if (self.fsync_res < 0) {
            log.warn("wal uring: fsync failed with errno {d}", .{self.fsync_res});
            return error.WalFsyncFailed;
        }
        self.fsync_count += 1;
    }

    /// The read path (epoch selection, scan, hydration) runs at open,
    /// before the loop's steady ticking: a blocking pread. Reads are not
    /// ring IO — the design's io_uring is the steady tick's pwrites.
    pub fn pread_all(self: *UringIO, buffer: []u8, offset: u64) !usize {
        const file = std.fs.File{ .handle = self.fd };
        return file.preadAll(buffer, offset);
    }

    /// One vacant SQE slot: reap non-blocking and retry once when the
    /// queue is full (the geometry keeps this a corner, not a path).
    fn sqe_slot(self: *UringIO) !*linux.io_uring_sqe {
        if (self.ring.sq_ready() >= self.entries / 2) {
            self.submit_batch() catch return error.WalEnterFailed;
        }
        if (self.ring.get_sqe()) |sqe| {
            return sqe;
        } else |_| {
            _ = self.pump();
            return self.ring.get_sqe() catch return error.WalRingFull;
        }
    }

    fn complete(self: *UringIO, cqe: linux.io_uring_cqe) void {
        const id = cqe.user_data;
        const slot: usize = @intCast(id % self.ops_len);

        if (self.ops[slot]) |op| {
            std.heap.c_allocator.free(op.buf);
            self.ops[slot] = null;
        }

        if (cqe.res < 0) {
            self.completion_errors += 1;
            self.last_errno = cqe.res;
            if (id == self.fsync_id) self.fsync_res = cqe.res;
            log.warn("wal uring: op {d} completed with errno {d}", .{ id, cqe.res });
        }

        self.mark_done(id);
        while (self.done_bit(self.completed_contiguous)) {
            self.clear_done_bit(self.completed_contiguous);
            self.completed_contiguous += 1;
        }
    }

    fn mark_done(self: *UringIO, id: u64) void {
        const bit: u32 = @intCast(id % self.ops_len);
        self.done[bit / 64] |= @as(u64, 1) << @intCast(bit % 64);
    }

    fn clear_done_bit(self: *UringIO, id: u64) void {
        const bit: u32 = @intCast(id % self.ops_len);
        self.done[bit / 64] &= ~(@as(u64, 1) << @intCast(bit % 64));
    }

    fn done_bit(self: *const UringIO, id: u64) bool {
        const bit: u32 = @intCast(id % self.ops_len);
        return (self.done[bit / 64] & (@as(u64, 1) << @intCast(bit % 64))) != 0;
    }
};

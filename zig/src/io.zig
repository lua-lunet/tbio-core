//! The blocking IO backend for the vendored AOF-only build.
//!
//! Upstream `src/io.zig` switches between the three async direct-IO
//! backends (io_uring / kevent / IOCP) — the WAL/grid machinery. The AOF
//! deliberately sits outside that path: its write and read helpers are the
//! blocking page-cached calls in `io/common.zig` (vendored verbatim), and
//! its durability is one fsync per checkpoint. This backend exposes exactly
//! the IO surface `AOFType(IO)` consumes, with `fsync` implemented as a
//! blocking `posix.fsync` delivered through the same completion-callback
//! shape the async backends use — the checkpoint's contract ("checkpoint
//! completes once the file is durable") is unchanged.
const std = @import("std");
const posix = std.posix;
const builtin = @import("builtin");

const common = @import("io/common.zig");

pub const DirectIO = enum {
    direct_io_required,
    direct_io_optional,
    direct_io_disabled,
};

pub fn buffer_limit(buffer_len: usize) usize {
    // Linux limits how much may be written in a `pwrite()/pread()` call, which is `0x7ffff000` on
    // both 64-bit and 32-bit systems, due to using a signed C int as the return value, as well as
    // stuffing the errno codes into the last `4096` values.
    // Darwin limits writes to `0x7fffffff` bytes, more than that returns `EINVAL`.
    // The corresponding POSIX limit is `std.math.maxInt(isize)`.
    const limit = switch (builtin.target.os.tag) {
        .linux => 0x7ffff000,
        .macos, .ios, .watchos, .tvos => std.math.maxInt(i32),
        else => std.math.maxInt(isize),
    };
    return @min(limit, buffer_len);
}

pub const IO = struct {
    pub const fd_t = posix.fd_t;
    pub const INVALID_FILE: fd_t = -1;

    pub const WriteError = posix.WriteError;
    pub const PReadError = posix.PReadError;
    pub const FsyncError = posix.SyncError || posix.UnexpectedError;
    pub const OpenatError = posix.OpenError || posix.UnexpectedError;

    /// The async backends' completion carrier. The AOF only ever holds one
    /// (`AOF.checkpoint`'s fsync completion); a blocking fsync needs no
    /// state beyond the caller's callback pointer, but the type keeps the
    /// `AOF.checkpoint` code byte-identical to upstream.
    pub const Completion = struct {
        context: ?*anyopaque = null,
        callback: ?*const fn (context: *anyopaque, completion: *Completion, result: FsyncError!void) void = null,
        fd: fd_t = INVALID_FILE,
    };

    pub fn init(_: u32, _: u64) !IO {
        return .{};
    }

    pub fn deinit(_: *IO) void {}

    /// Opens a directory with read only access.
    pub fn open_dir(dir_path: []const u8) !fd_t {
        return posix.open(dir_path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    }

    pub fn fsync(
        self: *IO,
        comptime Context: type,
        context: Context,
        comptime callback: fn (
            context: Context,
            completion: *Completion,
            result: FsyncError!void,
        ) void,
        completion: *Completion,
        fd: fd_t,
    ) void {
        _ = self;
        callback(context, completion, posix_fsync_blocking(fd));
    }

    fn posix_fsync_blocking(fd: fd_t) FsyncError!void {
        const rc = posix.system.fsync(fd);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => return,
            .IO => return error.InputOutput,
            .NOSPC => return error.NoSpaceLeft,
            .ROFS => return error.AccessDenied,
            else => |err| return posix.unexpectedErrno(err),
        }
    }

    pub fn aof_blocking_write_all(_: *IO, fd: fd_t, buffer: []const u8) posix.WriteError!void {
        return common.aof_blocking_write_all(fd, buffer);
    }

    pub fn aof_blocking_pread_all(_: *IO, fd: fd_t, buffer: []u8, offset: u64) PReadError!usize {
        return common.aof_blocking_pread_all(fd, buffer, offset);
    }

    pub fn aof_blocking_close(_: *IO, fd: fd_t) void {
        return common.aof_blocking_close(fd);
    }

    pub fn aof_blocking_stat(_: *IO, path: []const u8) std.fs.Dir.StatFileError!std.fs.File.Stat {
        return common.aof_blocking_stat(path);
    }

    pub fn aof_blocking_fstat(_: *IO, fd: fd_t) std.fs.Dir.StatError!std.fs.File.Stat {
        return common.aof_blocking_fstat(fd);
    }

    /// Open an AOF file the way upstream's darwin backend does: resolve the
    /// parent directory, open the file inside it with an exclusive lock and
    /// no truncation, fsync the file and the parent directory, and leave
    /// the write cursor at end-of-file.
    pub fn aof_blocking_open(io: *IO, path: []const u8) !fd_t {
        const dir_path = std.fs.path.dirname(path) orelse ".";
        const dir_fd = try open_dir(dir_path);
        defer io.aof_blocking_close(dir_fd);

        const file_path = std.fs.path.basename(path);

        return common.aof_blocking_open(dir_fd, file_path);
    }
};

//! The AOF-blocking-IO slice of upstream `src/io/common.zig`
//! (TigerBeetle 0.17.9), vendored verbatim with the TCP/trace helpers the
//! AOF never touches removed (upstream `listen`, `tcp_options`,
//! `setsockopt`'s socket surface, and the `Stats`/`Tracer` plumbing).
//! The vendored functions below are byte-identical to upstream at the
//! pinned ref — this is the actual AOF write/read IO: plain blocking
//! page-cached `std.fs` calls, no O_DIRECT, no event loop.
const builtin = @import("builtin");
const std = @import("std");
const posix = std.posix;

const assert = std.debug.assert;

pub fn aof_blocking_write_all(fd: posix.fd_t, buffer: []const u8) posix.WriteError!void {
    const file = std.fs.File{ .handle = fd };
    return file.writeAll(buffer);
}

pub fn aof_blocking_pread_all(fd: posix.fd_t, buffer: []u8, offset: u64) posix.PReadError!usize {
    const file = std.fs.File{ .handle = fd };
    return file.preadAll(buffer, offset);
}

pub fn aof_blocking_close(fd: posix.fd_t) void {
    const file = std.fs.File{ .handle = fd };
    file.close();
}

pub fn aof_blocking_stat(path: []const u8) std.fs.Dir.StatFileError!std.fs.File.Stat {
    return std.fs.cwd().statFile(path);
}

pub fn aof_blocking_fstat(fd: posix.fd_t) std.fs.Dir.StatError!std.fs.File.Stat {
    const file = std.fs.File{ .handle = fd };
    return file.stat();
}

pub fn aof_blocking_open(dir_fd: posix.fd_t, path: []const u8) !posix.fd_t {
    assert(!std.fs.path.isAbsolute(path));

    const dir = std.fs.Dir{ .fd = dir_fd };

    const file = try dir.createFile(path, .{
        .read = true,
        .truncate = false,
        .exclusive = false,
        .lock = .exclusive,
    });
    errdefer file.close();

    try file.sync();

    // We cannot fsync the directory handle on Windows.
    // We have no way to open a directory with write access.
    if (builtin.os.tag != .windows) {
        try std.posix.fsync(dir_fd);
    }

    try file.seekFromEnd(0);

    return file.handle;
}

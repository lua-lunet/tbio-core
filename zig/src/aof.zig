const std = @import("std");
const assert = std.debug.assert;

const constants = @import("constants.zig");
const vsr = @import("vsr.zig");
const stdx = @import("stdx");
const MessagePool = vsr.message_pool.MessagePool;
const Message = MessagePool.Message;
const Header = vsr.Header;

const MiB = stdx.MiB;

const log = std.log.scoped(.aof);

pub const std_options: std.Options = .{
    .log_level = .info,
    .logFn = stdx.log_with_timestamp,
};

const magic_number: u128 = 0xbcd8d3fee406119ed192c4f4c4fc82;

pub const AOFEntry = extern struct {
    /// In case of extreme corruption, start each entry with a fixed random integer,
    /// to allow skipping over corrupted entries.
    magic_number: u128 = magic_number,

    /// The main Message to log.
    /// This is written _without_ O_DIRECT, so sector alignment is not a concern.
    message: [constants.message_size_max]u8 align(@sizeOf(u128)),

    comptime {
        assert(stdx.no_padding(AOFEntry));

        // Ensure the message is the last field in the struct. When writing, the struct is truncated
        // based on the message length, so any fields after it would be truncated.
        assert(std.meta.fieldIndex(AOFEntry, "message").? == std.meta.fields(AOFEntry).len - 1);
    }

    /// Calculate the actual length of the AOFEntry that needs to be written to disk.
    pub fn size_disk(self: *AOFEntry) u64 {
        return @sizeOf(AOFEntry) - self.message.len + self.header().size;
    }

    /// The minimum size of an AOFEntry is when `message` is a Header with no body.
    pub fn size_minimum(self: *AOFEntry) u64 {
        return @sizeOf(AOFEntry) - self.message.len + @sizeOf(Header);
    }

    pub fn header(self: *AOFEntry) *Header.Prepare {
        return @ptrCast(&self.message);
    }

    /// Turn an AOFEntry back into a Message.
    pub fn to_message(self: *AOFEntry, target: *Message.Prepare) void {
        stdx.copy_disjoint(.inexact, u8, target.buffer, self.message[0..self.header().size]);
    }

    pub fn from_message(
        self: *AOFEntry,
        message: *const Message.Prepare,
        last_checksum: *?u128,
    ) void {
        assert(message.header.size <= self.message.len);

        // When writing, entries can backtrack / duplicate, so we don't necessarily have a valid
        // chain. Still, log when that happens. The `aof merge` command can generate a consistent
        // file from entries like these.
        log.debug("from_message: parent {x:0>32} (should == {x:0>32}) our checksum {x:0>32}", .{
            message.header.parent,
            last_checksum.* orelse 0,
            message.header.checksum,
        });
        if (last_checksum.* == null or last_checksum.*.? != message.header.parent) {
            log.info("from_message: parent {x:0>32}, expected {x:0>32} instead", .{
                message.header.parent,
                last_checksum.* orelse 0,
            });
        }
        last_checksum.* = message.header.checksum;

        // The cluster identifier is in the VSR header so we don't need to store it explicitly.
        // The replica that this was logged on will be the replica with this file. If uploaded to
        // object storage, this must be embedded in the filename or path.
        // Whether this replica is the primary can be determined by the view number from the
        // relevant op.
        comptime {
            const fields = std.meta.fieldNames(AOFEntry);
            assert(fields.len == 2);
            assert(std.mem.eql(u8, fields[0], "magic_number"));
            assert(std.mem.eql(u8, fields[1], "message"));
        }

        // Using self.* = .{ .message = undefined } notation causes a `constants.message_size_max`
        // increase in binary size, since Zig embeds the entire static initialization payload in the
        // binary.
        self.* = undefined;
        self.magic_number = magic_number;
        stdx.copy_disjoint(
            .exact,
            u8,
            self.message[0..message.header.size],
            message.buffer[0..message.header.size],
        );
        @memset(self.message[message.header.size..self.message.len], 0);
    }
};
pub fn AOFType(comptime IO: type) type {
    return struct {
        const AOF = @This();

        io: *IO,
        path: []const u8,
        fd: ?IO.fd_t = null,
        last_checksum: ?u128 = null,

        state: union(enum) {
            /// Store the number of unflushed entries - that is, calls to write() without
            /// checkpoint() to ensure we don't ever buffer more than the WAL can hold.
            writing: struct { unflushed: u64 },

            /// Keep an opaque pointer to the replica to workaround AOF being ?*AOF in Replica, and
            /// @fieldParentPtr being cumbersome with that.
            checkpoint: struct {
                replica: *anyopaque,
                replica_callback: *const fn (*anyopaque) void,
                fsync_completion: IO.Completion,
            },
        } = .{ .writing = .{ .unflushed = 0 } },
        size: usize = 0,

        /// Create an AOF in the dir_fd when given a file name. dir_fd must be opened read write
        /// (except on Windows). This ensures everything (including the dir) is fsync'd
        /// appropriately. Closing dir_fd is the responsibility of the caller, which can be done
        /// immediately after .init() finishes.
        pub fn init(
            io: *IO,
            path: []const u8,
        ) !AOF {
            stdx.maybe(std.fs.path.isAbsolute(path));
            assert(std.mem.endsWith(u8, path, ".aof"));

            return AOF{
                .io = io,
                .path = path,
                .fd = try io.aof_blocking_open(path),
            };
        }

        pub fn close(self: *AOF) void {
            assert(self.fd != null);

            self.io.aof_blocking_close(self.fd.?);
            self.fd = null;
        }

        /// Write a message to disk, with standard blocking IO but using the OS's page cache. The
        /// AOF borrows durability from the write ahead log: if the AOF hasn't been flushed, and the
        /// machine loses power, the op is guaranteed to still be in the WAL.
        pub fn write(self: *AOF, message: *const Message.Prepare) !void {
            assert(self.state == .writing);
            assert(self.state.writing.unflushed < constants.journal_slot_count);

            var entry: AOFEntry align(constants.sector_size) = undefined;
            entry.from_message(
                message,
                &self.last_checksum,
            );

            const size_disk = entry.size_disk();
            const bytes = std.mem.asBytes(&entry);

            try self.io.aof_blocking_write_all(self.fd.?, bytes[0..size_disk]);

            self.size += size_disk;
            self.state.writing.unflushed += 1;
        }

        pub fn sync(self: *AOF) void {
            assert(self.state == .writing);
            assert(self.state.writing.unflushed <= constants.journal_slot_count);
            self.state.writing.unflushed = 0;
        }

        pub fn checkpoint(
            self: *AOF,
            replica: *anyopaque,
            callback: *const fn (*anyopaque) void,
        ) void {
            assert(self.state == .writing);
            assert(self.state.writing.unflushed <= constants.journal_slot_count);

            self.state = .{
                .checkpoint = .{
                    .replica = replica,
                    .fsync_completion = undefined,
                    .replica_callback = callback,
                },
            };

            self.io.fsync(
                *AOF,
                self,
                on_fsync,
                &self.state.checkpoint.fsync_completion,
                self.fd.?,
            );
        }

        fn on_fsync(self: *AOF, completion: *IO.Completion, result: IO.FsyncError!void) void {
            _ = completion;
            _ = result catch @panic("aof fsync failure");

            assert(self.state == .checkpoint);
            const replica = self.state.checkpoint.replica;
            const replica_callback = self.state.checkpoint.replica_callback;
            self.state = .{ .writing = .{ .unflushed = 0 } };

            const stat_file = self.io.aof_blocking_stat(self.path) catch |err| switch (err) {
                error.FileNotFound => blk: {
                    log.info("{s} not found; creating", .{self.path});
                    self.close();
                    assert(self.fd == null);
                    self.fd = self.io.aof_blocking_open(self.path) catch |e| {
                        std.debug.panic("failed to reopen {s} after rotate: {}", .{ self.path, e });
                    };

                    break :blk self.io.aof_blocking_stat(self.path) catch |e| {
                        log.warn("failed to stat aof ({s}): {}", .{ self.path, e });
                        break :blk null;
                    };
                },
                else => blk: {
                    log.warn("failed to stat aof ({s}): {}", .{ self.path, err });
                    break :blk null;
                },
            };

            const stat_fd = self.io.aof_blocking_fstat(self.fd.?) catch |err| blk: {
                log.warn("failed to fstat aof ({s}): {}", .{ self.path, err });
                break :blk null;
            };

            // AOF change detection relies on detecting the file being removed, and *it* will
            // recreate it. It is an error for the operator to try and create file externally
            // (eg, touch tigerbeetle.aof).
            //
            // Warn the operator strongly if this happens.
            if (stat_fd != null and stat_file != null and stat_fd.?.inode != stat_file.?.inode) {
                log.err("AOF inode mismatch detected - the AOF file path is not the same as " ++
                    "the open file descriptor being written to.", .{});
                log.err(
                    "Move {s} out the way, and let tigerbeetle recreate the AOF.",
                    .{self.path},
                );
            }

            replica_callback(replica);
        }

        pub fn validate(self: *AOF, allocator: std.mem.Allocator, last_checksum: ?u128) !void {
            var validation_target: AOFEntry = undefined;

            var validation_checksums = std.AutoHashMap(u128, void).init(allocator);
            defer validation_checksums.deinit();

            var it = Iterator{
                .file_descriptor = self.fd.?,
                .io = self.io,
                .size = self.size,
            };

            // The iterator only does simple chain validation, but we can have backtracking
            // or duplicates, and still have a valid AOF. Handle this by keeping track of
            // every checksum we've seen so far, and considering it OK as long as we've seen
            // a parent.
            it.validate_chain = false;

            var last_entry: ?*AOFEntry = null;

            while (try it.next(&validation_target)) |entry| {
                const header = entry.header();

                if (entry.header().op == 1) {
                    // For op=1, put its parent in our list of seen checksums too.
                    // This handles the case where it gets replayed, but we don't record
                    // op=0 so the assert below would fail.
                    // It's needed for simulator validation only (aof merge uses a
                    // different method to walk down AOF entries).
                    try validation_checksums.put(header.parent, {});
                } else {
                    // (Null due to state sync skipping commits.)
                    stdx.maybe(validation_checksums.get(header.parent) == null);
                }

                try validation_checksums.put(header.checksum, {});

                last_entry = entry;
            }

            if (last_checksum) |checksum| {
                if (last_entry.?.header().checksum != checksum) {
                    return error.ChecksumMismatch;
                }
                log.info("validated all aof entries. last entry checksum {x:0>32} matches " ++
                    " supplied {x:0>32}", .{ last_entry.?.header().checksum, checksum });
            } else {
                log.info("validated present aof entries.", .{});
            }
        }

        pub fn reset(self: *AOF) void {
            self.state = .{ .writing = .{ .unflushed = 0 } };
        }

        /// Return an iterator into an AOF, to read entries one by one. This also validates that
        /// both the header and body checksums of the read entry are valid, and that all checksums
        /// chain correctly.
        pub const Iterator = struct {
            io: *IO,
            file_descriptor: IO.fd_t,
            size: u64,
            offset: u64 = 0,

            validate_chain: bool = true,
            last_checksum: ?u128 = null,

            pub fn init(io: *IO, path: []const u8) !Iterator {
                const file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
                errdefer file.close();

                const size = (try file.stat()).size;

                return Iterator{ .io = io, .file_descriptor = file.handle, .size = size };
            }

            pub fn next(it: *Iterator, target: *AOFEntry) !?*AOFEntry {
                if (it.offset >= it.size) return null;

                const buf = std.mem.asBytes(target);
                const bytes_read = try it.io.aof_blocking_pread_all(
                    it.file_descriptor,
                    buf,
                    it.offset,
                );

                // size_disk relies on information that was stored on disk, so further verify we
                // have read at least the minimum permissible.
                if (bytes_read < target.size_minimum() or
                    bytes_read < target.size_disk())
                {
                    return error.AOFShortRead;
                }

                if (target.magic_number != magic_number) {
                    return error.AOFMagicNumberMismatch;
                }

                const header = target.header();
                if (!header.valid_checksum()) {
                    return error.AOFChecksumMismatch;
                }

                if (!header.valid_checksum_body(target.message[@sizeOf(Header)..header.size])) {
                    return error.AOFBodyChecksumMismatch;
                }

                // Ensure this file has a consistent hash chain
                if (it.validate_chain) {
                    if (it.last_checksum != null and it.last_checksum.? != header.parent) {
                        return error.AOFChecksumChainMismatch;
                    }
                }

                it.last_checksum = header.checksum;

                it.offset += target.size_disk();

                return target;
            }

            pub fn reset(it: *Iterator) !void {
                it.offset = 0;
            }

            pub fn close(it: *Iterator) void {
                it.io.aof_blocking_close(it.file_descriptor);
            }

            /// Try skip ahead to the next entry in a potentially corrupted AOF file
            /// by searching from our current position for the next magic_number, seeking
            /// to it, and setting our internal position correctly.
            pub fn skip(it: *Iterator, allocator: std.mem.Allocator, count: usize) !void {
                var skip_buffer = try allocator.alloc(u8, 1 * MiB);
                defer allocator.free(skip_buffer);

                while (it.offset < it.size) {
                    const bytes_read = try it.io.aof_blocking_pread_all(
                        it.file_descriptor,
                        skip_buffer,
                        it.offset,
                    );
                    const offset = std.mem.indexOfPos(
                        u8,
                        skip_buffer[0..bytes_read],
                        count,
                        std.mem.asBytes(&magic_number),
                    );

                    if (offset) |offset_bytes| {
                        it.offset += offset_bytes;
                        break;
                    } else {
                        it.offset += skip_buffer.len;
                    }
                }
            }
        };
    };
}

const testing = std.testing;

test "aof write / read" {
    const IO = @import("io.zig").IO;
    const AOF = AOFType(IO);
    const AOFIterator = AOF.Iterator;

    const aof_file = "test.aof";
    std.fs.cwd().deleteFile(aof_file) catch {};
    defer std.fs.cwd().deleteFile(aof_file) catch {};

    const allocator = std.testing.allocator;

    var io = try IO.init(32, 0);
    defer io.deinit();

    const dir_fd = try IO.open_dir(".");
    defer std.posix.close(dir_fd);

    var aof = try AOF.init(&io, aof_file);

    var message_pool = try MessagePool.init_capacity(allocator, 2);
    defer message_pool.deinit(allocator);

    const demo_message = message_pool.get_message(.prepare);
    defer message_pool.unref(demo_message);

    const target = try allocator.create(AOFEntry);
    defer allocator.destroy(target);

    const demo_payload = "hello world";

    // The command / operation used here don't matter - we verify things bitwise.
    demo_message.header.* = .{
        .op = 0,
        .commit = 0,
        .view = 0,
        .client = 0,
        .request = 0,
        .parent = 0,
        .request_checksum = 0,
        .cluster = 0,
        .timestamp = 0,
        .checkpoint_id = 0,
        .release = vsr.Release.minimum,
        .command = .prepare,
        .operation = @enumFromInt(4),
        .size = @intCast(@sizeOf(Header) + demo_payload.len),
    };

    stdx.copy_disjoint(.exact, u8, demo_message.body_used(), demo_payload);
    demo_message.header.set_checksum_body(demo_payload);
    demo_message.header.set_checksum();

    try aof.write(demo_message);
    aof.close();

    var it = try AOFIterator.init(&io, aof_file);
    defer it.close();

    const read_entry = (try it.next(target)).?;

    // Check that to_message also works as expected
    const read_message = message_pool.get_message(.prepare);
    defer message_pool.unref(read_message);

    read_entry.to_message(read_message);
    try testing.expect(std.mem.eql(
        u8,
        demo_message.buffer[0..demo_message.header.size],
        read_message.buffer[0..read_message.header.size],
    ));

    try testing.expect(std.mem.eql(
        u8,
        demo_message.buffer[0..demo_message.header.size],
        read_entry.message[0..read_entry.header().size],
    ));

    // Ensure our iterator works correctly and stops at EOF.
    try testing.expect((try it.next(target)) == null);
}

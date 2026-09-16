//! The stripped VSR root module for the vendored AOF-only build.
//!
//! Vendored from TigerBeetle 0.17.9 (`src/vsr.zig`, upstream commit of the
//! release tag) and stripped to exactly the surface the AOF code path
//! needs: the wire `Header` and its checksums (vsr/checksum.zig, Aegis),
//! the `Release` identity types (the pure subset of multiversion.zig), the
//! process/command enums the header encodes, the `Zone`/`BlockReference`
//! types constants.zig and schema.zig name, and the MessagePool the AOF's
//! write/read tests (and this crate's FFI bridge) construct prepares with.
//!
//! Everything else upstream `vsr.zig` re-exports — Replica, Client, the
//! message bus, the grid, the journal, storage, sync, the testing corpus —
//! is deliberately absent: the AOF is a blocking page-cached write-behind
//! log and does not ride the direct-IO event loop. See VENDORED.md for the
//! full upstream-to-vendored file map.
const std = @import("std");
const math = std.math;
const assert = std.debug.assert;
const maybe = stdx.maybe;
const log = std.log.scoped(.vsr);

const constants = @import("constants.zig");
pub const stdx = @import("stdx");

pub const multiversion = @import("multiversion.zig");
pub const Release = multiversion.Release;
pub const ReleaseTriple = multiversion.ReleaseTriple;

pub const checksum = @import("vsr/checksum.zig").checksum;
pub const Header = @import("vsr/message_header.zig").Header;
pub const MessagePool = @import("message_pool.zig").MessagePool;
pub const tigerbeetle = @import("tigerbeetle.zig");

pub const message_pool = @import("message_pool.zig");

/// The superblock header (vendored `vsr/superblock.zig`), kept for the
/// `CheckpointState` extern struct the wire header validation names. The
/// SuperBlock state machine itself is upstream's; only the on-wire layout
/// types are referenced here.
const superblock = @import("vsr/superblock.zig");
pub const CheckpointState = superblock.SuperBlockHeader.CheckpointState;

/// The version of our Viewstamped Replication protocol in use, including customizations.
/// For backwards compatibility through breaking changes (e.g. upgrading checksums/ciphers).
pub const Version: u16 = 0;

pub const ProcessType = enum { replica, client };

/// Viewstamped Replication protocol commands:
pub const Command = enum(u8) {
    // Looking to make backwards incompatible changes here? Make sure to check release.zig for
    // `release_triple_client_min`.

    reserved = 0,

    ping = 1,
    pong = 2,

    ping_client = 3,
    pong_client = 4,

    request = 5,
    prepare = 6,
    prepare_ok = 7,
    reply = 8,
    commit = 9,

    exit_view = 10,
    join_view = 11,
    get_view = 13,

    get_headers = 14,
    get_prepare = 15,
    get_reply = 16,
    get_blocks = 19,

    headers = 17,

    eviction = 18,

    block = 20,

    view = 24,

    // If a command is removed from the protocol, its ordinal is added here and can't be re-used.
    deprecated_12 = 12, // .view without checkpoint
    deprecated_21 = 21, // .request_sync_checkpoint
    deprecated_22 = 22, // .sync_checkpoint
    deprecated_23 = 23, // .view with an older version of CheckpointState

    comptime {
        for (std.enums.values(Command)) |command| {
            assert(@intFromEnum(command) < std.enums.values(Command).len);
        }
    }
};

/// This type exists to avoid making the Header type dependent on the state
/// machine used, which would cause awkward circular type dependencies.
pub const Operation = enum(u8) {
    // Looking to make backwards incompatible changes here? Make sure to check release.zig for
    // `release_triple_client_min`.

    /// Operations reserved by VR protocol (for all state machines):
    /// The value 0 is reserved to prevent a spurious zero from being interpreted as an operation.
    reserved = 0,
    /// The value 1 is reserved to initialize the cluster.
    root = 1,
    /// The value 2 is reserved to register a client session with the cluster.
    register = 2,
    /// The value 3 is reserved for reconfiguration request.
    reconfigure = 3,
    /// The value 4 is reserved for pulse request.
    pulse = 4,
    /// The value 5 is reserved for release-upgrade requests.
    upgrade = 5,
    /// The value 6 is reserved for noop requests.
    noop = 6,

    /// Operations <vsr_operations_reserved are reserved for the control plane.
    /// Operations ≥vsr_operations_reserved are available for the state machine.
    _,

    pub fn from(comptime StateMachineOperation: type, operation: StateMachineOperation) Operation {
        comptime check_state_machine_operations(StateMachineOperation);
        return @as(Operation, @enumFromInt(@intFromEnum(operation)));
    }

    pub fn to(comptime StateMachineOperation: type, operation: Operation) StateMachineOperation {
        comptime check_state_machine_operations(StateMachineOperation);
        assert(operation.valid(StateMachineOperation));
        assert(!operation.vsr_reserved());
        return @as(StateMachineOperation, @enumFromInt(@intFromEnum(operation)));
    }

    pub fn cast(self: Operation, comptime StateMachineOperation: type) StateMachineOperation {
        comptime check_state_machine_operations(StateMachineOperation);
        return StateMachineOperation.from_vsr(self).?;
    }

    pub fn valid(self: Operation, comptime StateMachineOperation: type) bool {
        comptime check_state_machine_operations(StateMachineOperation);

        inline for (.{ Operation, StateMachineOperation }) |Enum| {
            const ops = comptime std.enums.values(Enum);
            inline for (ops) |op| {
                if (@intFromEnum(self) == @intFromEnum(op)) {
                    return true;
                }
            }
        }

        return false;
    }

    pub fn vsr_reserved(self: Operation) bool {
        return @intFromEnum(self) < constants.vsr_operations_reserved;
    }

    pub fn tag_name(self: Operation, comptime StateMachineOperation: type) []const u8 {
        assert(self.valid(StateMachineOperation));
        inline for (.{ Operation, StateMachineOperation }) |Enum| {
            inline for (@typeInfo(Enum).@"enum".fields) |field| {
                const op = @field(Enum, field.name);
                if (@intFromEnum(self) == @intFromEnum(op)) {
                    return field.name;
                }
            }
        }
        unreachable;
    }

    fn check_state_machine_operations(comptime StateMachineOperation: type) void {
        comptime {
            @setEvalBranchQuota(20_000);
            assert(@typeInfo(StateMachineOperation) == .@"enum");
            assert(@typeInfo(StateMachineOperation).@"enum".is_exhaustive);
            assert(@typeInfo(StateMachineOperation).@"enum".tag_type ==
                @typeInfo(Operation).@"enum".tag_type);
            for (@typeInfo(StateMachineOperation).@"enum".fields) |field| {
                const operation = @field(StateMachineOperation, field.name);
                if (@intFromEnum(operation) < constants.vsr_operations_reserved) {
                    @compileError("StateMachine Operation is reserved");
                }
            }
            for (@typeInfo(Operation).@"enum".fields) |field| {
                const vsr_operation = @field(Operation, field.name);
                switch (vsr_operation) {
                    // The StateMachine Operation can convert
                    // a `vsr.Operation.pulse` into a valid operation.
                    .pulse => maybe(StateMachineOperation.from_vsr(vsr_operation) == null),
                    else => assert(StateMachineOperation.from_vsr(vsr_operation) == null),
                }
            }
        }
    }
};

/// Reference to a single block in the grid.
///
/// Blocks are always referred to by a pair of an address and a checksum to protect from misdirected
/// reads and writes: checksum inside the block itself doesn't help if the disk accidentally reads a
/// wrong block.
///
/// Block addresses start from one, such that zeroed-out memory can not be confused with a valid
/// address.
pub const BlockReference = struct {
    checksum: u128,
    address: u64,
};

/// Whether the immediate sender is a replica or client (if this can be determined).
pub const Peer = union(enum) {
    unknown,
    replica: u8,
    client: u128,
    client_likely: u128,

    pub fn transition(old: Peer, new: Peer) enum { retain, update, reject } {
        return switch (old) {
            .unknown => .update,
            .client_likely => switch (new) {
                .client_likely => if (std.meta.eql(old, new))
                    .retain
                else
                    .retain,
                .client => if (old.client_likely == new.client) .update else .reject,
                .replica => .update,
                .unknown => .retain,
            },

            .replica => switch (new) {
                .replica => if (std.meta.eql(old, new)) .retain else .reject,
                .client => .reject,
                .client_likely, .unknown => .retain,
            },
            .client => switch (new) {
                .client => if (std.meta.eql(old, new)) .retain else .reject,
                .client_likely => if (old.client == new.client_likely) .retain else .reject,
                .replica => .reject,
                .unknown => .retain,
            },
        };
    }
};

/// Body of the builtin operation=.register request (the wire struct the
/// header validation sizes against).
pub const RegisterRequest = extern struct {
    /// When command=request, batch_size_limit = 0.
    /// When command=prepare, batch_size_limit > 0 and batch_size_limit ≤ message_body_size_max.
    /// (Note that this does *not* include the `@sizeOf(Header)`.)
    batch_size_limit: u32,
    reserved: [252]u8 = @splat(0),

    comptime {
        assert(@sizeOf(RegisterRequest) == 256);
        assert(@sizeOf(RegisterRequest) <= constants.message_body_size_max);
        assert(stdx.no_padding(RegisterRequest));
    }
};

pub const RegisterResult = extern struct {
    batch_size_limit: u32,
    reserved: [60]u8 = @splat(0),

    comptime {
        assert(@sizeOf(RegisterResult) == 64);
        assert(@sizeOf(RegisterResult) <= constants.message_body_size_max);
        assert(stdx.no_padding(RegisterResult));
    }
};

pub const BlockRequest = extern struct {
    block_checksum: u128,
    block_address: u64,
    reserved: [8]u8 = @splat(0),

    comptime {
        assert(@sizeOf(BlockRequest) == 32);
        assert(@sizeOf(BlockRequest) <= constants.message_body_size_max);
        assert(stdx.no_padding(BlockRequest));
    }
};

pub const UpgradeRequest = extern struct {
    release: Release,
    reserved: [12]u8 = @splat(0),

    comptime {
        assert(@sizeOf(UpgradeRequest) == 16);
        assert(@sizeOf(UpgradeRequest) <= constants.message_body_size_max);
        assert(stdx.no_padding(UpgradeRequest));
    }
};

/// Set of replica_ids of cluster members, where order of ids determines replica indexes.
pub const Members = [constants.members_max]u128;

/// Check that:
///  - all non-zero elements are different
///  - all zero elements are trailing
pub fn valid_members(members: *const Members) bool {
    for (members, 0..) |replica_i, i| {
        for (members[0..i]) |replica_j| {
            if (replica_j == 0 and replica_i != 0) return false;
            if (replica_j != 0 and replica_j == replica_i) return false;
        }
    }
    return true;
}

fn member_count(members: *const Members) u8 {
    for (members, 0..) |member, index| {
        if (member == 0) return @intCast(index);
    }
    return constants.members_max;
}

/// Upstream 0.17.9 verbatim (`src/vsr.zig`): locates a replica_id's index.
/// Re-added (from the upstream strip) for the superblock quorum machinery:
/// the superblock's own consistency asserts name it.
pub fn member_index(members: *const Members, replica_id: u128) ?u8 {
    assert(replica_id != 0);
    assert(valid_members(members));
    for (members, 0..) |member, replica_index| {
        if (member == replica_id) return @intCast(replica_index);
    } else return null;
}

/// Upstream 0.17.9 verbatim (`src/vsr.zig`), re-added for the vendored
/// superblock's zone constants: `data_file_size_min` computes the grid
/// padding offset through `Zone.size`.
pub const Zone = enum {
    superblock,
    wal_headers,
    wal_prepares,
    client_replies,
    // Add padding between `client_replies` and `grid`, to make sure grid blocks are aligned to
    // block size and not just to sector size. Aligning blocks this way makes it more likely that
    // they are aligned to the underlying physical sector size. This padding is zeroed during
    // format, but isn't used otherwise.
    grid_padding,
    grid,

    const size_superblock = superblock.superblock_zone_size;
    const size_wal_headers = constants.journal_size_headers;
    const size_wal_prepares = constants.journal_size_prepares;
    const size_client_replies = constants.client_replies_size;
    const size_grid_padding = size_grid_padding: {
        const grid_start_unaligned = size_superblock +
            size_wal_headers +
            size_wal_prepares +
            size_client_replies;
        const grid_start_aligned = std.mem.alignForward(
            usize,
            grid_start_unaligned,
            constants.block_size,
        );
        break :size_grid_padding grid_start_aligned - grid_start_unaligned;
    };

    comptime {
        for (.{
            size_superblock,
            size_wal_headers,
            size_wal_prepares,
            size_client_replies,
            size_grid_padding,
        }) |zone_size| {
            assert(zone_size % constants.sector_size == 0);
        }

        for (std.enums.values(Zone)) |zone| {
            assert(Zone.start(zone) % constants.sector_size == 0);
        }
        assert(Zone.start(.grid) % constants.block_size == 0);
    }

    pub fn offset(zone: Zone, offset_logical: u64) u64 {
        if (zone.size()) |zone_size| {
            assert(offset_logical < zone_size);
        }

        return zone.start() + offset_logical;
    }

    pub fn start(zone: Zone) u64 {
        comptime var start_offset = 0;
        inline for (comptime std.enums.values(Zone)) |z| {
            if (z == zone) return start_offset;
            start_offset += comptime size(z) orelse 0;
        }
        unreachable;
    }

    pub fn size(zone: Zone) ?u64 {
        return switch (zone) {
            .superblock => size_superblock,
            .wal_headers => size_wal_headers,
            .wal_prepares => size_wal_prepares,
            .client_replies => size_client_replies,
            .grid_padding => size_grid_padding,
            .grid => null,
        };
    }
};

/// Upstream 0.17.9 verbatim (`src/vsr/client_sessions.zig`): the on-disk
/// encode size of the client sessions. Re-added (the exact computation;
/// the client-session machinery itself is not the AOF path) for the
/// vendored superblock's consistency asserts, which compare a checkpoint's
/// `client_sessions_size` against it.
pub const ClientSessions = struct {
    /// Size of the buffer needed to encode the client sessions on disk.
    /// (Not rounded up to a sector boundary).
    pub const encode_size = blk: {
        var size_max: usize = 0;

        // First goes the vsr headers for the entries.
        // This takes advantage of the buffer alignment to avoid adding padding for the headers.
        assert(@alignOf(Header) == 16);
        size_max = std.mem.alignForward(usize, size_max, 16);
        size_max += @sizeOf(Header) * constants.clients_max;

        // Then follows the session values for the entries.
        assert(@alignOf(u64) == 8);
        size_max = std.mem.alignForward(usize, size_max, 8);
        size_max += @sizeOf(u64) * constants.clients_max;

        // For encoding/decoding simplicity, the ClientSessions always fits in a single block.
        assert(size_max <= constants.block_size - @sizeOf(Header));

        break :blk size_max;
    };
};

pub const ReconfigurationResult = enum(u32) {
    reserved = 0,
    /// Reconfiguration request is valid.
    ok = 1,

    replica_count_zero = 2,
    replica_count_max_exceeded = 3,
    standby_count_max_exceeded = 4,

    members_invalid = 5,
    members_count_invalid = 6,

    reserved_field = 7,
    result_must_be_reserved = 8,

    epoch_in_the_past = 9,
    epoch_in_the_future = 10,

    different_replica_count = 11,
    different_standby_count = 12,
    different_member_set = 13,

    configuration_applied = 14,
    configuration_conflict = 15,
    configuration_is_no_op = 16,

    comptime {
        for (std.enums.values(ReconfigurationResult), 0..) |result, index| {
            assert(@intFromEnum(result) == index);
        }
    }
};

/// Body of the builtin operation=.reconfigure request.
pub const ReconfigurationRequest = extern struct {
    /// The new list of members.
    members: Members,
    /// The new epoch.
    epoch: u32,
    /// The new replica count.
    replica_count: u8,
    /// The new standby count.
    standby_count: u8,
    reserved: [54]u8 = @splat(0),
    /// The result of this request. Set to zero by the client and filled-in by the primary when it
    /// accepts a reconfiguration request.
    result: ReconfigurationResult,

    comptime {
        assert(@sizeOf(ReconfigurationRequest) == 256);
        assert(stdx.no_padding(ReconfigurationRequest));
    }

    pub fn validate(
        request: *const ReconfigurationRequest,
        current: struct {
            members: *const Members,
            epoch: u32,
            replica_count: u8,
            standby_count: u8,
        },
    ) ReconfigurationResult {
        assert(member_count(current.members) == current.replica_count + current.standby_count);

        if (request.replica_count == 0) return .replica_count_zero;
        if (request.replica_count > constants.replicas_max) return .replica_count_max_exceeded;
        if (request.standby_count > constants.standbys_max) return .standby_count_max_exceeded;

        if (!valid_members(&request.members)) return .members_invalid;
        if (member_count(&request.members) != request.replica_count + request.standby_count) {
            return .members_count_invalid;
        }

        if (!std.mem.allEqual(u8, &request.reserved, 0)) return .reserved_field;
        if (request.result != .reserved) return .result_must_be_reserved;

        if (request.replica_count != current.replica_count) return .different_replica_count;
        if (request.standby_count != current.standby_count) return .different_standby_count;

        if (request.epoch < current.epoch) return .epoch_in_the_past;
        if (request.epoch == current.epoch) {
            return if (std.meta.eql(request.members, current.members.*))
                .configuration_applied
            else
                .configuration_conflict;
        }
        if (request.epoch - current.epoch > 1) return .epoch_in_the_future;

        assert(request.epoch == current.epoch + 1);

        assert(valid_members(current.members));
        assert(valid_members(&request.members));
        assert(member_count(current.members) == member_count(&request.members));
        // We have just asserted that the sets have no duplicates and have equal lengths,
        // so it's enough to check that current.members ⊂ request.members.
        for (current.members) |member_current| {
            if (member_current == 0) break;
            for (request.members) |member| {
                if (member == member_current) break;
            } else return .different_member_set;
        }

        if (std.meta.eql(request.members, current.members.*)) {
            return .configuration_is_no_op;
        }

        return .ok;
    }
};

/// Checkpoint interval arithmetic (the pure subset of upstream's `Checkpoint`).
pub const Checkpoint = struct {
    comptime {
        assert(constants.journal_slot_count > constants.lsm_compaction_ops);
        assert(constants.journal_slot_count % constants.lsm_compaction_ops == 0);
    }

    pub fn valid(op: u64) bool {
        // Divide by `lsm_compaction_ops` instead of `vsr_checkpoint_ops`:
        // although today in practice checkpoints are evenly spaced, the LSM layer doesn't assume
        // that. LSM allows any bar boundary to become a checkpoint which happens, e.g., in the tree
        // fuzzer.
        return op == 0 or (op + 1) % constants.lsm_compaction_ops == 0;
    }
};

comptime {
    // The vendored tree must keep the header/checksum contract byte-identical to upstream:
    // AOF files written by this build must be readable by upstream `aof debug`/`aof merge`
    // and vice versa.
    assert(@sizeOf(Header) == 256);
}

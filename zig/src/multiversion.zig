const std = @import("std");
const stdx = @import("stdx");
const assert = std.debug.assert;

pub const Release = extern struct {
    value: u32,

    comptime {
        assert(@sizeOf(Release) == 4);
        assert(@sizeOf(Release) == @sizeOf(ReleaseTriple));
        assert(stdx.no_padding(Release));
    }

    pub const zero = Release.from(.{ .major = 0, .minor = 0, .patch = 0 });
    // Minimum is used for all development builds, to distinguish them from production deployments.
    pub const minimum = Release.from(.{ .major = 0, .minor = 0, .patch = 1 });

    /// The 65535.x.x releases are reserved for cluster=0.
    /// This way, when testing multiversion binaries (either manually or with the integration tests'
    /// or Vortex's build) it isn't possible to use the test's multiversion build to upgrade a
    /// production cluster to non-production code.
    pub const development_major: u16 = std.math.maxInt(u16);

    pub fn from(release_triple: ReleaseTriple) Release {
        return std.mem.bytesAsValue(Release, std.mem.asBytes(&release_triple)).*;
    }

    pub fn parse(string: []const u8) !Release {
        return Release.from(try ReleaseTriple.parse(string));
    }

    pub fn triple(release: *const Release) ReleaseTriple {
        return std.mem.bytesAsValue(ReleaseTriple, std.mem.asBytes(release)).*;
    }

    /// Test-only release binary will only start when cluster=0.
    /// This ensures that test/development multiversion binaries can be tested by upgrading from
    /// actual production binaries, without risking accidentally upgrading a production cluster to a
    /// test/development binary.
    pub fn testing(release: *const Release) bool {
        return release.triple().major == std.math.maxInt(u16);
    }

    pub fn format(
        release: Release,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        const release_triple = release.triple();
        return writer.print("{}.{}.{}", .{
            release_triple.major,
            release_triple.minor,
            release_triple.patch,
        });
    }

    pub fn max(a: Release, b: Release) Release {
        if (a.value > b.value) {
            return a;
        } else {
            return b;
        }
    }

    pub fn less_than(_: void, a: Release, b: Release) bool {
        return switch (std.math.order(a.value, b.value)) {
            .lt => true,
            .eq => false,
            .gt => false,
        };
    }
};

pub const ReleaseTriple = extern struct {
    patch: u8,
    minor: u8,
    major: u16,

    comptime {
        assert(@sizeOf(ReleaseTriple) == 4);
        assert(stdx.no_padding(ReleaseTriple));
    }

    pub fn parse(string: []const u8) error{InvalidRelease}!ReleaseTriple {
        var parts = std.mem.splitScalar(u8, string, '.');
        const major = parts.first();
        const minor = parts.next() orelse return error.InvalidRelease;
        const patch = parts.next() orelse return error.InvalidRelease;
        if (parts.next() != null) return error.InvalidRelease;
        return .{
            .major = stdx.parse_int(u16, major, .{}) catch return error.InvalidRelease,
            .minor = stdx.parse_int(u8, minor, .{}) catch return error.InvalidRelease,
            .patch = stdx.parse_int(u8, patch, .{}) catch return error.InvalidRelease,
        };
    }
};

test "ReleaseTriple.parse" {
    const tests = [_]struct {
        string: []const u8,
        result: error{InvalidRelease}!ReleaseTriple,
    }{
        // Valid:
        .{ .string = "0.0.1", .result = .{ .major = 0, .minor = 0, .patch = 1 } },
        .{ .string = "0.1.0", .result = .{ .major = 0, .minor = 1, .patch = 0 } },
        .{ .string = "1.0.0", .result = .{ .major = 1, .minor = 0, .patch = 0 } },

        // Invalid characters:
        .{ .string = "v0.0.1", .result = error.InvalidRelease },
        .{ .string = "0.0.1v", .result = error.InvalidRelease },
        // Invalid separators:
        .{ .string = "0.0.0.1", .result = error.InvalidRelease },
        .{ .string = "0..0.1", .result = error.InvalidRelease },
        // Overflow (and near-overflow):
        .{ .string = "0.0.255", .result = .{ .major = 0, .minor = 0, .patch = 255 } },
        .{ .string = "0.0.256", .result = error.InvalidRelease },
        .{ .string = "0.255.0", .result = .{ .major = 0, .minor = 255, .patch = 0 } },
        .{ .string = "0.256.0", .result = error.InvalidRelease },
        .{ .string = "65535.0.0", .result = .{ .major = 65535, .minor = 0, .patch = 0 } },
        .{ .string = "65536.0.0", .result = error.InvalidRelease },
    };
    for (tests) |t| {
        try std.testing.expectEqualDeep(t.result, ReleaseTriple.parse(t.string));
    }
}

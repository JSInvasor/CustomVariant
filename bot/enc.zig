const std = @import("std");

// xor algorithm for encryption, but u can rewrite and use other algos (note: dont forget to rewrite the server side too)

pub fn enc(allocator: std.mem.Allocator, in: []const u8, key: u8) []const u8 {
    // +2 for separator (0x7C) and key byte
    const buf = allocator.alloc(u8, in.len + 2) catch unreachable;

    for (in, 0..) |c, i| {
        buf[i] = c ^ key;
    }

    // append separator and key to the end
    buf[in.len] = 0x7C;
    buf[in.len + 1] = key;

    return buf;
}

pub fn dec(allocator: std.mem.Allocator, in: []const u8) []const u8 {
    const buf = allocator.alloc(u8, in.len - 2) catch unreachable;

    const key = in[in.len - 1]; // get key from the end

    for (in[0 .. in.len - 2], 0..) |c, i| {
        buf[i] = c ^ key;
    }
    return buf;
}

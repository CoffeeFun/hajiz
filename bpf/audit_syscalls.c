// SPDX-License-Identifier: GPL-2.0
//
// BPF program for hajiz audit mode.
//
// Attaches to raw_tracepoint/sys_enter. Filters by target PID (set in
// config_map[0]) and counts syscalls in syscall_map.
//
// Maps:
//   config_map[0]  — u64: target TGID to trace (0 = disabled)
//   syscall_map    — hash: syscall_nr (u32) → call count (u64)

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 1);
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 512);
} syscall_map SEC(".maps");

// raw_tracepoint/sys_enter args:
//   ctx->args[0] = struct pt_regs *  (register state)
//   ctx->args[1] = long               (syscall id)
SEC("raw_tracepoint/sys_enter")
int audit_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u32 k = 0;
    __u64 *filter_pid = bpf_map_lookup_elem(&config_map, &k);
    if (!filter_pid || *filter_pid == 0)
        return 0;

    // bpf_get_current_pid_tgid: high 32 bits = TGID (process), low 32 bits = TID
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = (__u32)(pid_tgid >> 32);
    if ((__u64)tgid != *filter_pid)
        return 0;

    __u32 syscall_nr = (__u32)ctx->args[1];
    __u64 *cnt = bpf_map_lookup_elem(&syscall_map, &syscall_nr);
    if (cnt) {
        __sync_fetch_and_add(cnt, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&syscall_map, &syscall_nr, &one, BPF_ANY);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";

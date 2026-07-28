#define __TARGET_ARCH_x86
#define ESRCH 3

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

 // Share my PID with the eBPF program via a map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} loader_pid SEC(".maps");

// Must always include a license
char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/__x64_sys_kill")
int kill_enter(struct pt_regs *ctx)
{
    // Read the syscall arguments
    struct pt_regs *sys_regs = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned long di, si;
    bpf_probe_read_kernel(&di, sizeof(di), &sys_regs->di);
    bpf_probe_read_kernel(&si, sizeof(si), &sys_regs->si);
    
    pid_t pid = (pid_t)di;
    int sig = (int)si;
    
    // Read the PID to protect from the map
    __u32 key = 0;
    __u32 *blocked_pid_ptr = bpf_map_lookup_elem(&loader_pid, &key);
    if (!blocked_pid_ptr) {
        bpf_printk("Couldn't load protected PID from map!");
        return 0;
    }

    if (pid == *blocked_pid_ptr) {
        bpf_printk("Caught call to protected PID %u", *blocked_pid_ptr);
        bpf_override_return(ctx, -ESRCH);
    }

    return 0;
}
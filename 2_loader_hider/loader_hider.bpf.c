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

    bpf_printk("pid=%d sig=%d", pid, sig);

    if (pid == 30749) {
        bpf_printk("Caught call to protected PID %d", 30749);
        bpf_override_return(ctx, -ESRCH);
    }

    return 0;
}

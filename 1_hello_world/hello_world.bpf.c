#define __TARGET_ARCH_x86

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Must always include a license
char LICENSE[] SEC("license") = "GPL";

// Specify where to inject your hook
// SEC("tracepoint/syscalls/sys_enter_execve")
// int execve_enter(struct trace_event_raw_sys_enter *ctx)
// {
//     u64 pid = bpf_get_current_pid_tgid() >> 32;
    
//     char buf[256];
//     const char* filename = (const char*)ctx->args[0];
//     bpf_probe_read_user_str(buf, sizeof(buf), filename);

//     // Log to the trace_pipe
//     bpf_printk("[hello_world] PID %d: execve(%s)", pid, buf);
//     return 0;
// }

SEC("fentry/__x64_sys_execve")
int BPF_PROG(execve_enter, struct pt_regs *regs)
{
    // Get the PID of the process making the syscall
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get the first argument to the syscall (filename)
    char buf[256];
    const char* filename = (const char*)PT_REGS_PARM1(regs);
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    // Log to the trace_pipe
    bpf_printk("[hello_world] PID %d: execve(%s)", pid, buf);
    return 0;
}

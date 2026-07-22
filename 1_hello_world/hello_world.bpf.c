#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Must always include a license
char LICENSE[] SEC("license") = "GPL";

// Specify where to inject your hook
SEC("tracepoint/syscalls/sys_enter_execve")
int hello_world(void *ctx)
{
    bpf_printk("hello_world says Hello!\n");
    return 0;
}

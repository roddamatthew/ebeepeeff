# Build Requirements

```
sudo apt install clang llvm
sudo apt install libbpf-dev linux-libc-dev linux-headers-$(uname -r)
```

The `Makefile` expects a `vmlinux.h` header in the top level directory for linking against. You can export a header file for your currently running kernel's types with the following.

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

# Inspecting eBPF Programs

```
llvm-objdump -S <program>.bpf.o
```

# Running 

```
sudo ./loader.o
sudo cat /sys/kernel/tracing/trace_pipe
```


## Getting Errors?

- Demos 3 and 4 may fail if your kernel has SecureBoot. To check if this may be affecting you, run `cat /sys/kernel/security/lockdown`. If your output includes `[integrity] confidentiality` it may not work. These demos are intended to be run in a VM.
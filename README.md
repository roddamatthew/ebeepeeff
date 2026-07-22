# Build Requirements

```
sudo apt install clang llvm
sudo apt install libbpf-dev linux-libc-dev linux-headers-$(uname -r)
```

You can export a header file for your currently running kernel's types with the following:

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
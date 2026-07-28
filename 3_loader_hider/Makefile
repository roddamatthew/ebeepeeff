all: ebpf loader

ebpf: loader_hider.bpf.c
	clang -O2 -target bpf -g -c loader_hider.bpf.c -o loader_hider.bpf.o

loader: loader.c
	clang loader.c -lbpf -lelf -lz -o loader.o
	
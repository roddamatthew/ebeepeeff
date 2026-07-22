all: ebpf loader

ebpf: hello_world.bpf.c
	clang -target bpf -g -c hello_world.bpf.c -o hello_world.bpf.o

loader: loader.c
	clang loader.c -lbpf -lelf -lz -o loader.o
	
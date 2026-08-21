all: ebpf loader

ebpf: loader_protector.bpf.c
	clang -I ../ -O2 -target bpf -g -c loader_protector.bpf.c -o loader_protector.bpf.o

loader: loader.c
	clang loader.c -lbpf -lelf -lz -o loader.o
	
all: ebpf loader

ebpf: keylogger.bpf.c
	clang -I ../ -O2 -target bpf -g -c keylogger.bpf.c -o keylogger.bpf.o

loader: loader.c
	clang loader.c -lbpf -lelf -lz -o loader.o
	
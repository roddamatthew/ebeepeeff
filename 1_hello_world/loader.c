#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main(void)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;

    obj = bpf_object__open_file("hello_world.bpf.o", NULL);
    if (!obj) {
        perror("open");
        return 1;
    }

    if (bpf_object__load(obj)) {
        perror("load");
        return 1;
    }

    char *func_name = "hello_world";
    prog = bpf_object__find_program_by_name(obj, func_name);
    if (!prog) {
        printf("Couldn't find %s\n", func_name);
        return 1;
    }

    link = bpf_program__attach_tracepoint(
        prog,
        "syscalls",
        "sys_enter_execve"
    );

    if (!link) {
        printf("Failed to attach");
        return 1;
    }

    printf("Program loaded successfully... press enter to quit\n");
    getchar();
    
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

int main(void)
{
    const char *names[] = {
        "kill_enter",
    };

    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *links[ARRAY_SIZE(names)];

    obj = bpf_object__open_file("loader_protector.bpf.o", NULL);
    if (!obj) {
        perror("open");
        return 1;
    }

    if (bpf_object__load(obj)) {
        perror("load");
        return 1;
    }

    // Populate the PID map
    __u32 key = 0;
    __u32 pid = getpid();

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "loader_pid");
    bpf_map__update_elem(map, &key, sizeof(key), &pid, sizeof(pid), BPF_ANY);

    for (int i = 0; i < ARRAY_SIZE(names); i++) {
        prog = bpf_object__find_program_by_name(obj, names[i]);
        if (!prog) {
            printf("Couldn't find %s\n", names[i]);
            return 1;
        }

        links[i] = bpf_program__attach(prog);
        if (!links[i]) {
            printf("Failed to attach");
            return 1;
        }
    }

    printf("%u: Loaded.. read from /sys/kernel/tracing/trace_pipe\n", pid);
    getchar();
    
    for (int i = 0; i < ARRAY_SIZE(names); i++)
        bpf_link__destroy(links[i]);
    bpf_object__close(obj);
    return 0;
}
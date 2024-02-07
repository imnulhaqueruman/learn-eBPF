#!/usr/bin/python3
from bcc import BPF
from time import sleep

program_openat = r"""
BPF_HASH(counter_table_openat);

int hello_openat(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table_openat.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table_openat.update(&uid, &counter);
    return 0;
}
"""

program_write = r"""
BPF_HASH(counter_table_write);

int hello_write(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table_write.lookup(&uid);
    if (p != 0) {
        counter = *p;
    }
    counter++;
    counter_table_write.update(&uid, &counter);
    return 0;
}
"""

b = BPF(text=program_openat + program_write)

syscall_openat = b.get_syscall_fnname("openat")
syscall_write = b.get_syscall_fnname("write")

b.attach_kprobe(event=syscall_openat, fn_name="hello_openat")
b.attach_kprobe(event=syscall_write, fn_name="hello_write")

while True:
    sleep(2)
    s = ""
    
    # Print openat counters
    s += "openat: "
    for k, v in b["counter_table_openat"].items():
        s += f"ID {k.value}: {v.value}\t"
    
    # Print write counters
    s += "\nwrite: "
    for k, v in b["counter_table_write"].items():
        s += f"ID {k.value}: {v.value}\t"
    
    print(s)

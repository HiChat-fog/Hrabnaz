#ifndef KS_PROBES_CONTAINER_H
#define KS_PROBES_CONTAINER_H


#include "common.h"

struct container_escape_event {
    struct ks_event header;
    u32 pid;
    u32 uid;
    u32 source_ns_inum;
    u32 target_ns_inum;
    u32 cap_eff;
    u32 _pad_container1;
    char comm[16];
};

SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds, struct cred *new) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct container_escape_event *evt = KS_RESERVE(events, struct container_escape_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_CONTAINER_ESCAPE);
    evt->header.syscall_nr = 0;
    evt->header.retval = 0;
    evt->pid = pid;
    evt->uid = uid;

    evt->source_ns_inum = 0;
    evt->target_ns_inum = 0;
    evt->cap_eff = 0;
    evt->_pad_container1 = 0;

    __builtin_memcpy(evt->comm, evt->header.comm, sizeof(evt->comm));

    KS_SUBMIT(ctx, events, evt);
    return 0;
}

#endif

#ifndef KS_PROBES_SELF_PROTECT_H
#define KS_PROBES_SELF_PROTECT_H


#include "common.h"

struct ebpf_tamper_event {
    struct ks_event header;
    u32 pid;
    u32 uid;
    u32 _pad_self1;
    char prog_name[64];
    char comm[16];
    char action[16];
};

SEC("kprobe/security_bpf_prog_free")
int BPF_KPROBE(kprobe_security_bpf_prog_free, struct bpf_prog_aux *aux) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct ebpf_tamper_event *evt = KS_RESERVE(events, struct ebpf_tamper_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_EBPF_TAMPER);
    evt->header.syscall_nr = 0;
    evt->header.retval = 0;
    evt->pid = pid;
    evt->uid = uid;
    evt->_pad_self1 = 0;
    __builtin_memcpy(evt->comm, evt->header.comm, sizeof(evt->comm));

    __builtin_memcpy(evt->action, "free", 5);

#ifdef KS_NOBTF
    bpf_probe_read_str(&evt->prog_name, sizeof(evt->prog_name), (void *)aux + 8);
#else
    BPF_CORE_READ_STR_INTO(&evt->prog_name, aux, name);
#endif

    KS_SUBMIT(ctx, events, evt);
    return 0;
}

#endif

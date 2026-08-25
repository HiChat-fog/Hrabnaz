#ifndef KS_PROBES_LKM_H
#define KS_PROBES_LKM_H


#include "common.h"

struct lkm_load_event {
    struct ks_event header;
    u32 pid;
    u32 uid;
    u32 _pad_lkm1;
    char module_name[64];
    char comm[16];
};

SEC("kprobe/do_init_module")
int BPF_KPROBE(kprobe_do_init_module, struct module *mod) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct lkm_load_event *evt = KS_RESERVE(events, struct lkm_load_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_LKM_LOAD);
    evt->header.syscall_nr = 0;
    evt->header.retval = 0;
    evt->pid = pid;
    evt->uid = uid;
    evt->_pad_lkm1 = 0;
    __builtin_memcpy(evt->comm, evt->header.comm, sizeof(evt->comm));

#ifdef KS_NOBTF
    bpf_probe_read_str(&evt->module_name, sizeof(evt->module_name), (void *)mod + 16);
#else
    BPF_CORE_READ_STR_INTO(&evt->module_name, mod, name);
#endif

    KS_SUBMIT(ctx, events, evt);
    return 0;
}

#endif

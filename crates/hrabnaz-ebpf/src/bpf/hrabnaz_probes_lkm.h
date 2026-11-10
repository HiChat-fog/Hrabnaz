#ifndef HRABNAZ_PROBES_LKM_H
#define HRABNAZ_PROBES_LKM_H


#include "common.h"

struct lkm_load_event {
    struct ks_event header;
    u32 pid;
    u32 uid;
    u32 _pad_lkm1;
    char module_name[64];
    char comm[16];
};

/* struct module 里 name 的偏移在 3.10/4.x 上都是 24（state 4 + 填充 + list 16）
   ——用内嵌的 3.10 BTF 核对过 */
#define HRABNAZ_MODULE_NAME_OFF 24

static __always_inline int ks_emit_lkm_load(void *ctx, struct module *mod) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct lkm_load_event *evt = HRABNAZ_RESERVE(events, struct lkm_load_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_LKM_LOAD);
    evt->header.syscall_nr = 0;
    evt->header.retval = 0;
    evt->pid = pid;
    evt->uid = uid;
    evt->_pad_lkm1 = 0;
    __builtin_memcpy(evt->comm, evt->header.comm, sizeof(evt->comm));

    /* 先置空首位：perfbuf 路径的 HRABNAZ_RESERVE 复用 per-CPU 暂存区，
       读失败时会把上一件事的模块名带出去 */
    evt->module_name[0] = 0;
#ifdef HRABNAZ_NOBTF
    bpf_probe_read_str(&evt->module_name, sizeof(evt->module_name), (void *)mod + HRABNAZ_MODULE_NAME_OFF);
#else
    BPF_CORE_READ_STR_INTO(&evt->module_name, mod, name);
#endif

    if (evt->module_name[0] == 0) {
        HRABNAZ_DISCARD(evt);
        return 0;
    }

    HRABNAZ_SUBMIT(ctx, events, evt);
    return 0;
}

SEC("kprobe/do_init_module")
int BPF_KPROBE(kprobe_do_init_module, struct module *mod) {
    return ks_emit_lkm_load(ctx, mod);
}

/* 3.10 没有可用的 do_init_module/load_module 返回值（kretprobe tracepoint 只
   记录返回地址不记录返回值，BPF 拿到的是入口 pt_regs）——这条在 return value
   可用的内核上是 do_init_module 的回退，3.10 上它只会空转 */
SEC("kretprobe/load_module")
int BPF_KRETPROBE(kretprobe_load_module, struct module *mod) {
    unsigned long m = (unsigned long)mod;
    if (m == 0 || m >= 0xfffffffffffff000UL) return 0;
    return ks_emit_lkm_load(ctx, mod);
}

#endif

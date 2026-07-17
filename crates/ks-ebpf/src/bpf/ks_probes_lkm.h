#ifndef KS_PROBES_LKM_H
#define KS_PROBES_LKM_H

/* ── E4.2: 内核模块加载探针 ───────────────────────────────────
 * 捕获 insmod/modprobe 加载内核模块事件，记录模块名。
 * 复用 events ringbuf（与 syscall/vfs/net 共享），不新增 map。
 *
 * event_type=81（避开 1-31 syscall/vfs/net/signal、40-43 tree、50-54 flow、60-61 freq、70-72 filter、80 container）。
 *
 * struct module 在 vmlinux.h 中存在（name 字段为 char[56] 内联数组）。
 *   - CO-RE 路径（modern/legacy/ancient-BTF）：用 BPF_CORE_READ_STR_INTO 通过 BTF 重定位读字段
 *   - NOBTF 路径：硬编码 offset（3.10.0-1160 实测 struct module.name 在 offset 16，不可靠）
 *
 * do_init_module 在所有 Linux 版本存在（2.6+），kprobe attach 不会失败。
 */

#include "common.h"

struct lkm_load_event {
    struct ks_event header;
    u32 pid;
    u32 uid;
    u32 _pad_lkm1;
    char module_name[64];  /* struct module.name 是 char[56]，留 64 字节缓冲 */
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
    evt->header.syscall_nr = 0;        /* do_init_module 非 syscall */
    evt->header.retval = 0;
    evt->pid = pid;
    evt->uid = uid;
    evt->_pad_lkm1 = 0;
    __builtin_memcpy(evt->comm, evt->header.comm, sizeof(evt->comm));

    /* 读 mod->name（char[56] 内联数组，非指针）
     *   CO-RE 路径：BPF_CORE_READ_STR_INTO 用 __builtin_preserve_access_index 标记字段，
     *               clang 发射 CO-RE 重定位记录，aya 加载时按 BTF 解析偏移。
     *   NOBTF 路径：BTF.ext 已剥离，CO-RE 重定位无法应用，用硬编码 offset。
     *               3.10.0-1160.119.1.el7.x86_64 实测 struct module.name 在 offset 16
     *               （enum module_state 4B + struct list_head 16B = 20B，3.10 layout 略有差异）。
     *               ⚠️ 不同 3.10 子版本 layout 可能不同，硬编码 offset 不可靠。
     */
#ifdef KS_NOBTF
    bpf_probe_read_str(&evt->module_name, sizeof(evt->module_name), (void *)mod + 16);
#else
    BPF_CORE_READ_STR_INTO(&evt->module_name, mod, name);
#endif

    KS_SUBMIT(ctx, events, evt);
    return 0;
}

#endif // KS_PROBES_LKM_H

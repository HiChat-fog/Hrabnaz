#ifndef KS_PROBES_SELF_PROTECT_H
#define KS_PROBES_SELF_PROTECT_H

/* ── E4.3: eBPF 自身防护探针 ──────────────────────────────────
 * 检测本项目 BPF 程序被卸载/篡改，捕获 security_bpf_prog_free 调用。
 * 复用 events ringbuf（与 syscall/vfs/net 共享），不新增 map。
 *
 * event_type=82（避开 1-31 syscall/vfs/net/signal、40-43 tree、50-54 flow、60-61 freq、70-72 filter、80-81 container/lkm）。
 *
 * struct bpf_prog_aux 在 vmlinux.h 中存在（name 字段为 char[16] 内联数组，非指针）。
 *   - CO-RE 路径（modern/legacy/ancient-BTF）：BPF_CORE_READ_STR_INTO 通过 BTF 重定位
 *   - NOBTF 路径：硬编码 offset（不可靠，offset 在不同 bpf_prog_aux layout 差异巨大）
 *
 * ⚠️ security_bpf_prog_free 在 5.x+ 内核存在（LSM hook）；
 *    3.10 可能没有此函数，kprobe attach 会在运行时失败，
 *    loader 会报错但不影响其他探针 attach（aya 单探针失败可隔离）。
 *    编译期所有 tier 均可成功（kprobe 符号名只是字符串，不参与编译验证）。
 */

#include "common.h"

struct ebpf_tamper_event {
    struct ks_event header;
    u32 pid;
    u32 uid;
    u32 _pad_self1;
    char prog_name[64];   /* bpf_prog_aux.name 是 char[16]，留 64 字节缓冲 */
    char comm[16];
    char action[16];      /* "free" / "detach"（当前仅 free） */
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

    /* action = "free"（含末尾 \0，共 5 字节） */
    __builtin_memcpy(evt->action, "free", 5);

    /* 读 aux->name（char[16] 内联数组，非指针）
     *   CO-RE 路径：BPF_CORE_READ_STR_INTO 通过 BTF 重定位定位 name 字段偏移。
     *   NOBTF 路径：硬编码 offset 极不可靠（bpf_prog_aux 在不同内核 layout 差异巨大），
     *              当前用 offset 8（仅占位，3.10 上 attach 本就会失败，prog_name 读到的是脏数据）。
     *              真实 3.10 无此 hook，不会执行到此路径。
     * 简化：提交所有事件，用户态按 prog_name 前缀（kprobe_/trace_ 等）过滤本项目程序。
     */
#ifdef KS_NOBTF
    bpf_probe_read_str(&evt->prog_name, sizeof(evt->prog_name), (void *)aux + 8);
#else
    BPF_CORE_READ_STR_INTO(&evt->prog_name, aux, name);
#endif

    KS_SUBMIT(ctx, events, evt);
    return 0;
}

#endif // KS_PROBES_SELF_PROTECT_H

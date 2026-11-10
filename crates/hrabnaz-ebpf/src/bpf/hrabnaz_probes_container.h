#ifndef HRABNAZ_PROBES_CONTAINER_H
#define HRABNAZ_PROBES_CONTAINER_H


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

/*
 * 门控策略（按 tier 分层）：
 * - BTF tier (modern / legacy-with-BTF)：kprobe 在 commit_creds 入口触发，
 *   task->cred 仍是旧凭据，uid+euid 都没变就不发事件；并回填真实
 *   user_ns inum 与 cap_effective（旧实现恒 0 占位）。
 *   旧实现无条件 submit 纯噪音（所有进程、含内核线程路径）会打满 ringbuf。
 * - NOBTF tier (3.10/4.19)：不引入 bpf_get_current_task（3.10 kernel-plus
 *   不可靠），也不用 CORE 读 task->cred（offset 不可验证），只用
 *   bpf_get_current_uid_gid()（入口时仍是旧 uid）做保守门控：
 *   会漏掉仅 euid 变化（uid 不变）的场景，但能挡掉绝大多数噪音。
 */
#if defined(HRABNAZ_TIER_MODERN) || (defined(HRABNAZ_TIER_LEGACY) && !defined(HRABNAZ_NOBTF))
    #define HRABNAZ_CONTAINER_FULL 1
#endif

SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds, struct cred *new) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

#ifdef HRABNAZ_CONTAINER_FULL
    {
        u32 new_uid  = BPF_CORE_READ(new, uid.val);
        u32 new_euid = BPF_CORE_READ(new, euid.val);
        struct task_struct *tsk = (struct task_struct *)bpf_get_current_task();
        const struct cred *old = BPF_CORE_READ(tsk, cred);
        u32 old_uid  = BPF_CORE_READ(old, uid.val);
        u32 old_euid = BPF_CORE_READ(old, euid.val);
        if (old_uid == new_uid && old_euid == new_euid)
            return 0;
    }
#else
    {
#if defined(HRABNAZ_NOBTF)
        /* NOBTF: HRABNAZ_NOREAD_uid 按 cred 前缀偏移读出 u32 */
        u32 new_uid = BPF_CORE_READ(new, uid);
#else
        u32 new_uid = BPF_CORE_READ(new, uid.val);
#endif
        if (new_uid == uid)
            return 0;
    }
#endif

    struct container_escape_event *evt = HRABNAZ_RESERVE(events, struct container_escape_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_CONTAINER_ESCAPE);
    evt->header.syscall_nr = 0;
    evt->header.retval = 0;
    evt->pid = pid;
    evt->uid = uid;

#ifdef HRABNAZ_CONTAINER_FULL
    // source = 旧 user_ns 的 inum，target = 新 user_ns 的 inum（相等说明未跨越 ns）；
    // cap_eff 取新 cred 生效能力的低 32 位（cap 0-31，覆盖绝大多数能力位）
    {
        struct task_struct *tsk = (struct task_struct *)bpf_get_current_task();
        const struct cred *old = BPF_CORE_READ(tsk, cred);
        evt->source_ns_inum = BPF_CORE_READ(old, user_ns, ns.inum);
        evt->target_ns_inum = BPF_CORE_READ(new, user_ns, ns.inum);
        /* kernel_cap_t 在 6.9 前是 __u32 cap[2]、之后是 u64 val，子字段名不同，
           直接读 .val 会在老内核 BTF 上被 CO-RE 毒化。两种布局都是 8 字节且
           低 32 位同为 0-31 号能力位，故按字段锚定偏移整读 8 字节取低 32 位 */
        u64 caps = 0;
        bpf_core_read(&caps, sizeof(caps), &new->cap_effective);
        evt->cap_eff = (u32)caps;
    }
#else
    evt->source_ns_inum = 0;
    evt->target_ns_inum = 0;
    evt->cap_eff = 0;
#endif
    evt->_pad_container1 = 0;

    __builtin_memcpy(evt->comm, evt->header.comm, sizeof(evt->comm));

    HRABNAZ_SUBMIT(ctx, events, evt);
    return 0;
}

#endif

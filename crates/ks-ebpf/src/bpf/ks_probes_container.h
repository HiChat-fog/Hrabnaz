#ifndef KS_PROBES_CONTAINER_H
#define KS_PROBES_CONTAINER_H

/* ── E4.1: 容器逃逸探针 ──────────────────────────────────────
 * 检测容器内进程获取宿主命名空间权限（commit_creds 调用）。
 * 复用 events ringbuf（与 syscall/vfs/net 共享），不新增 map。
 *
 * 简化逻辑：仅记录 commit_creds 调用元数据（pid/uid/comm），
 * namespace inum / cap_effective 留 0（NOBTF 路径下读取 mnt_ns 链不可靠），
 * 由用户态规则按 uid 变化（如容器进程突然获得 root）判断逃逸。
 *
 * event_type=80（避开 1-31 syscall/vfs/net/signal、40-43 tree、50-54 flow、60-61 freq、70-72 filter）。
 */

#include "common.h"

/* 容器逃逸事件结构体（自包含，不污染 common.h） */
struct container_escape_event {
    struct ks_event header;
    u32 pid;
    u32 uid;
    u32 source_ns_inum;   /* task 自身 mnt_ns inum（NOBTF 路径下为 0） */
    u32 target_ns_inum;   /* 父进程 mnt_ns inum（差异表示逃逸） */
    u32 cap_eff;          /* cap_effective 当前值（NOBTF 路径下为 0） */
    u32 _pad_container1;
    char comm[16];        /* 冗余字段，与 header.comm 一致，便于用户态直接解析 */
};

/* commit_creds: 进程切换 cred 时触发（setuid/setgid/sudo/setns 等）。
 *
 * 命名空间逃逸典型场景：
 *   - 容器内进程调用 setns(CLONE_NEWNS) 切换到宿主 mnt_ns
 *   - 容器内特权进程通过 /proc/1/root/pivot_root 逃逸
 *   - 容器内 CAP_SYS_ADMIN + mount 嫁接
 * 这些路径大多最终走 commit_creds 或 override_creds。
 *
 * 注意：commit_creds 在所有 Linux 版本存在（2.6+），kprobe attach 不会失败。
 */
SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe_commit_creds, struct cred *new) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    struct container_escape_event *evt = KS_RESERVE(events, struct container_escape_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_CONTAINER_ESCAPE);
    evt->header.syscall_nr = 0;        /* commit_creds 非 syscall，留 0 */
    evt->header.retval = 0;
    evt->pid = pid;
    evt->uid = uid;

    /* TODO: 读 task->nsproxy->mnt_ns->ns.inum 对比父进程。
     *   CO-RE 路径（modern/legacy/ancient-BTF）：
     *     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
     *     struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
     *     struct mnt_namespace *mnt = BPF_CORE_READ(nsp, mnt_ns);
     *     u32 src_inum = BPF_CORE_READ(mnt, ns.inum);
     *   NOBTF 路径：硬编码 offset 链过长且不可靠，暂跳过。
     * 当前简化：source/target_ns_inum 留 0，用户态规则按 uid 变化判断。 */
    evt->source_ns_inum = 0;
    evt->target_ns_inum = 0;
    evt->cap_eff = 0;
    evt->_pad_container1 = 0;

    /* comm 与 header.comm 一致（fill_header 已填），冗余拷贝便于用户态单字段解析 */
    __builtin_memcpy(evt->comm, evt->header.comm, sizeof(evt->comm));

    KS_SUBMIT(ctx, events, evt);
    return 0;
}

#endif // KS_PROBES_CONTAINER_H

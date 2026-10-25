#ifndef KS_EVENTS_H
#define KS_EVENTS_H

/* ── 事件契约：探针发往用户态的结构与发射辅助 ──
   布局与用户态 aggregator 的解码结构一一对应（改这里必须同步 Rust 侧），
   经 KS_EVENT_MAP（ringbuf/perfbuf）按 base 层的 KS_RESERVE/SUBMIT 发射。 */

struct ks_event {
    u32 event_type;
    u32 _pad1;
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 uid;
    u32 ppid;
    u8  comm[16];
    i32 syscall_nr;
    u32 _pad2;
    i64 retval;
};

struct exec_event {
    struct ks_event header;
    u8  filename[256];
    u8  args[512];
};

struct file_event {
    struct ks_event header;
    u8  filename[256];
    u64 bytes;
    i32 fd;
    i32 flags;
};

struct net_event {
    struct ks_event header;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
    u8  family;
    u8  saddr6[16];
    u8  daddr6[16];
    u8  _pad3[2];
};

struct signal_event {
    struct ks_event header;
    u32 target_pid;
    i32 signal;
};

static __always_inline void fill_header(struct ks_event *hdr, u32 event_type) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid  = bpf_get_current_uid_gid();

    hdr->event_type  = event_type;
    hdr->timestamp_ns = bpf_ktime_get_ns();
    hdr->pid         = pid_tgid >> 32;
    hdr->tid         = (u32)pid_tgid;
    hdr->uid         = (u32)uid_gid;
    hdr->ppid        = 0;
    hdr->syscall_nr  = 0;
    hdr->retval      = 0;
    hdr->_pad1       = 0;
    hdr->_pad2       = 0;

    KS_WRITE_COMM(&hdr->comm, sizeof(hdr->comm));
}

static __always_inline int read_user_str(char *dst, int dst_len, const char __user *src) {
    return bpf_probe_read_user_str(dst, dst_len, src);
}

static __always_inline int read_kernel_str(char *dst, int dst_len, const char *src) {
    return bpf_probe_read_kernel_str(dst, dst_len, src);
}

#endif

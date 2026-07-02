#ifndef KS_COMMON_H
#define KS_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef __user
#define __user
#endif

typedef __s32 i32;
typedef __s64 i64;

/* ── Tier 条件编译（由 build.rs 注入 -DKS_TIER_xxx）───────── */
#if defined(KS_TIER_MODERN)
    #define KS_RINGBUF   1
    #define KS_LRU_HASH  1
#elif defined(KS_TIER_LEGACY)
    #define KS_RINGBUF   0
    #define KS_LRU_HASH  1
#elif defined(KS_TIER_ANCIENT)
    #define KS_RINGBUF   0
    #define KS_LRU_HASH  0
#else
    /* 默认 modern tier */
    #define KS_RINGBUF   1
    #define KS_LRU_HASH  1
#endif

/* ── 事件 Map 声明宏（ringbuf vs perf_event_array）────────── */
#if KS_RINGBUF
    #define KS_EVENT_MAP(name, size) \
        struct { \
            __uint(type, BPF_MAP_TYPE_RINGBUF); \
            __uint(max_entries, size); \
        } name SEC(".maps")
#else
    #define KS_EVENT_MAP(name, size) \
        struct { \
            __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
            __uint(max_entries, 0); \
            __type(key, i32); \
            __type(value, u32); \
        } name SEC(".maps")
#endif

/* ── 事件提交宏（ringbuf 路径已实现，perfbuf 路径 Phase B 实现）── */
#if KS_RINGBUF
    #define KS_RESERVE(buf, type) ((type *)bpf_ringbuf_reserve(&(buf), sizeof(type), 0))
    #define KS_SUBMIT(evt)        bpf_ringbuf_submit((evt), 0)
#else
    #error "perfbuf 路径尚未实现，请在 Phase B 中完成 KS_RESERVE/KS_SUBMIT 的 perfbuf 分支"
#endif

/* ── 事件类型常量 ───────────────────────────── */
#define EVENT_UNKNOWN       0
#define EVENT_PROCESS_EXEC  1
#define EVENT_PROCESS_EXIT  2
#define EVENT_PROCESS_CLONE 3
#define EVENT_FILE_OPEN     10
#define EVENT_FILE_READ     11
#define EVENT_FILE_WRITE    12
#define EVENT_FILE_DELETE   13
#define EVENT_FILE_RENAME   14
#define EVENT_FILE_CHMOD    15
#define EVENT_NET_CONNECT   20
#define EVENT_NET_ACCEPT    21
#define EVENT_NET_SEND      22
#define EVENT_NET_RECV      23
#define EVENT_NET_DNS       24
#define EVENT_PROC_PTRACE   30
#define EVENT_PROC_SIGNAL   31

/* ── 共享 BPF Maps ────────────────────────── */

/* 推理配置 / 风险分 / IP白名单 / 网络连接历史 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, u32);
    __type(value, u32);
} infer_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, u32);
} risk_scores SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, u32);
    __type(value, u8);
} ip_whitelist SEC(".maps");

struct net_conn_key {
    u32 pid; u32 daddr; u16 dport; u8 proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct net_conn_key);
    __type(value, u64);
} net_conn_history SEC(".maps");

/* 行为频率计数器（freq_counter / smart_filter 共享） */
#define FREQ_ANOMALY_RANSOMWARE  (1 << 0)
#define FREQ_ANOMALY_PORT_SCAN   (1 << 1)
#define FREQ_ANOMALY_DNS_TUNNEL  (1 << 2)
#define FREQ_ANOMALY_BRUTE_FORCE (1 << 3)
#define FREQ_ANOMALY_INJECTION   (1 << 4)

struct freq_counter {
    u32 syscall_count_60s, file_op_count_60s, net_op_count_60s;
    u32 dns_op_count_60s, ptrace_count_60s, signal_count_60s;
    u64 last_update_ns, window_start_ns;
    u32 anomaly_flags, _pad_freq1;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct freq_counter);
} freq_counters SEC(".maps");

/* ── 推理引擎 ──────────────────────────────── */

enum infer_config_key {
    CFG_RISK_THRESHOLD      = 0,
    CFG_PORT_SCAN_THRESHOLD = 1,
    CFG_TIME_WINDOW_NS      = 2,
    CFG_MAX_NEW_FILES       = 3,
    CFG_NEW_FILE_WINDOW_NS  = 4,
};

static __always_inline u32 get_config(u32 key, u32 default_val) {
    u32 *val = bpf_map_lookup_elem(&infer_config, &key);
    return val ? *val : default_val;
}

static __always_inline u32 get_risk(u32 pid) {
    u32 *score = bpf_map_lookup_elem(&risk_scores, &pid);
    return score ? *score : 0;
}

static __always_inline void add_risk(u32 pid, u32 delta) {
    u32 key = pid;
    u32 *score = bpf_map_lookup_elem(&risk_scores, &key);
    u32 new_score;
    if (score) {
        new_score = *score + delta;
        if (new_score > 100) new_score = 100;
        *score = new_score;
    } else {
        new_score = delta;
        bpf_map_update_elem(&risk_scores, &key, &new_score, BPF_ANY);
    }
}

static __always_inline int infer_sensitive_file(const char *filename, u32 pid) {
    if (!filename) return 0;
    if (filename[0] == '/' && filename[1] == 'e' && filename[2] == 't' &&
        filename[3] == 'c' && filename[4] == '/' && filename[5] == 's') {
        add_risk(pid, 40); return 1;
    }
    if (filename[0] == '/' && filename[1] == 'r' && filename[2] == 'o' &&
        filename[3] == 'o' && filename[4] == 't') {
        add_risk(pid, 30); return 1;
    }
    if (filename[0] == '/' && filename[1] == 'p' && filename[2] == 'r' &&
        filename[3] == 'o' && filename[4] == 'c') {
        add_risk(pid, 15); return 0;
    }
    return 0;
}

static __always_inline int infer_suspicious_net(u32 pid, u32 daddr, u16 dport, u8 proto) {
    u8 *whitelisted = bpf_map_lookup_elem(&ip_whitelist, &daddr);
    if (whitelisted && *whitelisted == 1) return 0;

    if (dport == 4444 || dport == 1337 || dport == 31337 ||
        dport == 5555 || dport == 6666 || dport == 6667 ||
        dport == 9999 || dport == 12345 || dport == 23456) {
        add_risk(pid, 50); return 1;
    }

    if (dport > 1024 && dport != 8080 && dport != 8443 &&
        dport != 3306 && dport != 5432 && dport != 6379 &&
        dport != 27017 && dport != 33060)
        add_risk(pid, 10);

    struct net_conn_key key = {.pid=pid, .daddr=daddr, .dport=dport, .proto=proto};
    u64 now = bpf_ktime_get_ns();
    u64 *prev = bpf_map_lookup_elem(&net_conn_history, &key);
    u64 window = 60000000000ULL; /* 60s 纳秒 */

    if (prev && now - *prev < window)
        add_risk(pid, 5);
    bpf_map_update_elem(&net_conn_history, &key, &now, BPF_ANY);
    return 0;
}

static __always_inline void infer_bulk_file_ops(u32 pid, u32 event_type) {
    if (event_type != EVENT_FILE_WRITE && event_type != EVENT_FILE_DELETE &&
        event_type != EVENT_FILE_RENAME) return;
    add_risk(pid, 2);
}

static __always_inline int infer_process_injection(u32 pid, u32 target_pid, u32 event_type) {
    if (event_type == EVENT_PROC_PTRACE) {
        add_risk(pid, 35); return 1;
    }
    if (event_type == EVENT_PROC_SIGNAL) {
        add_risk(pid, 20); return 1;
    }
    return 0;
}

static __always_inline int infer_event(u32 pid, u32 event_type, const char *filename,
                                       u32 daddr, u16 dport, u8 proto, u32 target_pid) {
    u32 risk = get_risk(pid);
    u32 threshold = get_config(CFG_RISK_THRESHOLD, 70);
    int alert = 0;

    switch (event_type) {
    case EVENT_FILE_OPEN:
    case EVENT_FILE_READ:
        if (filename) alert = infer_sensitive_file(filename, pid);
        break;
    case EVENT_FILE_WRITE:
    case EVENT_FILE_DELETE:
        infer_bulk_file_ops(pid, event_type);
        if (filename) alert = infer_sensitive_file(filename, pid);
        break;
    case EVENT_NET_CONNECT:
    case EVENT_NET_SEND:
        alert = infer_suspicious_net(pid, daddr, dport, proto);
        break;
    case EVENT_PROC_PTRACE:
    case EVENT_PROC_SIGNAL:
        alert = infer_process_injection(pid, target_pid, event_type);
        break;
    default:
        break;
    }

    risk = get_risk(pid);
    if (risk >= threshold) return 2;
    if (alert) return 1;
    return 0;
}

/* ── 频率计数辅助函数 ───────────────────── */

static __always_inline void update_freq_counter(u32 pid, u32 event_type) {
    struct freq_counter *fc = bpf_map_lookup_elem(&freq_counters, &pid);
    u64 now = bpf_ktime_get_ns();
    u64 window_ns = 60000000000ULL; /* 60s */

    if (!fc) {
        struct freq_counter new_fc = {};
        new_fc.window_start_ns = now;
        new_fc.last_update_ns = now;
        if (event_type >= 1 && event_type <= 9)
            new_fc.syscall_count_60s = 1;
        else if (event_type >= 10 && event_type <= 19)
            new_fc.file_op_count_60s = 1;
        else if (event_type >= 20 && event_type <= 29)
            new_fc.net_op_count_60s = 1;
        else if (event_type >= 30 && event_type <= 39)
            { new_fc.ptrace_count_60s = 1; new_fc.signal_count_60s = 1; }
        bpf_map_update_elem(&freq_counters, &pid, &new_fc, BPF_ANY);
        return;
    }

    if (now - fc->window_start_ns > window_ns)
        fc->window_start_ns = now;

    fc->last_update_ns = now;
    if (event_type >= 1 && event_type <= 9)
        fc->syscall_count_60s++;
    else if (event_type >= 10 && event_type <= 19)
        fc->file_op_count_60s++;
    else if (event_type >= 20 && event_type <= 29)
        fc->net_op_count_60s++;
    else if (event_type == EVENT_NET_DNS)
        fc->dns_op_count_60s++;
    else if (event_type == EVENT_PROC_PTRACE)
        fc->ptrace_count_60s++;
    else if (event_type == EVENT_PROC_SIGNAL)
        fc->signal_count_60s++;
}

/* ── 事件结构体 ────────────────────────────── */

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

    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

static __always_inline int read_user_str(char *dst, int dst_len, const char __user *src) {
    return bpf_probe_read_user_str(dst, dst_len, src);
}

static __always_inline int read_kernel_str(char *dst, int dst_len, const char *src) {
    return bpf_probe_read_kernel_str(dst, dst_len, src);
}

#endif // KS_COMMON_H
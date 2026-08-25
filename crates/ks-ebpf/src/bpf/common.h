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
    #define KS_RINGBUF   1
    #define KS_LRU_HASH  1
#endif

#if defined(KS_TIER_ANCIENT) || (defined(KS_TIER_LEGACY) && defined(KS_NOBTF))
    #define bpf_probe_read_kernel       bpf_probe_read
    #define bpf_probe_read_kernel_str   bpf_probe_read_str
    #define bpf_probe_read_user         bpf_probe_read
    #define bpf_probe_read_user_str     bpf_probe_read_str
#endif

#ifdef KS_NOBTF
    #undef BPF_CORE_READ

    #define KS_OFF_SOCK_COMMON         0
    #define KS_OFF_PATH_DENTRY         8
    #define KS_OFF_DENTRY_DNAME_NAME   40
    #define KS_OFF_FILE_FPATH          16
    #define KS_OFF_SIN6_PORT           2

    #if defined(KS_TIER_LEGACY)
        #define KS_OFF_INET_SADDR          728
        #define KS_OFF_INET_SPORT          736
    #elif defined(KS_TIER_ANCIENT)
        #define KS_OFF_INET_SADDR          776
        #define KS_OFF_INET_SPORT          784
    #else
        #error "KS_NOBTF 需要 KS_TIER_LEGACY 或 KS_TIER_ANCIENT 之一确定 inet offset"
    #endif

    #define BPF_CORE_READ(ptr, field) KS_NOREAD_##field(ptr)

    #define KS_NOREAD_inet_saddr(ptr)   ({ u32 _v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_INET_SADDR); _v; })
    #define KS_NOREAD_inet_sport(ptr)   ({ u16 _v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_INET_SPORT); _v; })
    #define KS_NOREAD___sk_common(ptr)  ({ struct sock_common _v={}; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_SOCK_COMMON); _v; })
    #define KS_NOREAD_dentry(ptr)       ({ struct dentry *_v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_PATH_DENTRY); _v; })
    #define KS_NOREAD_f_path(ptr)       ({ struct path _v={}; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_FILE_FPATH); _v; })
    #define KS_NOREAD_sin6_port(ptr)    ({ u16 _v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_SIN6_PORT); _v; })

    #define KS_READ_DNAME(ptr) ({ const char *_v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_DENTRY_DNAME_NAME); _v; })
#else
    #define KS_READ_DNAME(ptr) BPF_CORE_READ(ptr, d_name.name)
#endif

#define KS_D_PATH(buf, buf_len, path_ptr) ({ \
    struct dentry *_d = BPF_CORE_READ((path_ptr), dentry); \
    const char *_n = KS_READ_DNAME(_d); \
    bpf_probe_read_kernel_str((char *)(buf), (buf_len), _n); \
})

#if KS_LRU_HASH
    #define KS_LRU_HASH_MAP(name, key_type, value_type, cap) \
        struct { \
            __uint(type, BPF_MAP_TYPE_LRU_HASH); \
            __type(key, key_type); \
            __type(value, value_type); \
            __uint(max_entries, cap); \
        } name SEC(".maps")
#else
    #define KS_LRU_HASH_MAP(name, key_type, value_type, cap) \
        struct { \
            __uint(type, BPF_MAP_TYPE_HASH); \
            __type(key, key_type); \
            __type(value, value_type); \
            __uint(max_entries, cap); \
        } name SEC(".maps")
#endif

#if KS_LRU_HASH
    #define KS_PERCPU_ARRAY_MAP(name, value_type) \
        struct { \
            __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
            __uint(max_entries, 1); \
            __type(key, u32); \
            __type(value, value_type); \
        } name SEC(".maps")
    #define KS_PERCPU_KEY() ((u32)0)
#else
    #define KS_PERCPU_ARRAY_MAP(name, value_type) \
        struct { \
            __uint(type, BPF_MAP_TYPE_ARRAY); \
            __uint(max_entries, 256); \
            __type(key, u32); \
            __type(value, value_type); \
        } name SEC(".maps")
    #define KS_PERCPU_KEY() ((u32)bpf_get_smp_processor_id())
#endif

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
            __uint(max_entries, 256); \
            __type(key, i32); \
            __type(value, u32); \
        } name SEC(".maps")
#endif

#if KS_RINGBUF
    #define KS_RESERVE(buf, type) ((type *)bpf_ringbuf_reserve(&(buf), sizeof(type), 0))
    #define KS_SUBMIT(ctx, buf, evt) bpf_ringbuf_submit((evt), 0)
    #define KS_DISCARD(evt) bpf_ringbuf_discard((evt), 0)
#else
    KS_PERCPU_ARRAY_MAP(ks_scratch, u8[1024]);

    #define KS_RESERVE(buf, type) ({ \
        u32 _k = KS_PERCPU_KEY(); \
        (type *)bpf_map_lookup_elem(&ks_scratch, &_k); \
    })
    #define KS_SUBMIT(ctx, buf, evt) \
        bpf_perf_event_output((ctx), &(buf), BPF_F_CURRENT_CPU, (evt), sizeof(*(evt)))
    #define KS_DISCARD(evt) ((void)(evt))
#endif

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

#define EVENT_CONTAINER_ESCAPE 80
#define EVENT_LKM_LOAD         81
#define EVENT_EBPF_TAMPER      82


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, u32);
    __type(value, u32);
} infer_config SEC(".maps");

struct block_key { u32 pid; u32 _pad_blk; };
struct block_value {
    u64 expire_ns;
    u8  reason;
    u8  _pad_bv[7];
};

KS_LRU_HASH_MAP(block_decisions, struct block_key, struct block_value, 4096);

KS_LRU_HASH_MAP(protected_pids, u32, u8, 256);

struct comm_key { char comm[16]; };
KS_LRU_HASH_MAP(protected_comms, struct comm_key, u8, 64);

#define KS_EXE_PATH_LEN 256
struct process_node {
    u32 pid; u32 ppid;
    u8  comm[16];
    u8  exe_path[KS_EXE_PATH_LEN];
    u32 flags;
    u32 risk_score;
    u64 create_time;
    u64 exit_time;
    u32 _pad_node1, _pad_node2;
};
KS_LRU_HASH_MAP(process_tree, u32, struct process_node, 65536);

#if KS_RINGBUF
static __always_inline int ks_current_protected(void) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u8 *p = bpf_map_lookup_elem(&protected_pids, &tgid);
    return p && *p == 1;
}

static __always_inline int ks_comm_protected(void) {
    struct comm_key ck = {};
    bpf_get_current_comm(&ck.comm, sizeof(ck.comm));
    u8 *p = bpf_map_lookup_elem(&protected_comms, &ck);
    return p && *p == 1;
}

static __always_inline int ks_exe_path_suspicious(void);

static __always_inline int ks_check_block(u32 pid) {
    struct block_key bk = { .pid = pid, ._pad_blk = 0 };
    struct block_value *bv = bpf_map_lookup_elem(&block_decisions, &bk);
    if (!bv) return 0;
    if (bv->expire_ns == 0 || bpf_ktime_get_ns() < bv->expire_ns) {
        if (!ks_current_protected())
            bpf_send_signal(9);
        return 1;
    }
    return 0;
}

static __always_inline int ks_exe_path_suspicious(void) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    struct process_node *node = bpf_map_lookup_elem(&process_tree, &tgid);
    if (!node) return 0;
    char c0 = node->exe_path[0], c1 = node->exe_path[1], c2 = node->exe_path[2], c3 = node->exe_path[3];
    if (c0=='/' && c1=='t' && c2=='m' && c3=='p') return 1;
    if (c0=='/' && c1=='d' && c2=='e' && c3=='v') {
        char c4 = node->exe_path[4], c5 = node->exe_path[5], c6 = node->exe_path[6], c7 = node->exe_path[7];
        if (c4=='/' && c5=='s' && c6=='h' && c7=='m') return 1;
    }
    if (c0=='/' && c1=='v' && c2=='a' && c3=='r') {
        char c4 = node->exe_path[4], c5 = node->exe_path[5], c6 = node->exe_path[6], c7 = node->exe_path[7];
        if (c4=='/' && c5=='t' && c6=='m' && c7=='p') return 1;
    }
    return 0;
}

#define KS_MAYBE_BLOCK(pid, verdict) do { \
    if (get_config(CFG_ENFORCE_MODE, 0) == 1 && (verdict) == 2) { \
        u32 _warmup = get_config(CFG_ENFORCE_WARMUP_UNTIL_SEC, 0); \
        u32 _kill_thr = get_config(CFG_ENFORCE_KILL_THRESHOLD, 70); \
        u64 _now = bpf_ktime_get_ns(); \
        u32 _now_sec = (u32)(_now / 1000000000ULL); \
        int _warmup_ok = (_warmup == 0 || _now_sec >= _warmup); \
        u32 _risk = get_risk(pid); \
 \
        int _exempt = ks_current_protected() || \
            (ks_comm_protected() && !ks_exe_path_suspicious()); \
        if (_warmup_ok && _risk >= _kill_thr && !_exempt) \
            bpf_send_signal(9); \
    } \
    ks_check_block((pid)); \
} while (0)
#else
static __always_inline int ks_check_block(u32 pid) {
    struct block_key bk = { .pid = pid, ._pad_blk = 0 };
    struct block_value *bv = bpf_map_lookup_elem(&block_decisions, &bk);
    if (!bv) return 0;
    if (bv->expire_ns == 0 || bpf_ktime_get_ns() < bv->expire_ns) {
        return 1;
    }
    return 0;
}

#define KS_MAYBE_BLOCK(pid, verdict) do { \
    (void)(verdict); \
    ks_check_block((pid)); \
} while (0)
#endif

KS_LRU_HASH_MAP(risk_scores, u32, u32, 4096);

KS_LRU_HASH_MAP(ip_whitelist, u32, u8, 256);

struct net_conn_key {
    u32 pid; u32 daddr; u16 dport; u8 proto;
};

KS_LRU_HASH_MAP(net_conn_history, struct net_conn_key, u64, 8192);

#define FREQ_ANOMALY_RANSOMWARE  (1 << 0)
#define FREQ_ANOMALY_PORT_SCAN   (1 << 1)
#define FREQ_ANOMALY_DNS_TUNNEL  (1 << 2)
#define FREQ_ANOMALY_BRUTE_FORCE (1 << 3)
#define FREQ_ANOMALY_INJECTION   (1 << 4)
#define FREQ_REPORTED            (1 << 5)

struct freq_counter {
    u32 syscall_count_60s, file_op_count_60s, net_op_count_60s;
    u32 dns_op_count_60s, ptrace_count_60s, signal_count_60s;
    u64 last_update_ns, window_start_ns;
    u32 anomaly_flags, _pad_freq1;
};

KS_LRU_HASH_MAP(freq_counters, u32, struct freq_counter, 4096);


enum infer_config_key {
    CFG_RISK_THRESHOLD      = 0,
    CFG_PORT_SCAN_THRESHOLD = 1,
    CFG_TIME_WINDOW_NS      = 2,
    CFG_MAX_NEW_FILES       = 3,
    CFG_NEW_FILE_WINDOW_NS  = 4,
    CFG_ENFORCE_MODE        = 5,
    CFG_ENFORCE_WARMUP_UNTIL_SEC = 6,
    CFG_ENFORCE_KILL_THRESHOLD   = 7,
};

static __always_inline u32 get_config(u32 key, u32 default_val) {
    switch (key) {
    case CFG_RISK_THRESHOLD:      return 70;
    case CFG_PORT_SCAN_THRESHOLD: return 20;
    case CFG_TIME_WINDOW_NS:      return 30;
    case CFG_MAX_NEW_FILES:       return 100;
    case CFG_NEW_FILE_WINDOW_NS:  return 30;
    default: break;
    }
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
    if (filename[0]=='/' && filename[1]=='e' && filename[2]=='t' &&
        filename[3]=='c' && filename[4]=='/' && filename[5]=='s' &&
        filename[6]=='h' && filename[7]=='a' && filename[8]=='d' &&
        filename[9]=='o' && filename[10]=='w') {
        add_risk(pid, 40); return 1;
    }
    if (filename[0]=='/' && filename[1]=='e' && filename[2]=='t' &&
        filename[3]=='c' && filename[4]=='/' && filename[5]=='g' &&
        filename[6]=='s' && filename[7]=='h' && filename[8]=='a' &&
        filename[9]=='d' && filename[10]=='o' && filename[11]=='w') {
        add_risk(pid, 35); return 1;
    }
    if (filename[0]=='/' && filename[1]=='e' && filename[2]=='t' &&
        filename[3]=='c' && filename[4]=='/' && filename[5]=='s' &&
        filename[6]=='u' && filename[7]=='d' && filename[8]=='o' &&
        filename[9]=='e' && filename[10]=='r' && filename[11]=='s') {
        add_risk(pid, 40); return 1;
    }
    if (filename[0]=='/' && filename[1]=='r' && filename[2]=='o' &&
        filename[3]=='o' && filename[4]=='t' && filename[5]=='/' &&
        filename[6]=='.' && filename[7]=='s' && filename[8]=='s' &&
        filename[9]=='h') {
        add_risk(pid, 30); return 1;
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

    struct net_conn_key key = {};
    key.pid = pid; key.daddr = daddr; key.dport = dport; key.proto = proto;
    u64 now = bpf_ktime_get_ns();
    u64 *prev = bpf_map_lookup_elem(&net_conn_history, &key);
    u64 window = 60000000000ULL;

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


static __always_inline void update_freq_counter(u32 pid, u32 event_type) {
    struct freq_counter *fc = bpf_map_lookup_elem(&freq_counters, &pid);
    u64 now = bpf_ktime_get_ns();
    u64 window_ns = 60000000000ULL;

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

#endif

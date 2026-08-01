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

/* ── C1: Ancient/Legacy-NOBTF tier shim — bpf_probe_read_kernel 系列回退 ──
 * 3.10 与 4.19 均无 bpf_probe_read_kernel / bpf_probe_read_kernel_str helper（5.5+ 引入），
 * 回退到 bpf_probe_read / bpf_probe_read_str（语义等价）。
 * BPF_CORE_READ 内部调用 bpf_probe_read_kernel，经此 shim 自动重定向。
 *
 * C0: 同时回退 bpf_probe_read_user / bpf_probe_read_user_str。
 *      这两个 helper 同为 5.5+ 引入（vmlinux.h 编号 112/114），
 *      ks_probes_syscall.h 中 trace_sys_exit 探针主动调用。
 *      bpf_probe_read 对 __user 指针也能 fault-in 用户页，语义等价。
 *
 * Phase F: 4.19 无 BTF（legacy_nobtf）同样需要此 shim——4.19 原版内核无 5.5+ helper。
 */
#if defined(KS_TIER_ANCIENT) || (defined(KS_TIER_LEGACY) && defined(KS_NOBTF))
    #define bpf_probe_read_kernel       bpf_probe_read
    #define bpf_probe_read_kernel_str   bpf_probe_read_str
    #define bpf_probe_read_user         bpf_probe_read
    #define bpf_probe_read_user_str     bpf_probe_read_str
#endif

/* ── NOBTF: 无 BTF 环境下的 BPF_CORE_READ 替代 ──
 * 3.10.0-1160 stock 内核有完整 eBPF 支持（bpf syscall + helpers + JIT），
 * 但无 BTF（CONFIG_DEBUG_INFO_BTF 未启用）。
 * BPF_CORE_READ 依赖 .BTF.ext 重定位，无 BTF 时加载失败。
 *
 * NOBTF 方案：用 bpf_probe_read + 硬编码 offset 替代 BPF_CORE_READ。
 * Offset 通过 kernel module 在 3.10.0-1160.119.1.el7.x86_64 上实测获取。
 *
 * BPF_CORE_READ(ptr, field) → KS_NOREAD_##field(ptr) 分发
 * 注意：d_name.name 含点号无法 token-paste，改用 KS_READ_DNAME(ptr)
 */
#ifdef KS_NOBTF
    #undef BPF_CORE_READ

    /* 跨版本稳定的 offset（4.19 与 3.10 一致） */
    #define KS_OFF_SOCK_COMMON         0
    #define KS_OFF_PATH_DENTRY         8
    #define KS_OFF_DENTRY_DNAME_NAME   40
    #define KS_OFF_FILE_FPATH          16
    #define KS_OFF_SIN6_PORT           2

    /* inet_saddr/inet_sport 依赖 struct sock 布局，跨内核版本变化，按 tier 区分 */
    #if defined(KS_TIER_LEGACY)
        /* 4.19 实测 offset（pahole on 4.19.0-20-dbg vmlinux: inet_sock.inet_saddr=728, inet_sport=736） */
        #define KS_OFF_INET_SADDR          728
        #define KS_OFF_INET_SPORT          736
    #elif defined(KS_TIER_ANCIENT)
        /* 3.10.0-1160.119.1.el7.x86_64 实测 offset */
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
    /* 非 NOBTF：走标准 BPF_CORE_READ CO-RE 重定位 */
    #define KS_READ_DNAME(ptr) BPF_CORE_READ(ptr, d_name.name)
#endif

/* ── C2: KS_D_PATH 宏 — 文件路径读取 ──
 * 所有 tier 统一用手动 dentry 遍历（bpf_d_path 仅允许 tracing/LSM 程序使用，
 * kprobe 程序不能用）。Ancient tier 依赖 BTF backport 使 BPF_CORE_READ 可用。
 * 签名：KS_D_PATH(buf, buf_len, path_ptr)  返回 < 0 失败
 */
#define KS_D_PATH(buf, buf_len, path_ptr) ({ \
    struct dentry *_d = BPF_CORE_READ((path_ptr), dentry); \
    const char *_n = KS_READ_DNAME(_d); \
    bpf_probe_read_kernel_str((char *)(buf), (buf_len), _n); \
})

/* ── C3: KS_LRU_HASH_MAP 宏 — LRU_HASH 声明兼容 ──
 * Modern/Legacy: BPF_MAP_TYPE_LRU_HASH（自动 LRU 淘汰）
 * Ancient: BPF_MAP_TYPE_HASH（3.10 无 LRU_HASH，HASH 是唯一选项）
 * 签名：KS_LRU_HASH_MAP(name, key_type, value_type, max_entries)
 */
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

/* ── C5: KS_PERCPU_ARRAY_MAP 宏 — PERCPU_ARRAY 声明兼容 ──
 * Modern/Legacy: BPF_MAP_TYPE_PERCPU_ARRAY（4.6+，per-CPU 无锁）
 * Ancient: BPF_MAP_TYPE_ARRAY + bpf_get_smp_processor_id() 作 key 模拟 per-CPU
 *          （3.10 无 PERCPU_ARRAY，回退到普通 ARRAY + CPU 索引）
 * 签名：KS_PERCPU_ARRAY_MAP(name, value_type)
 *       配套 KS_PERCPU_KEY() 取当前 CPU 的 key
 * 注意：Ancient 路径要求 ARRAY 容量 >= NR_CPUS（设 256，覆盖典型服务器）
 */
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

/* ── 事件 Map 声明宏（ringbuf vs perf_event_array）────────── */
#if KS_RINGBUF
    #define KS_EVENT_MAP(name, size) \
        struct { \
            __uint(type, BPF_MAP_TYPE_RINGBUF); \
            __uint(max_entries, size); \
        } name SEC(".maps")
#else
    /* PERF_EVENT_ARRAY: max_entries=0 是 4.6+ 特性，3.10 不支持。
     * 设 256 覆盖典型服务器 NR_CPUS，aya 按 CPU 索引写入。 */
    #define KS_EVENT_MAP(name, size) \
        struct { \
            __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
            __uint(max_entries, 256); \
            __type(key, i32); \
            __type(value, u32); \
        } name SEC(".maps")
#endif

/* ── 事件提交宏（ringbuf + perfbuf 统一接口，tier-agnostic）──
 * B1: perfbuf 路径用 PERCPU_ARRAY scratch 暂存事件结构体，
 * 绕过 BPF 512 字节栈限制。BPF 程序 per-CPU 不可抢占，
 * 一个 CPU 同时只有一个事件在飞，scratch 无竞争。
 * KS_SUBMIT 签名统一为 (ctx, buf, evt)：ringbuf 路径忽略 ctx/buf，
 * perfbuf 路径用 ctx 调 bpf_perf_event_output + buf 指定 perf_event_array map。
 */
#if KS_RINGBUF
    #define KS_RESERVE(buf, type) ((type *)bpf_ringbuf_reserve(&(buf), sizeof(type), 0))
    #define KS_SUBMIT(ctx, buf, evt) bpf_ringbuf_submit((evt), 0)
#else
    /* PERCPU_ARRAY scratch：value=u8[1024] 覆盖最大事件结构体 exec_event(~816B)
     * C5: 通过 KS_PERCPU_ARRAY_MAP 宏，Ancient tier 自动回退到 CPU-keyed ARRAY */
    KS_PERCPU_ARRAY_MAP(ks_scratch, u8[1024]);

    #define KS_RESERVE(buf, type) ({ \
        u32 _k = KS_PERCPU_KEY(); \
        (type *)bpf_map_lookup_elem(&ks_scratch, &_k); \
    })
    #define KS_SUBMIT(ctx, buf, evt) \
        bpf_perf_event_output((ctx), &(buf), BPF_F_CURRENT_CPU, (evt), sizeof(*(evt)))
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

/* E4.1/E4.2/E4.3: 安全探针事件类型（提交到 events ringbuf）
 * 避开 1-31 syscall/vfs/net/signal、40-43 tree、50-54 flow、60-61 freq、70-72 filter。
 * 80-82 是新分配的安全事件段。 */
#define EVENT_CONTAINER_ESCAPE 80
#define EVENT_LKM_LOAD         81
#define EVENT_EBPF_TAMPER      82

/* ── 共享 BPF Maps ────────────────────────── */

/* 推理配置 / 风险分 / IP白名单 / 网络连接历史 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, u32);
    __type(value, u32);
} infer_config SEC(".maps");

/* ── G2.1: 内核态阻断 block_decisions map ──
 * 申报书第四阶段："阻断机制基于 bpf_send_signal 实现...探针调用 bpf_send_signal 发送 SIGKILL"
 * 用户态 BlockManager.block_pid() 写入，内核态探针查询。
 *   key=pid, value={expire_ns, reason}
 *   expire_ns: 0=永久阻断；否则 bpf_ktime_get_ns() < expire_ns 阻断
 * 阻断 reason 编码（与用户态 BlockReason 枚举对齐）：
 *   1=RuleMatch / 2=BaselineDeviation / 3=MlAnomaly / 4=Correlation / 5=Manual
 */
struct block_key { u32 pid; u32 _pad_blk; };
struct block_value {
    u64 expire_ns;
    u8  reason;
    u8  _pad_bv[7];
};

KS_LRU_HASH_MAP(block_decisions, struct block_key, struct block_value, 4096);

/* 自身进程豁免白名单：用户态启动时写入 kernelsentinel 自身 pid(及关键系统 pid)，
 * KS_MAYBE_BLOCK 在 bpf_send_signal 前判断当前 tgid 命中即跳过，
 * 避免分类器冷启动误报把自身/系统进程 SIGKILL(Tetragon 无此硬保险，本项目多加一层)。
 * key=tgid, value=1(受保护)。Array 不足以存任意 pid，用 LRU_HASH。 */
KS_LRU_HASH_MAP(protected_pids, u32, u8, 256);

/* G2.1: 内核态阻断查询 — 命中且未过期则 SIGKILL（仅 Modern tier）。
 * Modern tier（5.8+）一定支持 bpf_send_signal（5.4+ helper）。
 * Legacy/Ancient 不调 bpf_send_signal（兼容性未知），仅返回是否应阻断，
 * 由用户态反向通道（BlockManager）补齐。
 *
 * 申报书第四阶段对齐：infer 返回 verdict==2（风险分≥70）时，探针在内核态
 * 直接调 bpf_send_signal(SIGKILL) 终止恶意进程（零延迟阻断）。
 * bpf_send_signal 发送给当前任务（即触发该 syscall 的进程本身），
 * 监控系统自身不发起恶意 syscall，故不会"自杀"。
 * 此外仍查 block_decisions map —— 用户态 BlockManager 显式写入的 PID 也阻断。 */
#if KS_RINGBUF
/* 受保护进程豁免：bpf_send_signal 发给当前任务，故以当前 tgid 判断。
 * protected_pids 由用户态启动时写入自身/关键系统 pid。命中则绝不杀，
 * 防止分类器冷启动误报把自身或系统进程 SIGKILL。 */
static __always_inline int ks_current_protected(void) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u8 *p = bpf_map_lookup_elem(&protected_pids, &tgid);
    return p && *p == 1;
}

static __always_inline int ks_check_block(u32 pid) {
    struct block_key bk = { .pid = pid, ._pad_blk = 0 };
    struct block_value *bv = bpf_map_lookup_elem(&block_decisions, &bk);
    if (!bv) return 0;
    if (bv->expire_ns == 0 || bpf_ktime_get_ns() < bv->expire_ns) {
        if (!ks_current_protected())
            bpf_send_signal(9); /* SIGKILL */
        return 1;
    }
    return 0;
}

/* Modern tier 阻断：
 *   enforce_mode=1(默认0=monitor)：verdict==2 内核态直接 bpf_send_signal。
 *   monitor 模式仅查 block_decisions(用户态显式阻断)，不因 verdict 主动杀。
 * monitor 默认避免冷启动误报误杀正常进程/自身；用户态显式置 enforce 才真阻断。
 * 两条 kill 路径都先过 ks_current_protected() 豁免自身。 */
#define KS_MAYBE_BLOCK(pid, verdict) do { \
    if (get_config(CFG_ENFORCE_MODE, 0) == 1 && (verdict) == 2) { \
        if (!ks_current_protected()) \
            bpf_send_signal(9); /* SIGKILL — verdict==2 内核态直接阻断(申报书第四阶段) */ \
    } \
    ks_check_block((pid)); \
} while (0)
#else
/* Legacy/Ancient: 仅查询 map，不主动调 bpf_send_signal（兼容性未知） */
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

KS_LRU_HASH_MAP(freq_counters, u32, struct freq_counter, 4096);

/* ── 推理引擎 ──────────────────────────────── */

enum infer_config_key {
    CFG_RISK_THRESHOLD      = 0,
    CFG_PORT_SCAN_THRESHOLD = 1,
    CFG_TIME_WINDOW_NS      = 2,
    CFG_MAX_NEW_FILES       = 3,
    CFG_NEW_FILE_WINDOW_NS  = 4,
    /* 5: enforce_mode — 0=monitor(只告警/记block_decisions，不主动SIGKILL)，
     * 1=enforce(verdict==2 内核态直接 bpf_send_signal)。默认 0，
     * 冷启动误报高时避免误杀正常进程/自身；用户态显式置 1 才真阻断。
     * 对齐 Tetragon POLICY_MODE_ENFORCE/MONITOR 设计。 */
    CFG_ENFORCE_MODE        = 5,
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

    struct net_conn_key key = {};
    key.pid = pid; key.daddr = daddr; key.dport = dport; key.proto = proto;
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
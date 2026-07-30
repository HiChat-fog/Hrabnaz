#ifndef KS_PROBES_SMART_FILTER_H
#define KS_PROBES_SMART_FILTER_H

#define EVENT_FILTER_PASS    70
#define EVENT_FILTER_BLOCK   71
#define EVENT_FILTER_STATS   72

struct filter_decision {
    u8 action, reason;
    u16 _pad_decision1;
    u32 risk_score;
};

#define FILTER_REASON_LOW_RISK     0
#define FILTER_REASON_NORMAL_FREQ  1
#define FILTER_REASON_WHITELIST    2
#define FILTER_REASON_SAFE_PATTERN 3

struct filter_stats {
    u64 total_events, passed_events, blocked_events;
};

KS_LRU_HASH_MAP(process_whitelist, u32, u8, 256);

struct safe_pattern_key {
    u8 comm[16], path_prefix[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct safe_pattern_key);
    __type(value, u8);
    __uint(max_entries, 128);
} safe_patterns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 8);
} filter_config SEC(".maps");

enum filter_config_key {
    FC_MIN_RISK_SCORE    = 0,
    FC_MAX_NORMAL_FREQ   = 1,
    FC_BLOCK_RATE_TARGET = 2,
};

/* C6: KS_PERCPU_ARRAY_MAP 宏声明，Ancient tier 自动回退到 CPU-keyed ARRAY */
KS_PERCPU_ARRAY_MAP(filter_stats_map, struct filter_stats);

KS_EVENT_MAP(filter_events, 1024 * 1024);

static __always_inline u32 get_filter_config(u32 key, u32 default_val) {
    u32 *val = bpf_map_lookup_elem(&filter_config, &key);
    return val ? *val : default_val;
}

static __always_inline struct filter_decision should_send_event(
    u32 pid, u32 event_type, const char *filename) {

    struct filter_decision decision = {};
    decision.action = 0; decision.reason = 0;
    u32 min_risk = get_filter_config(FC_MIN_RISK_SCORE, 40);

    u8 *whitelisted = bpf_map_lookup_elem(&process_whitelist, &pid);
    if (whitelisted && *whitelisted == 1) {
        decision.action=1; decision.reason=FILTER_REASON_WHITELIST; return decision;
    }

    if (filename && (event_type >= 10 && event_type <= 12)) {
        struct safe_pattern_key sp_key = {};
        bpf_get_current_comm(&sp_key.comm, sizeof(sp_key.comm));
        bpf_probe_read_kernel_str(sp_key.path_prefix, sizeof(sp_key.path_prefix), filename);
        u8 *safe = bpf_map_lookup_elem(&safe_patterns, &sp_key);
        if (safe && *safe == 1) {
            decision.action=1; decision.reason=FILTER_REASON_SAFE_PATTERN; return decision;
        }
    }

    u32 *risk = bpf_map_lookup_elem(&risk_scores, &pid);
    decision.risk_score = risk ? *risk : 0;
    if (decision.risk_score >= min_risk) return decision;

    struct freq_counter *fc = bpf_map_lookup_elem(&freq_counters, &pid);
    if (fc) {
        if (fc->anomaly_flags > 0) return decision;
        decision.action=1; decision.reason=FILTER_REASON_NORMAL_FREQ; return decision;
    }

    switch (event_type) {
    case 1:  case 30: case 31: case 20:
        break;
    case 10: case 11:
        decision.action=1; decision.reason=FILTER_REASON_LOW_RISK; break;
    }
    return decision;
}

static __always_inline void update_filter_stats(u8 action) {
    u32 key = KS_PERCPU_KEY();
    struct filter_stats *stats = bpf_map_lookup_elem(&filter_stats_map, &key);
    if (!stats) {
        struct filter_stats new_stats = {};
        new_stats.total_events = 1;
        if (action == 0) new_stats.passed_events = 1;
        else new_stats.blocked_events = 1;
        bpf_map_update_elem(&filter_stats_map, &key, &new_stats, BPF_ANY);
        return;
    }
    stats->total_events++;
    if (action == 0) stats->passed_events++;
    else stats->blocked_events++;
}

static __always_inline void smart_filter_handle_vfs_open(struct path *path) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) return;

    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    const char *name = KS_READ_DNAME(dentry);

    /* 3.10 verifier 无法追踪 bpf_probe_read 返回的指针（标记为 inv），
     * 直接解引用会报 "invalid mem access"。先拷到栈缓冲区。 */
    char name_buf[64] = {};
    if (name) bpf_probe_read(name_buf, sizeof(name_buf), name);

    struct filter_decision decision = should_send_event(pid, EVENT_FILE_OPEN, name_buf);
    update_filter_stats(decision.action);

    if (decision.action == 1) {
        infer_sensitive_file(name_buf, pid);
        update_freq_counter(pid, 10);
    }
}

#endif // KS_PROBES_SMART_FILTER_H

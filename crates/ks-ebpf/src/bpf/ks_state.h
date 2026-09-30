#ifndef KS_STATE_H
#define KS_STATE_H

/* ── 内核态原语：跨事件状态维护与风险评分 ──
   进程树拓扑、TCP 连接历史、六维频率计数、风险分累积。
   只维护状态和分数，不定义"什么算可疑"（那是 ks_semantics），
   也不触发实杀（那是 ks_channel/ks_semantics）。 */

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

#endif

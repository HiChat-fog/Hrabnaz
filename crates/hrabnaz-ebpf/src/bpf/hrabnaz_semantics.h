#ifndef HRABNAZ_SEMANTICS_H
#define HRABNAZ_SEMANTICS_H

/* ── 检测语义：什么算可疑、风险分怎么加、何时由内核实杀 ──
   infer_* 定义"行为→风险分"的映射（读 ks_state 的状态），
   HRABNAZ_MAYBE_BLOCK 定义"verdict→实杀"的决策（经 ks_channel 查裁决表）。
   阈值/开关全部走 infer_config map，用户态可调，本层不硬编码策略。 */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, u32);
    __type(value, u32);
} infer_config SEC(".maps");

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
    // 先查 map：infer_config 里用户态写入的值优先；
    // 旧实现对 key 0-4 硬编码直返，map 里对这些 key 的写入全是死配置
    u32 *val = bpf_map_lookup_elem(&infer_config, &key);
    if (val && *val != 0)
        return *val;
    switch (key) {
    case CFG_RISK_THRESHOLD:      return 70;
    case CFG_PORT_SCAN_THRESHOLD: return 20;
    case CFG_TIME_WINDOW_NS:      return 30;
    case CFG_MAX_NEW_FILES:       return 100;
    case CFG_NEW_FILE_WINDOW_NS:  return 30;
    default: break;
    }
    return default_val;
}

#if HRABNAZ_RINGBUF
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

#define HRABNAZ_MAYBE_BLOCK(pid, verdict) do { \
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
#define HRABNAZ_MAYBE_BLOCK(pid, verdict) do { \
    (void)(verdict); \
    ks_check_block((pid)); \
} while (0)
#endif

static __always_inline int infer_sensitive_file(const char *filename, u32 pid) {
    if (!filename) return 0;
    /*
     * 低敏放行（只穿透智能过滤，不加分）：FILE_OPEN/READ 对低风险进程默认丢弃，
     * 而 /etc/ 与 /boot/ 下的路径是配置篡改类规则（cron.d、sudoers、/boot 启动文件）
     * 的唯一信号源——不在这里放行，那些用户态规则对新起进程永远等不到事件
     * （ART T1053.003 真机实测：写 /etc/cron.d 零告警，规则层本地可达）。
     * 不加分的原因：/etc 读取是正常运维高频行为，加分会把长跑进程误推过风险阈值；
     * 分支放在具体路径之后，避免短路 shadow/gshadow/sudoers 的加分。
     * /home 下 authorized_keys/id_rsa 需要后缀匹配，3.10 verifier 无循环支持做不了，
     * 列入 H-2；当前以 /root/.ssh 前缀覆盖 root 场景。
     */
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
    if (filename[0]=='/' && filename[1]=='e' && filename[2]=='t' &&
        filename[3]=='c' && filename[4]=='/') {
        return 1;
    }
    if (filename[0]=='/' && filename[1]=='b' && filename[2]=='o' &&
        filename[3]=='o' && filename[4]=='t' && filename[5]=='/') {
        return 1;
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


/* 旧版 update_freq_counter 已删除：全部调用点走 freq.h 的 update_freq_counter_ex，
   本函数语义与之不一致（窗口重置不清计数、DNS 分支永不命中），留着只会误导 */

#endif

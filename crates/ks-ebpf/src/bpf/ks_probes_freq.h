#ifndef KS_PROBES_FREQ_H
#define KS_PROBES_FREQ_H

#define EVENT_FREQ_UPDATE  60
#define EVENT_FREQ_ANOMALY 61

struct freq_anomaly_event {
    struct ks_event header;
    u32 pid, syscall_count_60s, file_op_count_60s, net_op_count_60s;
    u32 dns_op_count_60s, ptrace_count_60s, signal_count_60s;
    u32 anomaly_flags;
    u64 duration_ns;
};

struct freq_update_event {
    struct ks_event header;
    u32 pid, syscall_count_60s, file_op_count_60s, net_op_count_60s;
    u32 dns_op_count_60s, ptrace_count_60s, signal_count_60s;
    u32 anomaly_flags;
    u64 duration_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 16);
} freq_thresholds SEC(".maps");

enum freq_threshold_key {
    TH_FILE_OPS_60S = 0, TH_NET_OPS_60S = 1, TH_DNS_OPS_60S = 2,
    TH_SYSCALL_60S = 3,  TH_PTRACE_60S = 4,  TH_SIGNAL_60S = 5,
    TH_REPORT_EVERY = 6,  TH_WINDOW_NS = 7,
};

KS_EVENT_MAP(freq_events, 256 * 1024);

static __always_inline u32 get_threshold(u32 key, u32 default_val) {
    u32 *val = bpf_map_lookup_elem(&freq_thresholds, &key);
    return val ? *val : default_val;
}

static __always_inline void update_freq_counter_ex(void *ctx, u32 pid, u32 counter_type) {
    u64 now = bpf_ktime_get_ns();
    u64 window_ns = (u64)get_threshold(TH_WINDOW_NS, 60) * 1000000000ULL;

    struct freq_counter *fc = bpf_map_lookup_elem(&freq_counters, &pid);
    if (!fc) {
        struct freq_counter new_fc = {};
        new_fc.syscall_count_60s = 1;
        new_fc.last_update_ns = now;
        new_fc.window_start_ns = now;

        if (counter_type >= 10 && counter_type <= 15)
            new_fc.file_op_count_60s = 1;
        else if (counter_type >= 20 && counter_type <= 23)
            new_fc.net_op_count_60s = 1;
        else if (counter_type == 24)
            new_fc.dns_op_count_60s = 1;
        else if (counter_type == 30)
            new_fc.ptrace_count_60s = 1;
        else if (counter_type == 31)
            new_fc.signal_count_60s = 1;

        bpf_map_update_elem(&freq_counters, &pid, &new_fc, BPF_ANY);
        return;
    }

    u64 elapsed = now - fc->window_start_ns;
    if (elapsed > window_ns) {
        fc->syscall_count_60s = 0; fc->file_op_count_60s = 0;
        fc->net_op_count_60s = 0;  fc->dns_op_count_60s = 0;
        fc->ptrace_count_60s = 0;  fc->signal_count_60s = 0;
        fc->window_start_ns = now; fc->anomaly_flags = 0;
    }

    fc->syscall_count_60s++;
    fc->last_update_ns = now;

    if (counter_type >= 10 && counter_type <= 15)
        fc->file_op_count_60s++;
    else if (counter_type >= 20 && counter_type <= 23)
        fc->net_op_count_60s++;
    else if (counter_type == 24)
        fc->dns_op_count_60s++;
    else if (counter_type == 30)
        fc->ptrace_count_60s++;
    else if (counter_type == 31)
        fc->signal_count_60s++;

    if (fc->file_op_count_60s  > get_threshold(TH_FILE_OPS_60S, 500))
        fc->anomaly_flags |= FREQ_ANOMALY_RANSOMWARE;
    if (fc->net_op_count_60s   > get_threshold(TH_NET_OPS_60S, 100))
        fc->anomaly_flags |= FREQ_ANOMALY_PORT_SCAN;
    if (fc->dns_op_count_60s   > get_threshold(TH_DNS_OPS_60S, 50))
        fc->anomaly_flags |= FREQ_ANOMALY_DNS_TUNNEL;
    if (fc->syscall_count_60s  > get_threshold(TH_SYSCALL_60S, 10000))
        fc->anomaly_flags |= FREQ_ANOMALY_BRUTE_FORCE;
    if (fc->ptrace_count_60s   > get_threshold(TH_PTRACE_60S, 3))
        fc->anomaly_flags |= FREQ_ANOMALY_INJECTION;

    if (fc->anomaly_flags > 0) {
        struct freq_anomaly_event *evt = KS_RESERVE(freq_events, struct freq_anomaly_event);
        if (!evt) goto report;
        fill_header(&evt->header, EVENT_FREQ_ANOMALY);
        evt->pid=pid; evt->syscall_count_60s=fc->syscall_count_60s;
        evt->file_op_count_60s=fc->file_op_count_60s; evt->net_op_count_60s=fc->net_op_count_60s;
        evt->dns_op_count_60s=fc->dns_op_count_60s; evt->ptrace_count_60s=fc->ptrace_count_60s;
        evt->signal_count_60s=fc->signal_count_60s; evt->anomaly_flags=fc->anomaly_flags;
        evt->duration_ns=now - fc->window_start_ns;
        KS_SUBMIT(ctx, freq_events, evt);
    }

report:
    ;
    u32 report_every = get_threshold(TH_REPORT_EVERY, 100);
    if (fc->syscall_count_60s % report_every == 0) {
        struct freq_update_event *evt = KS_RESERVE(freq_events, struct freq_update_event);
        if (!evt) return;
        fill_header(&evt->header, EVENT_FREQ_UPDATE);
        evt->pid=pid; evt->syscall_count_60s=fc->syscall_count_60s;
        evt->file_op_count_60s=fc->file_op_count_60s; evt->net_op_count_60s=fc->net_op_count_60s;
        evt->dns_op_count_60s=fc->dns_op_count_60s; evt->ptrace_count_60s=fc->ptrace_count_60s;
        evt->signal_count_60s=fc->signal_count_60s; evt->anomaly_flags=fc->anomaly_flags;
        evt->duration_ns=now - fc->window_start_ns;
        KS_SUBMIT(ctx, freq_events, evt);
    }

    bpf_map_update_elem(&freq_counters, &pid, fc, BPF_ANY);
}

static __always_inline void freq_handle_sys_exit(void *ctx, u32 syscall_nr) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) return;

    switch (syscall_nr) {
    case 2:  case 257: update_freq_counter_ex(ctx, pid, 10); break;
    case 0:            update_freq_counter_ex(ctx, pid, 11); break;
    case 1:            update_freq_counter_ex(ctx, pid, 12); break;
    case 87:           update_freq_counter_ex(ctx, pid, 13); break;
    case 42:           update_freq_counter_ex(ctx, pid, 20); break;
    case 101:          update_freq_counter_ex(ctx, pid, 30); break;
    case 62:           update_freq_counter_ex(ctx, pid, 31); break;
    }
}

#endif // KS_PROBES_FREQ_H

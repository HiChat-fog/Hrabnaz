#ifndef KS_PROBES_NETFLOW_H
#define KS_PROBES_NETFLOW_H

#define TCP_SYN_SENT    1
#define TCP_ESTABLISHED 2
#define TCP_FIN_WAIT    3
#define TCP_CLOSED      4
#define TCP_RESET       5

#define EVENT_FLOW_CREATE  50
#define EVENT_FLOW_STATE   51
#define EVENT_FLOW_DATA    52
#define EVENT_FLOW_CLOSE   53
#define EVENT_FLOW_ANOMALY 54

struct net_flow_key {
    u32 pid, saddr, daddr;
    u16 sport, dport;
    u8  proto, _pad_key;
};

struct net_flow_state {
    u8  tcp_state, _pad_state1;
    u16 anomaly_flags;
    u64 byte_count, packet_count, create_time_ns, last_update_ns;
    u32 connect_count, _pad_state2;
};

#define FLOW_ANOMALY_C2_HEARTBEAT   (1 << 0)
#define FLOW_ANOMALY_DATA_EXFIL     (1 << 1)
#define FLOW_ANOMALY_PORT_SCAN      (1 << 2)
#define FLOW_ANOMALY_LONG_CONN      (1 << 3)
#define FLOW_ANOMALY_FAST_RECONNECT (1 << 4)

struct net_flow_event {
    struct ks_event header;
    u32 pid, saddr, daddr;
    u16 sport, dport;
    u8  proto, tcp_state;
    u16 anomaly_flags;
    u64 byte_count, packet_count, duration_ns;
    u32 connect_count, _pad_flow1;
};

KS_LRU_HASH_MAP(net_flows, struct net_flow_key, struct net_flow_state, 8192);

struct port_scan_tracker {
    u32 scan_count, _pad_scan1, _pad_scan2;
    u64 first_scan_ns;
};

KS_LRU_HASH_MAP(port_scan_map, u32, struct port_scan_tracker, 4096);

KS_EVENT_MAP(flow_events, 256 * 1024);

static __always_inline void netflow_handle_tcp_v4_connect(void *ctx, struct sock *sk, struct sockaddr *uaddr) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) return;
    u64 now = bpf_ktime_get_ns();

    struct inet_sock *inet = (struct inet_sock *)sk;
    u32 saddr = BPF_CORE_READ(inet, inet_saddr);
    u16 sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
    struct sockaddr_in sin;
    if (bpf_probe_read_kernel(&sin, sizeof(sin), uaddr) < 0) return;
    u32 daddr = sin.sin_addr.s_addr;
    u16 dport = bpf_ntohs(sin.sin_port);

    struct net_flow_key key = {};
    key.pid=pid; key.saddr=saddr; key.daddr=daddr;
    key.sport=sport; key.dport=dport; key.proto=6; key._pad_key=0;
    struct net_flow_state state = {};
    state.tcp_state=TCP_SYN_SENT; state.create_time_ns=now;
    state.last_update_ns=now; state.connect_count=1;
    state.packet_count=1;

    struct net_flow_state *prev = bpf_map_lookup_elem(&net_flows, &key);
    if (prev) {
        u64 time_since_last = now - prev->last_update_ns;
        if (time_since_last < 30ULL * 1000 * 1000 * 1000)
            state.anomaly_flags |= FLOW_ANOMALY_FAST_RECONNECT;
        if (prev->connect_count >= 3)
            state.anomaly_flags |= FLOW_ANOMALY_C2_HEARTBEAT;
        state.connect_count = prev->connect_count + 1;
    }

    struct port_scan_tracker *scan = bpf_map_lookup_elem(&port_scan_map, &pid);
    if (scan) {
        scan->scan_count++;
        u64 scan_duration = now - scan->first_scan_ns;
        if (scan->scan_count >= 20 && scan_duration < 30ULL * 1000 * 1000 * 1000)
            state.anomaly_flags |= FLOW_ANOMALY_PORT_SCAN;
    } else {
        struct port_scan_tracker new_scan = {};
        new_scan.scan_count = 1;
        new_scan.first_scan_ns = now;
        bpf_map_update_elem(&port_scan_map, &pid, &new_scan, BPF_ANY);
    }

    if (state.anomaly_flags > 0) {
        struct net_flow_event *evt = KS_RESERVE(flow_events, struct net_flow_event);
        if (!evt) return;
        fill_header(&evt->header, EVENT_FLOW_CREATE);
        evt->pid=pid; evt->saddr=saddr; evt->daddr=daddr;
        evt->sport=sport; evt->dport=dport; evt->proto=6;
        evt->tcp_state=TCP_SYN_SENT; evt->anomaly_flags=state.anomaly_flags;
        evt->connect_count=state.connect_count;
        KS_SUBMIT(ctx, flow_events, evt);
    }
    bpf_map_update_elem(&net_flows, &key, &state, BPF_ANY);
}

SEC("kprobe/tcp_set_state")
int BPF_KPROBE(kprobe_tcp_set_state_flow, struct sock *sk, int new_state) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) return 0;
    u64 now = bpf_ktime_get_ns();

    struct inet_sock *inet = (struct inet_sock *)sk;
    struct sock_common common = BPF_CORE_READ(sk, __sk_common);
    struct net_flow_key key = {};
    key.pid=pid; key.saddr=BPF_CORE_READ(inet, inet_saddr);
    key.daddr=common.skc_daddr; key.proto=6;
    key.sport=bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
    key.dport=bpf_ntohs(common.skc_dport);

    u8 our_state;
    switch (new_state) {
    case 1:  our_state = TCP_ESTABLISHED; break;
    case 2:  our_state = TCP_SYN_SENT;    break;
    case 4: case 5: case 8: our_state = TCP_FIN_WAIT; break;
    case 7:  our_state = TCP_CLOSED;      break;
    default: return 0;
    }

    struct net_flow_state *flow = bpf_map_lookup_elem(&net_flows, &key);
    if (!flow) return 0;

    flow->tcp_state = our_state;
    flow->last_update_ns = now;

    if (our_state == TCP_ESTABLISHED) {
        u64 duration = now - flow->create_time_ns;
        if (duration > 24ULL * 3600 * 1000 * 1000 * 1000)
            flow->anomaly_flags |= FLOW_ANOMALY_LONG_CONN;
    }

    if (our_state == TCP_ESTABLISHED || our_state == TCP_CLOSED || flow->anomaly_flags > 0) {
        struct net_flow_event *evt = KS_RESERVE(flow_events, struct net_flow_event);
        if (!evt) return 0;
        fill_header(&evt->header, EVENT_FLOW_STATE);
        evt->pid=pid; evt->saddr=key.saddr; evt->daddr=key.daddr;
        evt->sport=key.sport; evt->dport=key.dport; evt->proto=6;
        evt->tcp_state=our_state; evt->anomaly_flags=flow->anomaly_flags;
        evt->byte_count=flow->byte_count; evt->packet_count=flow->packet_count;
        evt->duration_ns=now - flow->create_time_ns;
        evt->connect_count=flow->connect_count;
        KS_SUBMIT(ctx, flow_events, evt);
    }

    if (our_state == TCP_CLOSED)
        bpf_map_delete_elem(&net_flows, &key);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg_flow, struct sock *sk, struct msghdr *msg, size_t size) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    if (pid == 0) return 0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    struct sock_common common = BPF_CORE_READ(sk, __sk_common);
    struct net_flow_key key = {};
    key.pid=pid; key.saddr=BPF_CORE_READ(inet, inet_saddr);
    key.daddr=common.skc_daddr; key.proto=6;
    key.sport=bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
    key.dport=bpf_ntohs(common.skc_dport);

    struct net_flow_state *flow = bpf_map_lookup_elem(&net_flows, &key);
    if (!flow) return 0;
    flow->byte_count += size;
    flow->packet_count++;
    flow->last_update_ns = bpf_ktime_get_ns();

    if (flow->byte_count > 100ULL * 1024 * 1024)
        flow->anomaly_flags |= FLOW_ANOMALY_DATA_EXFIL;
    return 0;
}

#endif // KS_PROBES_NETFLOW_H

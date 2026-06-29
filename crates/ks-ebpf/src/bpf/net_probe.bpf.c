// 网络探针 — kprobe/tcp_v4_connect, tcp_v6_connect, udp_sendmsg
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct net_event), 0);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_NET_CONNECT);
    evt->header.syscall_nr = 42;

    evt->saddr = 0;  evt->daddr = 0;
    evt->sport = 0;  evt->dport = 0;
    evt->proto = 0;  evt->family = 0;
    __builtin_memset(evt->saddr6, 0, sizeof(evt->saddr6));
    __builtin_memset(evt->daddr6, 0, sizeof(evt->daddr6));
    evt->_pad3[0]=0;  evt->_pad3[1]=0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    evt->saddr = BPF_CORE_READ(inet, inet_saddr);
    evt->sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));

    struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
    bpf_probe_read_kernel(&evt->daddr, sizeof(evt->daddr), &addr->sin_addr.s_addr);
    bpf_probe_read_kernel(&evt->dport, sizeof(evt->dport), &addr->sin_port);
    evt->dport = bpf_ntohs(evt->dport);
    evt->proto = 6;   evt->family = 2;

    infer_event(evt->header.pid, EVENT_NET_CONNECT, NULL,
                evt->daddr, evt->dport, evt->proto, 0);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct net_event), 0);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_NET_CONNECT);
    evt->header.syscall_nr = 42;
    evt->saddr = 0;  evt->daddr = 0;
    evt->sport = 0;  evt->dport = 0;
    evt->proto = 0;  evt->family = 0;
    __builtin_memset(evt->saddr6, 0, sizeof(evt->saddr6));
    __builtin_memset(evt->daddr6, 0, sizeof(evt->daddr6));
    evt->_pad3[0]=0;  evt->_pad3[1]=0;

    evt->family = 10;
    struct inet_sock *inet = (struct inet_sock *)sk;
    evt->sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));

    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)uaddr;
    evt->dport = bpf_ntohs(BPF_CORE_READ(addr6, sin6_port));
    bpf_probe_read_kernel(evt->daddr6, sizeof(evt->daddr6), &addr6->sin6_addr);
    evt->proto = 6;

    infer_event(evt->header.pid, EVENT_NET_CONNECT, NULL,
                0, evt->dport, evt->proto, 0);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct net_event), 0);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_NET_SEND);
    evt->header.syscall_nr = 44;
    evt->saddr = 0;  evt->daddr = 0;
    evt->sport = 0;  evt->dport = 0;
    evt->proto = 0;  evt->family = 0;
    __builtin_memset(evt->saddr6, 0, sizeof(evt->saddr6));
    __builtin_memset(evt->daddr6, 0, sizeof(evt->daddr6));
    evt->_pad3[0]=0;  evt->_pad3[1]=0;

    struct inet_sock *inet = (struct inet_sock *)sk;
    evt->saddr = BPF_CORE_READ(inet, inet_saddr);
    evt->sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));

    struct sock_common common = BPF_CORE_READ(sk, __sk_common);
    evt->daddr = common.skc_daddr;
    evt->dport = bpf_ntohs(common.skc_dport);

    if (evt->daddr != 0)
        evt->family = 2;
    evt->proto = 17;

    if (evt->dport == 53)
        evt->header.event_type = EVENT_NET_DNS;

    infer_event(evt->header.pid, evt->header.event_type, NULL,
                evt->daddr, evt->dport, evt->proto, 0);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
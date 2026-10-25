#ifndef KS_PROBES_NET_H
#define KS_PROBES_NET_H

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    netflow_handle_tcp_v4_connect(ctx, sk, uaddr);

    struct net_event *evt = KS_RESERVE(events, struct net_event);
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

    // uaddr 是用户态指针：5.5+ 内核区分 user/kernel 读取后，
    // 旧实现 bpf_probe_read_kernel 在此恒 -EFAULT，connect 目标地址全丢。
    // ancient/legacy_nobtf 由 common.h 宏回落 bpf_probe_read
    struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
    KS_WRITE_USER(&evt->daddr, sizeof(evt->daddr), &addr->sin_addr.s_addr);
    KS_WRITE_USER(&evt->dport, sizeof(evt->dport), &addr->sin_port);
    evt->dport = bpf_ntohs(evt->dport);
    evt->proto = 6;   evt->family = 2;

    infer_event(evt->header.pid, EVENT_NET_CONNECT, NULL,
                evt->daddr, evt->dport, evt->proto, 0);
    KS_SUBMIT(ctx, events, evt);
    return 0;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len) {
    struct net_event *evt = KS_RESERVE(events, struct net_event);
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

    // uaddr 是用户态指针：整块读入栈再取字段。
    // 旧实现 BPF_CORE_READ/bpf_probe_read_kernel 直读用户地址，
    // 5.5+ 内核上恒失败（v6 的 dport/daddr 一直是 0）
    struct sockaddr_in6 sa6 = {};
    if (bpf_probe_read_user(&sa6, sizeof(sa6), uaddr) < 0)
        sa6.sin6_port = 0;
    evt->dport = bpf_ntohs(sa6.sin6_port);
    __builtin_memcpy(evt->daddr6, &sa6.sin6_addr, sizeof(evt->daddr6));
    evt->proto = 6;

    infer_event(evt->header.pid, EVENT_NET_CONNECT, NULL,
                0, evt->dport, evt->proto, 0);
    KS_SUBMIT(ctx, events, evt);
    return 0;
}

SEC("kprobe/udp_sendmsg")
/*
 * udp_sendmsg 的函数签名在 4.2 前后不同（H-1.2；签名以内嵌 3.10.0-1160.119.1
 * BTF 的 FUNC_PROTO 核实：vlen=4 'iocb','sk','msg','len'）：
 *   <4.2（ancient tier 覆盖的 3.10~4.1，含 RHEL7）：(kiocb, sk, msg, len)
 *   >=4.2（legacy/modern tier 的 4.19/5.x+）：      (sk, msg, len)
 * 旧实现统一按 (sk, msg, len) 取 args[0]，在 3.10 上拿到的是 kiocb 栈指针，
 * 后续 inet_saddr/skc_daddr/skc_dport 全部读在错误结构上——真机实测 UDP 事件
 * daddr/dport 恒 0（76 条全 0），dport==53 的 DNS 判定分支永不可达。
 * tcp_v4_connect 不受影响：两世代签名相同。
 * 4.0/4.1 非长期维护内核，不在兼容矩阵内（ancient BTF 预埋按 3.10 发行版走）。
 */
#if defined(KS_TIER_ANCIENT)
int BPF_KPROBE(kprobe_udp_sendmsg, void *iocb, struct sock *sk, struct msghdr *msg, size_t len) {
    (void)iocb;
#else
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len) {
#endif
    struct net_event *evt = KS_RESERVE(events, struct net_event);
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
    KS_SUBMIT(ctx, events, evt);
    return 0;
}

#endif

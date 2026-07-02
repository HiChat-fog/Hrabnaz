#ifndef KS_PROBES_SYSCALL_H
#define KS_PROBES_SYSCALL_H

struct syscall_ctx {
    u64 args[6];
    u64 start_ns;
    u32 pid;
    u32 syscall_nr;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct syscall_ctx);
} syscall_ctxs SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 syscall_nr = ctx->id;

    switch (syscall_nr) {
    case 59:  case 2:   case 257:
    case 0:   case 1:   case 42:
    case 101: case 62:
        break;
    default:
        return 0;
    }

    struct syscall_ctx sctx = {};
    sctx.start_ns   = bpf_ktime_get_ns();
    sctx.pid        = pid_tgid >> 32;
    sctx.syscall_nr = syscall_nr;
    sctx.args[0] = ctx->args[0];
    sctx.args[1] = ctx->args[1];
    sctx.args[2] = ctx->args[2];
    sctx.args[3] = ctx->args[3];
    sctx.args[4] = ctx->args[4];
    sctx.args[5] = ctx->args[5];

    bpf_map_update_elem(&syscall_ctxs, &pid_tgid, &sctx, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_ctx *sctx = bpf_map_lookup_elem(&syscall_ctxs, &pid_tgid);
    if (!sctx) return 0;

    long ret = ctx->ret;
    u32 syscall_nr = sctx->syscall_nr;

    if (syscall_nr == 59 && ret >= 0) {
        struct exec_event *evt = KS_RESERVE(events, struct exec_event);
        if (!evt) goto cleanup;

        fill_header(&evt->header, EVENT_PROCESS_EXEC);
        evt->header.syscall_nr = 59;
        evt->header.retval = ret;

        const char __user *filename_ptr = (const char __user *)sctx->args[0];
        bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename_ptr);

        const char __user *const *argv_ptr = (const char __user *const *)sctx->args[1];
        if (argv_ptr) {
            int offset = 0;
            for (int i = 0; i < 5; i++) {
                const char __user *arg_ptr;
                if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_ptr[i]) < 0)
                    break;
                if (!arg_ptr) break;
                if (offset >= 448) break;
                int len = bpf_probe_read_user_str(evt->args + offset, 64, arg_ptr);
                if (len <= 0) break;
                offset += len;
            }
        }

        infer_event(evt->header.pid, EVENT_PROCESS_EXEC,
                    (const char *)evt->filename, 0, 0, 0, 0);
        KS_SUBMIT(evt);
        goto cleanup;
    }

    if ((syscall_nr == 2 || syscall_nr == 257) && ret >= 0) {
        struct file_event *evt = KS_RESERVE(events, struct file_event);
        if (!evt) goto cleanup;

        fill_header(&evt->header, EVENT_FILE_OPEN);
        evt->header.syscall_nr = syscall_nr;
        evt->header.retval = ret;

        const char __user *path_ptr;
        if (syscall_nr == 257)
            path_ptr = (const char __user *)sctx->args[1];
        else
            path_ptr = (const char __user *)sctx->args[0];
        bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), path_ptr);
        evt->fd = (i32)ret;
        evt->flags = (syscall_nr == 2) ? (i32)sctx->args[1] : (i32)sctx->args[2];
        evt->bytes = 0;

        infer_event(evt->header.pid, EVENT_FILE_OPEN,
                    (const char *)evt->filename, 0, 0, 0, 0);
        KS_SUBMIT(evt);
        goto cleanup;
    }

    if (syscall_nr == 42) {
        struct net_event *evt = KS_RESERVE(events, struct net_event);
        if (!evt) goto cleanup;

        fill_header(&evt->header, EVENT_NET_CONNECT);
        evt->header.syscall_nr = 42;
        evt->header.retval = ret;

        evt->saddr = 0;  evt->daddr = 0;
        evt->sport = 0;  evt->dport = 0;
        evt->proto = 0;  evt->family = 0;
        __builtin_memset(evt->saddr6, 0, sizeof(evt->saddr6));
        __builtin_memset(evt->daddr6, 0, sizeof(evt->daddr6));
        evt->_pad3[0]=0;  evt->_pad3[1]=0;

        int fd = (int)sctx->args[0];
        struct sockaddr __user *addr = (struct sockaddr __user *)sctx->args[1];
        struct sockaddr sa;
        if (bpf_probe_read_user(&sa, sizeof(sa), addr) == 0) {
            if (sa.sa_family == 2) {
                struct sockaddr_in sin;
                if (bpf_probe_read_user(&sin, sizeof(sin), addr) == 0) {
                    evt->family = 2;
                    evt->daddr  = sin.sin_addr.s_addr;
                    evt->dport  = bpf_ntohs(sin.sin_port);
                    evt->proto  = 6;
                }
            } else if (sa.sa_family == 10) {
                struct sockaddr_in6 sin6;
                if (bpf_probe_read_user(&sin6, sizeof(sin6), addr) == 0) {
                    evt->family = 10;
                    evt->dport  = bpf_ntohs(sin6.sin6_port);
                    evt->proto  = 6;
                    bpf_probe_read_user(evt->daddr6, sizeof(evt->daddr6), sin6.sin6_addr.in6_u.u6_addr8);
                }
            }
        }

        infer_event(evt->header.pid, EVENT_NET_CONNECT, NULL,
                    evt->daddr, evt->dport, evt->proto, 0);
        KS_SUBMIT(evt);
        goto cleanup;
    }

    if (syscall_nr == 101 && ret >= 0) {
        struct signal_event *evt = KS_RESERVE(events, struct signal_event);
        if (!evt) goto cleanup;

        fill_header(&evt->header, EVENT_PROC_PTRACE);
        evt->header.syscall_nr = 101;
        evt->header.retval = ret;
        evt->target_pid = (u32)sctx->args[1];
        evt->signal = (i32)sctx->args[0];

        infer_event(evt->header.pid, EVENT_PROC_PTRACE, NULL, 0,0,0, evt->target_pid);
        KS_SUBMIT(evt);
        goto cleanup;
    }

    if (syscall_nr == 62 && ret >= 0) {
        struct signal_event *evt = KS_RESERVE(events, struct signal_event);
        if (!evt) goto cleanup;

        fill_header(&evt->header, EVENT_PROC_SIGNAL);
        evt->header.syscall_nr = 62;
        evt->header.retval = ret;
        evt->target_pid = (u32)sctx->args[0];
        evt->signal = (i32)sctx->args[1];

        infer_event(evt->header.pid, EVENT_PROC_SIGNAL, NULL, 0,0,0, evt->target_pid);
        KS_SUBMIT(evt);
        goto cleanup;
    }

cleanup:
    bpf_map_delete_elem(&syscall_ctxs, &pid_tgid);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int trace_sched_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct signal_event *evt = KS_RESERVE(events, struct signal_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_PROCESS_EXEC);
    evt->header.syscall_nr = 59;
    evt->header.retval = 0;
    evt->target_pid = 0;
    evt->signal = 0;

    KS_SUBMIT(evt);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct signal_event *evt = KS_RESERVE(events, struct signal_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_PROCESS_EXIT);
    evt->header.syscall_nr = 0;
    evt->header.retval = 0;
    evt->target_pid = 0;
    evt->signal = 0;

    KS_SUBMIT(evt);
    return 0;
}

#endif // KS_PROBES_SYSCALL_H

#ifndef KS_PROBES_SYSCALL_H
#define KS_PROBES_SYSCALL_H

/* 系统调用号硬编码 x86_64（59/2/257/42/101/62/313 等）：
   换架构时这些 case 会静默失配，宁可编译失败也不要静默漏检 */
#if !defined(__TARGET_ARCH_x86)
#error "ks 探针的系统调用号为 x86_64 硬编码，仅支持 __TARGET_ARCH_x86"
#endif

struct syscall_ctx {
    u64 args[6];
    u64 start_ns;
    u32 pid;
    u32 syscall_nr;
    char exec_args[384];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct syscall_ctx);
} syscall_ctxs SEC(".maps");

struct syscount { u64 enter; u64 exit; u64 drop; };
KS_PERCPU_ARRAY_MAP(syscount_map, struct syscount);

static __always_inline void ks_count_drop(void) {
    u32 k = 0;
    struct syscount *sc = bpf_map_lookup_elem(&syscount_map, &k);
    if (sc) sc->drop++;
}

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(KS_TP_SYS_ENTER *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 syscall_nr = ctx->id;

    {
        u32 _k = 0;
        struct syscount *sc = bpf_map_lookup_elem(&syscount_map, &_k);
        if (sc) sc->enter++;
    }

    switch (syscall_nr) {
    case 59:  case 2:   case 257:
    case 0:   case 1:   case 42:
    case 101: case 62:  case 313:
    /* 8-31 补发射的事件源：rename(82/264/316)/chmod(90/268) 产出 FILE_RENAME/FILE_CHMOD
       事件（勒索批量改名、持久化替换此前完全不可见）；unlink(87)/fchmod(91) 不产事件，
       仅供 freq 计频（FILE_DELETE 事件由 vfs_unlink kprobe 发射，避免重复上报） */
    case 82:  case 87:  case 90:  case 91:
    case 264: case 268: case 316:
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

    if (syscall_nr == 59) {
        const char __user *const *argv_ptr = (const char __user *const *)sctx.args[1];
        if (argv_ptr) {
            const char __user *arg_ptr;
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_ptr[0]) == 0 && arg_ptr)
                bpf_probe_read_user_str(sctx.exec_args,        64, arg_ptr);
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_ptr[1]) == 0 && arg_ptr)
                bpf_probe_read_user_str(sctx.exec_args + 64,   64, arg_ptr);
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_ptr[2]) == 0 && arg_ptr)
                bpf_probe_read_user_str(sctx.exec_args + 128,  64, arg_ptr);
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_ptr[3]) == 0 && arg_ptr)
                bpf_probe_read_user_str(sctx.exec_args + 192, 64, arg_ptr);
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_ptr[4]) == 0 && arg_ptr)
                bpf_probe_read_user_str(sctx.exec_args + 256,  64, arg_ptr);
            if (bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv_ptr[5]) == 0 && arg_ptr)
                bpf_probe_read_user_str(sctx.exec_args + 320,  64, arg_ptr);
        }
    }

    bpf_map_update_elem(&syscall_ctxs, &pid_tgid, &sctx, BPF_ANY);
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit_proc(KS_TP_SYS_EXIT *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_ctx *sctx = bpf_map_lookup_elem(&syscall_ctxs, &pid_tgid);
    if (!sctx) return 0;

    long ret = ctx->ret;
    u32 syscall_nr = sctx->syscall_nr;

    /* 系统调用计数与频率窗口只在 proc 程序做一次（三个程序都会收到同一事件，
     * 若各做一次会三倍计数）。 */
    {
        u32 _k = 0;
        struct syscount *sc = bpf_map_lookup_elem(&syscount_map, &_k);
        if (sc) sc->exit++;
    }
    freq_handle_sys_exit(ctx, syscall_nr);
    /* 注：raw_syscalls/sys_exit 上挂了 3 个程序（proc/file/net）以守住 3.10 的
     * 4096 指令上限（单程序实测 7483 条 → E2BIG）。syscall_ctxs 条目不再在退出侧
     * 删除：键是 pid_tgid，下一次 sys_enter 会覆盖；三程序顺序不确定，任何一方
     * 删除都可能截断其它程序的读取。 */

    if (syscall_nr == 59 && ret >= 0) {
        struct exec_event *evt = KS_RESERVE(events, struct exec_event);
        if (!evt) { ks_count_drop(); goto cleanup; }

        fill_header(&evt->header, EVENT_PROCESS_EXEC);
        evt->header.syscall_nr = 59;
        evt->header.retval = ret;

        const char __user *filename_ptr = (const char __user *)sctx->args[0];
        KS_WRITE_USER_STR(evt->filename, sizeof(evt->filename), filename_ptr);

        __builtin_memcpy(evt->args, sctx->exec_args, sizeof(sctx->exec_args));

        int verdict = infer_event(evt->header.pid, EVENT_PROCESS_EXEC,
                    (const char *)evt->filename, 0, 0, 0, 0);
        KS_MAYBE_BLOCK(evt->header.pid, verdict);
        if (ks_should_drop(evt->header.pid, EVENT_PROCESS_EXEC,
                           (const char *)evt->filename, verdict)) {
            KS_DISCARD(evt); goto cleanup;
        }
        KS_SUBMIT(ctx, events, evt);
        goto cleanup;
    }

    if (syscall_nr == 101 && ret >= 0) {
        struct signal_event *evt = KS_RESERVE(events, struct signal_event);
        if (!evt) { ks_count_drop(); goto cleanup; }

        fill_header(&evt->header, EVENT_PROC_PTRACE);
        evt->header.syscall_nr = 101;
        evt->header.retval = ret;
        evt->target_pid = (u32)sctx->args[1];
        evt->signal = (i32)sctx->args[0];

        int verdict4 = infer_event(evt->header.pid, EVENT_PROC_PTRACE, NULL, 0,0,0, evt->target_pid);
        KS_MAYBE_BLOCK(evt->header.pid, verdict4);
        if (ks_should_drop(evt->header.pid, EVENT_PROC_PTRACE, NULL, verdict4)) {
            KS_DISCARD(evt); goto cleanup;
        }
        KS_SUBMIT(ctx, events, evt);
        goto cleanup;
    }

    if (syscall_nr == 62 && ret >= 0) {
        struct signal_event *evt = KS_RESERVE(events, struct signal_event);
        if (!evt) { ks_count_drop(); goto cleanup; }

        fill_header(&evt->header, EVENT_PROC_SIGNAL);
        evt->header.syscall_nr = 62;
        evt->header.retval = ret;
        evt->target_pid = (u32)sctx->args[0];
        evt->signal = (i32)sctx->args[1];

        int verdict5 = infer_event(evt->header.pid, EVENT_PROC_SIGNAL, NULL, 0,0,0, evt->target_pid);
        KS_MAYBE_BLOCK(evt->header.pid, verdict5);
        if (ks_should_drop(evt->header.pid, EVENT_PROC_SIGNAL, NULL, verdict5)) {
            KS_DISCARD(evt); goto cleanup;
        }
        KS_SUBMIT(ctx, events, evt);
        goto cleanup;
    }

    if (syscall_nr == 313 && ret < 0) {
        struct lkm_load_event *evt = KS_RESERVE(events, struct lkm_load_event);
        if (!evt) { ks_count_drop(); goto cleanup; }

        fill_header(&evt->header, EVENT_LKM_LOAD);
        evt->header.syscall_nr = 313;
        evt->header.retval = ret;
        evt->pid = evt->header.pid;
        evt->uid = evt->header.uid;
        evt->_pad_lkm1 = 0;
        __builtin_memcpy(evt->comm, evt->header.comm, sizeof(evt->comm));
        __builtin_memcpy(evt->module_name, "finit_module", 13);

        KS_SUBMIT(ctx, events, evt);
        goto cleanup;
    }

cleanup:
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit_file(KS_TP_SYS_EXIT *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_ctx *sctx = bpf_map_lookup_elem(&syscall_ctxs, &pid_tgid);
    if (!sctx) return 0;

    long ret = ctx->ret;
    u32 syscall_nr = sctx->syscall_nr;

    if ((syscall_nr == 2 || syscall_nr == 257) && ret >= 0) {
        struct file_event *evt = KS_RESERVE(events, struct file_event);
        if (!evt) { ks_count_drop(); goto cleanup; }

        fill_header(&evt->header, EVENT_FILE_OPEN);
        evt->header.syscall_nr = syscall_nr;
        evt->header.retval = ret;

        const char __user *path_ptr;
        if (syscall_nr == 257)
            path_ptr = (const char __user *)sctx->args[1];
        else
            path_ptr = (const char __user *)sctx->args[0];
        KS_WRITE_USER_STR(evt->filename, sizeof(evt->filename), path_ptr);
        evt->fd = (i32)ret;
        evt->flags = (syscall_nr == 2) ? (i32)sctx->args[1] : (i32)sctx->args[2];
        evt->bytes = 0;

        int verdict2 = infer_event(evt->header.pid, EVENT_FILE_OPEN,
                    (const char *)evt->filename, 0, 0, 0, 0);
        KS_MAYBE_BLOCK(evt->header.pid, verdict2);
        if (ks_should_drop(evt->header.pid, EVENT_FILE_OPEN,
                           (const char *)evt->filename, verdict2)) {
            KS_DISCARD(evt); goto cleanup;
        }
        KS_SUBMIT(ctx, events, evt);
        goto cleanup;
    }

    if ((syscall_nr == 82 || syscall_nr == 264 || syscall_nr == 316) && ret >= 0) {
        struct file_event *evt = KS_RESERVE(events, struct file_event);
        if (!evt) { ks_count_drop(); goto cleanup; }

        fill_header(&evt->header, EVENT_FILE_RENAME);
        evt->header.syscall_nr = syscall_nr;
        evt->header.retval = ret;

        /* filename 记录新路径：勒索软件批量改后缀（x.y → x.y.encrypted）与
           持久化替换（替换 cron/systemd 单元）看的是改名后的名字。
           rename(82) 新路径在 args[1]；renameat/at2(264/316) 在 args[3] */
        const char __user *new_path = (syscall_nr == 82)
            ? (const char __user *)sctx->args[1]
            : (const char __user *)sctx->args[3];
        KS_WRITE_USER_STR(evt->filename, sizeof(evt->filename), new_path);
        evt->bytes = 0;  evt->fd = -1;  evt->flags = 0;

        int verdict_r = infer_event(evt->header.pid, EVENT_FILE_RENAME,
                        (const char *)evt->filename, 0, 0, 0, 0);
        KS_MAYBE_BLOCK(evt->header.pid, verdict_r);
        if (ks_should_drop(evt->header.pid, EVENT_FILE_RENAME,
                           (const char *)evt->filename, verdict_r)) {
            KS_DISCARD(evt); goto cleanup;
        }
        KS_SUBMIT(ctx, events, evt);
        goto cleanup;
    }

    if ((syscall_nr == 90 || syscall_nr == 268) && ret >= 0) {
        struct file_event *evt = KS_RESERVE(events, struct file_event);
        if (!evt) { ks_count_drop(); goto cleanup; }

        fill_header(&evt->header, EVENT_FILE_CHMOD);
        evt->header.syscall_nr = syscall_nr;
        evt->header.retval = ret;

        /* chmod(90) 路径在 args[0]；fchmodat(268) 在 args[1]。
           fchmod(91) 是 fd 描述符，无路径可读，只计频不发事件 */
        const char __user *path_ptr = (syscall_nr == 90)
            ? (const char __user *)sctx->args[0]
            : (const char __user *)sctx->args[1];
        KS_WRITE_USER_STR(evt->filename, sizeof(evt->filename), path_ptr);
        evt->bytes = 0;  evt->fd = -1;  evt->flags = 0;

        int verdict_c = infer_event(evt->header.pid, EVENT_FILE_CHMOD,
                        (const char *)evt->filename, 0, 0, 0, 0);
        KS_MAYBE_BLOCK(evt->header.pid, verdict_c);
        if (ks_should_drop(evt->header.pid, EVENT_FILE_CHMOD,
                           (const char *)evt->filename, verdict_c)) {
            KS_DISCARD(evt); goto cleanup;
        }
        KS_SUBMIT(ctx, events, evt);
        goto cleanup;
    }

cleanup:
    return 0;
}

SEC("tracepoint/raw_syscalls/sys_exit")
int trace_sys_exit_net(KS_TP_SYS_EXIT *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct syscall_ctx *sctx = bpf_map_lookup_elem(&syscall_ctxs, &pid_tgid);
    if (!sctx) return 0;

    long ret = ctx->ret;
    u32 syscall_nr = sctx->syscall_nr;

    if (syscall_nr == 42) {
        struct net_event *evt = KS_RESERVE(events, struct net_event);
        if (!evt) { ks_count_drop(); goto cleanup; }

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
                    KS_WRITE_USER(evt->daddr6, sizeof(evt->daddr6), &sin6.sin6_addr.in6_u.u6_addr8);
                }
            }
        }

        int verdict3 = infer_event(evt->header.pid, EVENT_NET_CONNECT, NULL,
                    evt->daddr, evt->dport, evt->proto, 0);
        KS_MAYBE_BLOCK(evt->header.pid, verdict3);
        if (ks_should_drop(evt->header.pid, EVENT_NET_CONNECT, NULL, verdict3)) {
            KS_DISCARD(evt); goto cleanup;
        }
        KS_SUBMIT(ctx, events, evt);
        goto cleanup;
    }

cleanup:
    return 0;
}

#endif

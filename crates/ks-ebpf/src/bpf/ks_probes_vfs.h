#ifndef KS_PROBES_VFS_H
#define KS_PROBES_VFS_H

/* vmlinux.h（BTF 生成）不含 uapi stat.h 宏，本地补齐 */
#ifndef S_IFMT
#define S_IFMT  0170000
#define S_IFREG 0100000
#endif

static __always_inline int read_full_path(struct path *p, u8 *dst, int dst_len) {
    long ret = KS_D_PATH(dst, dst_len, p);
    if (ret <= 0) {
        /* 树形路径失败时回退为纯文件名 */
        struct dentry *dentry = BPF_CORE_READ(p, dentry);
        const char *name = KS_READ_DNAME(dentry);
        bpf_probe_read_kernel_str((char *)dst, dst_len, name);
        return 0;
    }
    return (int)ret;
}

static __always_inline int read_file_path(struct file *f, u8 *dst, int dst_len) {
    struct path p = BPF_CORE_READ(f, f_path);
    return read_full_path(&p, dst, dst_len);
}

SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe_vfs_open, struct path *path, struct file *file) {
    smart_filter_handle_vfs_open(path);
    return 0;
}

/*
 * vfs_write / vfs_unlink 与 sys_exit 路径对齐：
 * 1) 走 infer_event 风险评分 + KS_MAYBE_BLOCK（enforce 下可实杀）——
 *    旧实现 kprobe 路径完全绕过风控，勒索软件的批量写/删在内核态拿不到阻断判定；
 * 2) 走 ks_should_drop 智能过滤并计入 drop 统计——旧实现绕过过滤也不计数；
 * 3) 路径为多级拼接（见 KS_D_TREE），"/etc/shadow" 这类规则路径可以命中。
 */
SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos) {
    if (count < 1024) return 0;

    struct file_event *evt = KS_RESERVE(events, struct file_event);
    if (!evt) { ks_count_drop(); return 0; }

    fill_header(&evt->header, EVENT_FILE_WRITE);
    evt->header.syscall_nr = 1;
    read_file_path(file, evt->filename, sizeof(evt->filename));
    evt->bytes = count;  evt->fd = 0;  evt->flags = 0;

    int verdict = infer_event(evt->header.pid, EVENT_FILE_WRITE,
                              (const char *)evt->filename, 0, 0, 0, 0);
    KS_MAYBE_BLOCK(evt->header.pid, verdict);
    /* 批量文件操作计数由 infer_event 内部的 infer_bulk_file_ops 完成，勿重复调用 */
    if (ks_should_drop(evt->header.pid, EVENT_FILE_WRITE,
                       (const char *)evt->filename, verdict)) {
        KS_DISCARD(evt);
        return 0;
    }
    KS_SUBMIT(ctx, events, evt);
    return 0;
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(kprobe_vfs_unlink, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode) {
    struct file_event *evt = KS_RESERVE(events, struct file_event);
    if (!evt) { ks_count_drop(); return 0; }

    fill_header(&evt->header, EVENT_FILE_DELETE);
    evt->header.syscall_nr = 87;

    /* 多级路径：目录+文件名，"删 /etc/shadow" 的规则路径可命中 */
    KS_D_TREE(evt->filename, sizeof(evt->filename), dentry);
    evt->bytes = 0;  evt->fd = -1;  evt->flags = 0;

    int verdict = infer_event(evt->header.pid, EVENT_FILE_DELETE,
                              (const char *)evt->filename, 0, 0, 0, 0);
    KS_MAYBE_BLOCK(evt->header.pid, verdict);
    /* 同上：计数在 infer_event 内部完成 */
    if (ks_should_drop(evt->header.pid, EVENT_FILE_DELETE,
                       (const char *)evt->filename, verdict)) {
        KS_DISCARD(evt);
        return 0;
    }
    KS_SUBMIT(ctx, events, evt);
    return 0;
}

/*
 * do_splice_direct 写出侧探针（H-1.3 文件写覆盖缺口）。
 *
 * cp（copy_file_range / sendfile fallback）、cat（splice read→write）、dd oflag=splice
 * 的"读文件→写文件"都经 do_splice_direct 落盘，完全绕过 vfs_write kprobe——
 * 勒索/收集阶段用 cp 打包敏感文件时此前零事件。选它而非 copy_file_range：
 *   - RHEL 3.10 的 copy_file_range 与 sendfile 内部都回落 do_splice_direct，
 *     一个点位覆盖 cp/sendfile/cat 三类来源，且与 vfs_write 无双计
 *     （vfs_copy_file_range 直接走 write 路径的内核新实现不受影响，仍被 vfs_write 捕获）；
 *   - 3.10~6.x 签名稳定：(file_in, pos_in, file_out, pos_out, count, flags)。
 * 噪音控制：只报 file_out 为 regular file 的分支——sendfile 到 socket、管道直通
 * 不落盘，不是文件写事件。低字节段（<1024）不报的门槛与 vfs_write 保持一致，
 * count 字段只在该分支有效（读侧分支的 count 是读取上限，不是写入量）。
 */
SEC("kprobe/do_splice_direct")
int BPF_KPROBE(kprobe_do_splice_direct, struct file *file_in, loff_t *ppos_in,
               struct file *file_out, loff_t *ppos_out, size_t count, unsigned int flags) {
    (void)ppos_in;
    (void)flags;
    /* 显式两步读：直接把 &file_out->f_inode->i_mode 委托给 bpf_core_read 会让验证器
       把中间指针当 scalar（R7 invalid mem access），先读出 inode 再取 i_mode。
       CO-RE tier 用 bpf_core_read（按 BTF 重定位字段偏移）；NOBTF tier 没有
       BPF_CORE_READ 展开（KS_NOREAD_ 白名单无 f_inode），统一走 bpf_probe_read
       + 内嵌 vmlinux.h 的编译期偏移（f_inode 在 file 布局中历代 x86_64 稳定） */
#ifdef KS_NOBTF
    struct inode *out_inode = 0;
    bpf_probe_read(&out_inode, sizeof(out_inode), &file_out->f_inode);
#else
    struct inode *out_inode = BPF_CORE_READ(file_out, f_inode);
#endif
    umode_t mode = 0;
    if (out_inode)
        bpf_core_read(&mode, sizeof(mode), &out_inode->i_mode);
    if ((mode & S_IFMT) != S_IFREG)
        return 0;
    if (count < 1024)
        return 0;

    struct file_event *evt = KS_RESERVE(events, struct file_event);
    if (!evt) { ks_count_drop(); return 0; }

    fill_header(&evt->header, EVENT_FILE_WRITE);
    evt->header.syscall_nr = 1;
    read_file_path(file_out, evt->filename, sizeof(evt->filename));
    evt->bytes = count;  evt->fd = 0;  evt->flags = 0;

    int verdict = infer_event(evt->header.pid, EVENT_FILE_WRITE,
                              (const char *)evt->filename, 0, 0, 0, 0);
    KS_MAYBE_BLOCK(evt->header.pid, verdict);
    if (ks_should_drop(evt->header.pid, EVENT_FILE_WRITE,
                       (const char *)evt->filename, verdict)) {
        KS_DISCARD(evt);
        return 0;
    }
    KS_SUBMIT(ctx, events, evt);
    return 0;
}

#endif

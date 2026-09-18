#ifndef KS_PROBES_VFS_H
#define KS_PROBES_VFS_H

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

#endif

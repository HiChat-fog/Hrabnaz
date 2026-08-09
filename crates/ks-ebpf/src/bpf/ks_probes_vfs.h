#ifndef KS_PROBES_VFS_H
#define KS_PROBES_VFS_H

static __always_inline int read_full_path(struct path *p, u8 *dst, int dst_len) {
    long ret = KS_D_PATH(dst, dst_len, p);
    if (ret < 0) {
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
    /* vfs_open与sys_exit(open/openat)是同一open的两条hook,sys_exit已发
     * EVENT_FILE_OPEN(带完整path+fd+flags),此处再发是冗余双发——是file open
     * 占ringbuf 67%的主因。改为只做内核推理(累加风险分+过滤统计),不submit事件。
     * 事件由sys_exit统一发并经ks_should_drop过滤。vfs_write/vfs_unlink保留submit
     * (sys_exit不覆盖write/unlink的path)。 */
    smart_filter_handle_vfs_open(path);
    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos) {
    if (count < 1024) return 0;

    struct file_event *evt = KS_RESERVE(events, struct file_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_FILE_WRITE);
    evt->header.syscall_nr = 1;
    read_file_path(file, evt->filename, sizeof(evt->filename));
    evt->bytes = count;  evt->fd = 0;  evt->flags = 0;

    infer_bulk_file_ops(evt->header.pid, EVENT_FILE_WRITE);
    KS_SUBMIT(ctx, events, evt);
    return 0;
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(kprobe_vfs_unlink, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode) {
    struct file_event *evt = KS_RESERVE(events, struct file_event);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_FILE_DELETE);
    evt->header.syscall_nr = 87;

    const char *name = KS_READ_DNAME(dentry);
    bpf_probe_read_kernel_str((char *)evt->filename, sizeof(evt->filename), name);
    evt->bytes = 0;  evt->fd = -1;  evt->flags = 0;

    infer_bulk_file_ops(evt->header.pid, EVENT_FILE_DELETE);
    KS_SUBMIT(ctx, events, evt);
    return 0;
}

#endif // KS_PROBES_VFS_H

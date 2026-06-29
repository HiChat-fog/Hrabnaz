// VFS 探针 — kprobe/vfs_open, kprobe/vfs_write, kprobe/vfs_unlink
#include "common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int read_full_path(struct path *p, u8 *dst, int dst_len) {
    long ret = bpf_d_path(p, (char *)dst, dst_len);
    if (ret < 0) {
        struct dentry *dentry = BPF_CORE_READ(p, dentry);
        const char *name = BPF_CORE_READ(dentry, d_name.name);
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
    struct file_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct file_event), 0);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_FILE_OPEN);
    evt->header.syscall_nr = 2;
    read_full_path(path, evt->filename, sizeof(evt->filename));
    evt->fd = -1;  evt->bytes = 0;  evt->flags = 0;

    infer_sensitive_file((const char *)evt->filename, evt->header.pid);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos) {
    if (count < 1024) return 0;

    struct file_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct file_event), 0);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_FILE_WRITE);
    evt->header.syscall_nr = 1;
    read_file_path(file, evt->filename, sizeof(evt->filename));
    evt->bytes = count;  evt->fd = 0;  evt->flags = 0;

    infer_bulk_file_ops(evt->header.pid, EVENT_FILE_WRITE);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(kprobe_vfs_unlink, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode) {
    struct file_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct file_event), 0);
    if (!evt) return 0;

    fill_header(&evt->header, EVENT_FILE_DELETE);
    evt->header.syscall_nr = 87;

    const char *name = BPF_CORE_READ(dentry, d_name.name);
    bpf_probe_read_kernel_str((char *)evt->filename, sizeof(evt->filename), name);
    evt->bytes = 0;  evt->fd = -1;  evt->flags = 0;

    infer_bulk_file_ops(evt->header.pid, EVENT_FILE_DELETE);
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
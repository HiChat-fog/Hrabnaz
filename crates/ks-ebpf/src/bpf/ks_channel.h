#ifndef KS_CHANNEL_H
#define KS_CHANNEL_H

/* ── 跨进程裁决通道：block_decisions 查表与保护名单 ──
   用户态（引擎自动裁决 / ks block 独立进程经 bpffs pin）写入，
   探针在 syscall 路径查表。这是 map 布局层面的公共契约：
   key 8B = pid+pad，value 16B = expire_mono(8)+reason(1)+pad(7)，
   与用户态 linux_map_reader.rs / blocker.rs 逐字节对齐。
   Modern tier 命中即 bpf_send_signal；Legacy/Ancient 只置返回值，
   实杀由用户态 killer 补（非 Modern 无 bpf_send_signal）。 */

struct block_key { u32 pid; u32 _pad_blk; };
struct block_value {
    u64 expire_ns;
    u8  reason;
    u8  _pad_bv[7];
};

KS_LRU_HASH_MAP(block_decisions, struct block_key, struct block_value, 4096);

KS_LRU_HASH_MAP(protected_pids, u32, u8, 256);

struct comm_key { char comm[16]; };
KS_LRU_HASH_MAP(protected_comms, struct comm_key, u8, 64);

#if KS_RINGBUF
static __always_inline int ks_current_protected(void) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u8 *p = bpf_map_lookup_elem(&protected_pids, &tgid);
    return p && *p == 1;
}

static __always_inline int ks_comm_protected(void) {
    struct comm_key ck = {};
    bpf_get_current_comm(&ck.comm, sizeof(ck.comm));
    u8 *p = bpf_map_lookup_elem(&protected_comms, &ck);
    return p && *p == 1;
}

static __always_inline int ks_check_block(u32 pid) {
    struct block_key bk = { .pid = pid, ._pad_blk = 0 };
    struct block_value *bv = bpf_map_lookup_elem(&block_decisions, &bk);
    if (!bv) return 0;
    if (bv->expire_ns == 0 || bpf_ktime_get_ns() < bv->expire_ns) {
        if (!ks_current_protected() && !ks_comm_protected())
            bpf_send_signal(9);
        return 1;
    }
    return 0;
}
#else
static __always_inline int ks_check_block(u32 pid) {
    struct block_key bk = { .pid = pid, ._pad_blk = 0 };
    struct block_value *bv = bpf_map_lookup_elem(&block_decisions, &bk);
    if (!bv) return 0;
    if (bv->expire_ns == 0 || bpf_ktime_get_ns() < bv->expire_ns) {
        return 1;
    }
    return 0;
}
#endif

#endif

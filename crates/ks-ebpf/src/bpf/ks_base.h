#ifndef KS_BASE_H
#define KS_BASE_H

/* ── 探针挂载层的基础设施：编译开关、tier 适配、路径/事件发射宏 ──
   只提供机制，不含任何检测语义；上层为 ks_state/ks_channel/ks_semantics/ks_events */

#ifndef __user
#define __user
#endif

/* ancient 与 nobtf 变体用本地 tracepoint ctx 结构体：这些运行在 3.10/4.x 上，
   (a) 老内核 BTF 没有 trace_event_raw_* 类型，用 vmlinux.h 的类型会让 aya 把重定位
       静默毒化成 jmp 0xBAD2310，验证器拒绝整个程序；
   (b) nobtf 对象本就剥离了 .BTF.ext，没有重定位，只能靠编译期偏移。
   布局取自 3.10/4.x 的 tracefs format。modern/legacy 仍走 CO-RE：v6.15 起
   sched_process_fork 的 comm 改成了 __string()，parent_pid 从 24 移到 12，
   硬编码在这些内核上会读错字段，必须由重定位按目标内核布局改写。 */
#if defined(KS_TIER_ANCIENT) || defined(KS_NOBTF)
struct ks_tp_sys_enter { u16 type; u8 flags; u8 preempt_count; s32 pid; s64 id; u64 args[6]; };
struct ks_tp_sys_exit  { u16 type; u8 flags; u8 preempt_count; s32 pid; s64 id; s64 ret; };
struct ks_tp_sched_fork { u16 type; u8 flags; u8 preempt_count; s32 pid; char parent_comm[16]; s32 parent_pid; char child_comm[16]; s32 child_pid; };
struct ks_tp_sched_exec { u16 type; u8 flags; u8 preempt_count; s32 pid; s32 __data_loc_filename; s32 new_pid; s32 old_pid; };
struct ks_tp_sched_exit { u16 type; u8 flags; u8 preempt_count; s32 pid; char comm[16]; s32 exit_pid; s32 prio; };
#define KS_TP_SYS_ENTER     struct ks_tp_sys_enter
#define KS_TP_SYS_EXIT      struct ks_tp_sys_exit
#define KS_TP_SCHED_FORK    struct ks_tp_sched_fork
#define KS_TP_SCHED_EXEC    struct ks_tp_sched_exec
#define KS_TP_SCHED_EXIT    struct ks_tp_sched_exit
#else
#define KS_TP_SYS_ENTER     struct trace_event_raw_sys_enter
#define KS_TP_SYS_EXIT      struct trace_event_raw_sys_exit
#define KS_TP_SCHED_FORK    struct trace_event_raw_sched_process_fork
#define KS_TP_SCHED_EXEC    struct trace_event_raw_sched_process_exec
#define KS_TP_SCHED_EXIT    struct trace_event_raw_sched_process_template
#endif

typedef __s32 i32;
typedef __s64 i64;

#if defined(KS_TIER_MODERN)
    #define KS_RINGBUF   1
    #define KS_LRU_HASH  1
#elif defined(KS_TIER_LEGACY)
    #define KS_RINGBUF   0
    #define KS_LRU_HASH  1
#elif defined(KS_TIER_ANCIENT)
    #define KS_RINGBUF   0
    #define KS_LRU_HASH  0
#else
    #define KS_RINGBUF   1
    #define KS_LRU_HASH  1
#endif

/* read_kernel/read_user 的 user/kernel 拆分是 5.5+ 才有的 helper：
   4.x（无论走不走 BTF）与 3.10 都必须回退 bpf_probe_read，
   否则 legacy tier 在 4.19 上加载时 helper 不存在直接失败 */
#if !defined(KS_TIER_MODERN)
    #define bpf_probe_read_kernel       bpf_probe_read
    #define bpf_probe_read_kernel_str   bpf_probe_read_str
    #define bpf_probe_read_user         bpf_probe_read
    #define bpf_probe_read_user_str     bpf_probe_read_str
#endif

#ifdef KS_NOBTF
    #undef BPF_CORE_READ

    #define KS_OFF_SOCK_COMMON         0
    #define KS_OFF_PATH_DENTRY         8
    #define KS_OFF_DENTRY_DNAME_NAME   40
    /* d_parent 在 3.10/4.19 x86_64 均为 24：d_flags(4)+d_seq(4)+d_hash(16) */
    #define KS_OFF_DENTRY_D_PARENT     24
    #define KS_OFF_FILE_FPATH          16
    #define KS_OFF_SIN6_PORT           2
    /* struct cred 前缀布局（usage 后紧跟 uid）在 3.10/4.19 稳定：
       usage(0-4) uid(4-8) gid(8-12) suid(12-16) sgid(16-20) euid(20-24) */
    #define KS_OFF_CRED_UID            4
    #define KS_OFF_CRED_EUID           20

    #if defined(KS_TIER_LEGACY)
        #define KS_OFF_INET_SADDR          728
        #define KS_OFF_INET_SPORT          736
    #elif defined(KS_TIER_ANCIENT)
        #define KS_OFF_INET_SADDR          776
        #define KS_OFF_INET_SPORT          784
    #else
        #error "KS_NOBTF 需要 KS_TIER_LEGACY 或 KS_TIER_ANCIENT 之一确定 inet offset"
    #endif

    #define BPF_CORE_READ(ptr, field) KS_NOREAD_##field(ptr)

    #define KS_NOREAD_inet_saddr(ptr)   ({ u32 _v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_INET_SADDR); _v; })
    #define KS_NOREAD_inet_sport(ptr)   ({ u16 _v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_INET_SPORT); _v; })
    #define KS_NOREAD___sk_common(ptr)  ({ struct sock_common _v={}; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_SOCK_COMMON); _v; })
    #define KS_NOREAD_dentry(ptr)       ({ struct dentry *_v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_PATH_DENTRY); _v; })
    #define KS_NOREAD_d_parent(ptr)     ({ struct dentry *_v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_DENTRY_D_PARENT); _v; })
    #define KS_NOREAD_f_path(ptr)       ({ struct path _v={}; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_FILE_FPATH); _v; })
    #define KS_NOREAD_sin6_port(ptr)    ({ u16 _v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_SIN6_PORT); _v; })
    #define KS_NOREAD_uid(ptr)          ({ u32 _v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_CRED_UID); _v; })
    #define KS_NOREAD_euid(ptr)         ({ u32 _v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_CRED_EUID); _v; })

    #define KS_READ_DNAME(ptr) ({ const char *_v=0; bpf_probe_read(&_v,sizeof(_v),(char*)(ptr)+KS_OFF_DENTRY_DNAME_NAME); _v; })
#else
    #define KS_READ_DNAME(ptr) BPF_CORE_READ(ptr, d_name.name)
#endif

/*
 * KS_D_APPEND_LEVEL：把一级目录名（24B 定长块，含 NUL+零填充）写到 dst[pos]，
 * 并用 '/' 覆盖其 NUL。定长块拷贝保证 __builtin_memcpy 尺寸是编译期常量
 * （BPF 不支持变长 memcpy）。空间不够时置 pos=-1，后续层级自动跳过
 *
 * 下标一律用无符号并显式钳制 nlen：nlen 是 bpf_probe_read_kernel_str 的返回值，
 * 在验证器眼里是无界的，累加后做有符号转换会让 3.10/4.x 的老验证器推不出边界
 * （"map_value pointer be out of bounds"），整个程序被拒。
 */
#define KS_D_APPEND_LEVEL(dst, pos, nbuf, nlen, dst_len) do { \
    if ((pos) >= 0) { \
        u32 _p = (u32)(pos); \
        u32 _n = (u32)(nlen); \
        if (_n > (u32)sizeof(nbuf) - 1) _n = (u32)sizeof(nbuf) - 1; \
        if (_n == 0 || (nbuf)[0] == '/') { \
            /* 根目录的 d_name 是 "/"（旧内核为空串）：只落一个 '/'，不加分隔符。\
               旧实现照常追加名字+分隔符，路径头变成 "//etc/..."——真机实测\
               kprobe 写事件 3223/3223 条全部双斜杠，starts_with("/boot")、\
               "^/var/log/" 类锚定规则在写/删事件上全部失配 */ \
            if (_p == 0 && _p + 2 <= (u32)(dst_len)) { \
                (dst)[0] = '/'; \
                (pos) = 1; \
            } \
            /* 中间层级出现根名（不应发生）：跳过该级，保持已有前缀 */ \
        } else { \
            u32 _need = (u32)sizeof(nbuf) + 24; \
            if (_p + _need <= (u32)(dst_len)) { \
                __builtin_memcpy((dst) + _p, (nbuf), sizeof(nbuf)); \
                (dst)[_p + _n] = '/'; \
                (pos) = (int)(_p + _n + 1); \
            } else { \
                (pos) = -1; \
            } \
        } \
    } \
} while (0)

/*
 * KS_D_TREE：从 dentry 沿 d_parent 向上最多走 4 级，拼出
 * "/祖先/…/父目录/文件名" 形式的路径。
 * 旧实现只读 d_name.name 末段："/etc/shadow" 拿到的是 "shadow"，
 * 规则里 FilenameContains("/etc/shadow")、"^/var/log/" 这类
 * 带目录的路径判断在 kprobe 路径上全部失效。
 * d_parent==自身 表示已到挂载点根部，停止上溯。
 * 返回写入 dst 的字节数；读不到名字返回 0（调用方自行回退）。
 */
#define KS_D_TREE(dst, dst_len, dent) ({ \
    char _n0[24] = {}, _n1[24] = {}, _n2[24] = {}, _n3[24] = {}, _n4[24] = {}; \
    struct dentry *_d0 = (dent); \
    const char *_c0 = _d0 ? KS_READ_DNAME(_d0) : 0; \
    long _l0 = _c0 ? bpf_probe_read_kernel_str(_n0, sizeof(_n0), _c0) : -1; \
    struct dentry *_d1 = (_l0 > 0) ? BPF_CORE_READ(_d0, d_parent) : 0; \
    int _h1 = (_d1 && _d1 != _d0) ? 1 : 0; \
    const char *_c1 = _h1 ? KS_READ_DNAME(_d1) : 0; \
    long _l1 = _c1 ? bpf_probe_read_kernel_str(_n1, sizeof(_n1), _c1) : -1; \
    _h1 = (_h1 && _l1 > 0) ? 1 : 0; \
    struct dentry *_d2 = _h1 ? BPF_CORE_READ(_d1, d_parent) : 0; \
    int _h2 = (_d2 && _d2 != _d1) ? 1 : 0; \
    const char *_c2 = _h2 ? KS_READ_DNAME(_d2) : 0; \
    long _l2 = _c2 ? bpf_probe_read_kernel_str(_n2, sizeof(_n2), _c2) : -1; \
    _h2 = (_h2 && _l2 > 0) ? 1 : 0; \
    struct dentry *_d3 = _h2 ? BPF_CORE_READ(_d2, d_parent) : 0; \
    int _h3 = (_d3 && _d3 != _d2) ? 1 : 0; \
    const char *_c3 = _h3 ? KS_READ_DNAME(_d3) : 0; \
    long _l3 = _c3 ? bpf_probe_read_kernel_str(_n3, sizeof(_n3), _c3) : -1; \
    _h3 = (_h3 && _l3 > 0) ? 1 : 0; \
    struct dentry *_d4 = _h3 ? BPF_CORE_READ(_d3, d_parent) : 0; \
    int _h4 = (_d4 && _d4 != _d3) ? 1 : 0; \
    const char *_c4 = _h4 ? KS_READ_DNAME(_d4) : 0; \
    long _l4 = _c4 ? bpf_probe_read_kernel_str(_n4, sizeof(_n4), _c4) : -1; \
    _h4 = (_h4 && _l4 > 0) ? 1 : 0; \
    int _pos = 0; \
    if (_h4) KS_D_APPEND_LEVEL((dst), _pos, _n4, (int)(_l4 - 1), (dst_len)); \
    if (_h3) KS_D_APPEND_LEVEL((dst), _pos, _n3, (int)(_l3 - 1), (dst_len)); \
    if (_h2) KS_D_APPEND_LEVEL((dst), _pos, _n2, (int)(_l2 - 1), (dst_len)); \
    if (_h1) KS_D_APPEND_LEVEL((dst), _pos, _n1, (int)(_l1 - 1), (dst_len)); \
    ({ \
        u32 _n0len = (u32)(_l0 - 1); \
        int _out = 0; \
        if (_l0 > 0) { \
            if (_n0len > (u32)sizeof(_n0) - 1) _n0len = (u32)sizeof(_n0) - 1; \
            if (_pos >= 0 && _pos + (int)sizeof(_n0) <= (int)(dst_len)) { \
                __builtin_memcpy((dst) + _pos, _n0, sizeof(_n0)); \
                _out = _pos + (int)_n0len; \
                ((char *)(dst))[_out] = 0; \
            } else if (_pos < 0) { \
                /* 全路径放不下：退化为纯文件名 */ \
                __builtin_memcpy((dst), _n0, sizeof(_n0)); \
                _out = (int)_n0len; \
            } \
        } \
        _out; \
    }); \
})

/* KS_D_PATH：struct path* 入口的树形路径（语义同 KS_D_TREE） */
#define KS_D_PATH(buf, buf_len, path_ptr) ({ \
    struct dentry *_d = BPF_CORE_READ((path_ptr), dentry); \
    KS_D_TREE((buf), (buf_len), _d); \
})

#if KS_LRU_HASH
    #define KS_LRU_HASH_MAP(name, key_type, value_type, cap) \
        struct { \
            __uint(type, BPF_MAP_TYPE_LRU_HASH); \
            __type(key, key_type); \
            __type(value, value_type); \
            __uint(max_entries, cap); \
        } name SEC(".maps")
#else
    #define KS_LRU_HASH_MAP(name, key_type, value_type, cap) \
        struct { \
            __uint(type, BPF_MAP_TYPE_HASH); \
            __type(key, key_type); \
            __type(value, value_type); \
            __uint(max_entries, cap); \
        } name SEC(".maps")
#endif

#if KS_LRU_HASH
    #define KS_PERCPU_ARRAY_MAP(name, value_type) \
        struct { \
            __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); \
            __uint(max_entries, 1); \
            __type(key, u32); \
            __type(value, value_type); \
        } name SEC(".maps")
    #define KS_PERCPU_KEY() ((u32)0)
#else
    #define KS_PERCPU_ARRAY_MAP(name, value_type) \
        struct { \
            __uint(type, BPF_MAP_TYPE_ARRAY); \
            __uint(max_entries, 256); \
            __type(key, u32); \
            __type(value, value_type); \
        } name SEC(".maps")
    #define KS_PERCPU_KEY() ((u32)bpf_get_smp_processor_id())
#endif

#if KS_RINGBUF
    #define KS_EVENT_MAP(name, size) \
        struct { \
            __uint(type, BPF_MAP_TYPE_RINGBUF); \
            __uint(max_entries, size); \
        } name SEC(".maps")
#else
    #define KS_EVENT_MAP(name, size) \
        struct { \
            __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
            __uint(max_entries, 256); \
            __type(key, i32); \
            __type(value, u32); \
        } name SEC(".maps")
#endif

#if KS_RINGBUF
    #define KS_RESERVE(buf, type) ((type *)bpf_ringbuf_reserve(&(buf), sizeof(type), 0))
    #define KS_SUBMIT(ctx, buf, evt) bpf_ringbuf_submit((evt), 0)
    #define KS_DISCARD(evt) bpf_ringbuf_discard((evt), 0)
#else
    KS_PERCPU_ARRAY_MAP(ks_scratch, u8[1024]);

    #define KS_RESERVE(buf, type) ({ \
        u32 _k = KS_PERCPU_KEY(); \
        (type *)bpf_map_lookup_elem(&ks_scratch, &_k); \
    })
    #define KS_SUBMIT(ctx, buf, evt) \
        bpf_perf_event_output((ctx), &(buf), BPF_F_CURRENT_CPU, (evt), sizeof(*(evt)))
    #define KS_DISCARD(evt) ((void)(evt))
#endif

#define EVENT_UNKNOWN       0
#define EVENT_PROCESS_EXEC  1
#define EVENT_PROCESS_EXIT  2
#define EVENT_PROCESS_CLONE 3
#define EVENT_FILE_OPEN     10
#define EVENT_FILE_READ     11
#define EVENT_FILE_WRITE    12
#define EVENT_FILE_DELETE   13
#define EVENT_FILE_RENAME   14
#define EVENT_FILE_CHMOD    15
#define EVENT_NET_CONNECT   20
#define EVENT_NET_ACCEPT    21
#define EVENT_NET_SEND      22
#define EVENT_NET_RECV      23
#define EVENT_NET_DNS       24
#define EVENT_PROC_PTRACE   30
#define EVENT_PROC_SIGNAL   31

#define EVENT_CONTAINER_ESCAPE 80
#define EVENT_LKM_LOAD         81
#define EVENT_EBPF_TAMPER      82

#endif

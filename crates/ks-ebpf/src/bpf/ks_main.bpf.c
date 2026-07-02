// KernelSentinel — 合并入口（ks_main.bpf.c）
//
// 所有 8 个原 .bpf.c 探针文件已合并为单一编译单元。
// - 共享 events ringbuf（syscall/vfs/net 探针共用）
// - 共享 risk_scores/ip_whitelist/net_conn_history/freq_counters/infer_config maps
//   （来自 common.h，跨探针风险累积现在生效）
// - 5 个 ringbuf：events（共享）+ tree_events + freq_events + flow_events + filter_events
//
// 条件编译：build.rs 注入 -DKS_TIER_MODERN / -DKS_TIER_LEGACY / -DKS_TIER_ANCIENT
// 当前 Phase A 仅实现 KS_TIER_MODERN（ringbuf 路径）。
// Phase B/C 将实现 perfbuf 路径（KS_RESERVE/KS_SUBMIT 的 perf_event_array 分支）。

#include "common.h"

/* ── 共享事件 ringbuf（syscall/vfs/net 探针共用，1MB 容量）── */
KS_EVENT_MAP(events, 1024 * 1024);

/* ── 探针函数体（来自原 .bpf.c，已移除 map 声明和 LICENSE）── */
#include "ks_probes_syscall.h"
#include "ks_probes_vfs.h"
#include "ks_probes_net.h"
#include "ks_probes_process_tree.h"
#include "ks_probes_freq.h"
#include "ks_probes_netflow.h"
#include "ks_probes_smart_filter.h"

char LICENSE[] SEC("license") = "GPL";

// KernelSentinel - 合并入口(ks_main.bpf.c)
//
// 所有8个原.bpf.c探针文件已合并为单一编译单元。
// - 共享events ringbuf(syscall/vfs/net探针共用)
// - 共享risk_scores/ip_whitelist/net_conn_history/freq_counters/infer_config maps
//   (来自common.h,跨探针风险累积现在生效)
// - 5个ringbuf:events(共享)+tree_events+freq_events+flow_events+filter_events
//
// 条件编译:build.rs注入-DKS_TIER_MODERN / -DKS_TIER_LEGACY / -DKS_TIER_ANCIENT
// 当前仅实现KS_TIER_MODERN(ringbuf路径)。
// 后续将实现perfbuf路径(KS_RESERVE/KS_SUBMIT的perf_event_array分支)。

#include "common.h"

/* 共享事件ringbuf(syscall/vfs/net探针共用)。加大到16MB减少高压drop,
 * 5.15压测显示1MB时ringbuf_drop达38%(内核捕获52万/s但丢640万/32s)。 */
KS_EVENT_MAP(events, 16 * 1024 * 1024);

/* 探针函数体(来自原.bpf.c,已移除map声明和LICENSE)
 * include顺序:freq/netflow/smart_filter的inline helper必须在
 * syscall/vfs/net主探针之前,以便主探针调用这些helper */
#include "ks_probes_freq.h"
#include "ks_probes_netflow.h"
#include "ks_probes_smart_filter.h"
#include "ks_probes_syscall.h"
#include "ks_probes_vfs.h"
#include "ks_probes_net.h"
#include "ks_probes_process_tree.h"
#include "ks_probes_container.h"
#include "ks_probes_lkm.h"
#include "ks_probes_self_protect.h"

char LICENSE[] SEC("license") = "GPL";

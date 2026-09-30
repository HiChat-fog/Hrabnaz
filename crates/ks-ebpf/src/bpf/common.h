#ifndef KS_COMMON_H
#define KS_COMMON_H

/* 分层聚合头：探针代码（ks_probes_*.h）只 include 本文件。
   四层按依赖序排列，逻辑边界在此，物理上仍编进同一个 .o
   （逻辑解耦、物理混合——未来要抽独立底座时按此边界切）：
     ks_base      编译开关 / tier 适配 / 路径与发射宏（探针挂载层的基础设施）
     ks_state     内核态原语：进程树 / TCP 流 / 频率计数 / 风险分（状态维护）
     ks_channel   跨进程裁决通道：block_decisions 查表 + 保护名单（map 即契约）
     ks_semantics 检测语义：infer_* 风险映射 + KS_MAYBE_BLOCK 实杀决策
     ks_events    事件契约：发往用户态的结构与发射辅助
   依赖方向：base → state/channel → semantics，events 独立；
   探针挂载层（各 probe 头）只消费以上各层，不被以上各层依赖。 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "ks_base.h"
#include "ks_state.h"
#include "ks_channel.h"
#include "ks_semantics.h"
#include "ks_events.h"

#endif

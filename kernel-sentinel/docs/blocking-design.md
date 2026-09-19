# 内核哨兵 — 阻断机制设计文档 (G2.1 / G2.2)

> 本文档定义 KernelSentinel 的阻断机制：内核态 eBPF 阻断（G2.1）与
> 用户态 `BlockManager` 阻断通道（G2.2）。涵盖数据结构、Tier 差异、
> 决策流程、安全考量与测试覆盖。
>
> ⚠️ 2026-08-31 更新：按当前代码修正了 KS_ENFORCE 门控体系、AGATTACH 分支数量、
> "用户态写内核 map"不存在的闭环、以及不存在的 CLI 子命令。
>
> 关联代码：
> - `crates/ks-ebpf/src/bpf/common.h`（`block_decisions` map、`KS_MAYBE_BLOCK` 宏、`KS_ENFORCE` 门控）
> - `crates/ks-ebpf/src/bpf/ks_probes_syscall.h`（`trace_sys_exit` 内的 5 个决策分支）
> - `crates/ks-engine/src/blocker.rs`（`BlockManager` 实现，纯用户态）
> - `crates/ks-server/src/routes.rs`（REST 端点）
> - `crates/ks-cli/src/cmds/start.rs`（告警触发阻断入口）

## 1. 设计目标

| 目标 | 说明 |
|------|------|
| 即时性 | 高风险事件在内核态直接 `bpf_send_signal(SIGKILL)`，无需用户态往返 |
| 兼容性 | Modern（5.8+，`KS_RINGBUF=1`）支持实杀；Legacy/Ancient 仅查表，由用户态补齐 |
| 可撤销 | 用户态 `BlockManager` 维护 TTL，支持手动 `unblock_pid` 与过期清理 |
| 可观测 | 阻断决策带 `reason` 编码与 `trigger` 字符串，便于审计与回溯 |
| 安全降级 | 默认 monitor 模式；enforce 必须显式 `KS_ENFORCE=1` + 冷启动防护（保护名单/干跑期/kill 阈值） |

## 2. 架构概览

```
        ┌────────────────────────── 内核态 (eBPF) ──────────────────────────┐
        │                                                                  │
   syscall exit (tracepoint, 1 个程序内 5 个分支)                           │
        │                                                                  │
        ▼                                                                  │
  ┌──────────────┐    verdict=2     ┌─────────────────────────────┐    │
  │ infer_event()│ ───────────────► │ KS_MAYBE_BLOCK(pid,verdict) │    │
  └──────────────┘                   │                             │    │
                                     │  Modern+enforce: 判门控后   │    │
                                     │    bpf_send_signal(9)      │    │
                                     │    + ks_check_block()      │    │
                                     │  Legacy/Ancient: 只查表    │    │
                                     └──────────┬──────────────────┘    │
                                                │ 查询                    │
                                                ▼                        │
                                   ┌─────────────────────────┐         │
                                   │ block_decisions LRU_HASH │         │
                                   │  key=pid value={expire, │         │
                                   │  reason}  (4096 entries) │         │
                                   └─────────────────────────┘         │
        └───────────────────────────────────────────────────────────────┘
                ▲  ⚠️ 用户态从不写 block_decisions map（见 §5）
        ┌───────┴────────── 用户态 ───────────────────────────────────────┐
        │                                                                  │
        │   ┌────────────────────────────────────────────┐                │
        │   │ BlockManager (blocker.rs) — 纯内存 HashMap  │                │
        │   │  block_pid/unblock_pid/is_blocked/...      │                │
        │   └───────▲────────────▲──────────────────────┘                 │
        │           │            │                                        │
        │   start.rs 触发    REST API（无 CLI 子命令）                     │
        │   (规则/关联告警)  (POST/DELETE/GET /api/v1/block*)              │
        └──────────────────────────────────────────────────────────────────┘
```

职责划分：内核态负责"enforce 模式下的即时处决 + block_decisions 查表"，用户态负责
"决策记录 + TTL 管理 + 对外接口"。**两条通道不联动**——用户态表不写回内核 map。

## 3. 内核态阻断

### 3.1 `block_decisions` LRU_HASH map

定义于 `crates/ks-ebpf/src/bpf/common.h`：

```c
struct block_key { u32 pid; u32 _pad_blk; };
struct block_value {
    u64 expire_ns;   // 0 = 永久阻断；否则 bpf_ktime_get_ns() < expire_ns 阻断
    u8  reason;      // 与用户态 BlockReason 对齐：1..5
    u8  _pad_bv[7];
};

KS_LRU_HASH_MAP(block_decisions, struct block_key, struct block_value, 4096);
```

`expire_ns` 使用 `bpf_ktime_get_ns()` 语义。`reason` 编码：`1=RuleMatch / 2=BaselineDeviation / 3=MlAnomaly / 4=Correlation / 5=Manual`。
⚠️ 该 map 当前**无用户态写入点**（见 §5 差异说明），仅内核查询 + loader/API 读取展示。

### 3.2 `KS_MAYBE_BLOCK` 宏与 Tier / enforce 门控

```c
/* Modern tier (KS_RINGBUF=1, 内核 5.8+) */
#define KS_MAYBE_BLOCK(pid, verdict) do { \
    if (get_config(CFG_ENFORCE_MODE,0)==1 && (verdict)==2) { \
        /* 干跑期未过则不杀 */ \
        u32 _warmup = get_config(CFG_ENFORCE_WARMUP_UNTIL_SEC, 0); \
        /* risk ≥ kill_thr(默认70) 才杀 */ \
        u32 _kill_thr = get_config(CFG_ENFORCE_KILL_THRESHOLD, 70); \
        /* 保护名单豁免 + exe_path 反伪装 */ \
        if (!ks_current_protected()) bpf_send_signal(9); \
    } \
    ks_check_block((pid)); \
} while (0)

/* Legacy / Ancient tier — 从不发信号，只查表标记 */
#define KS_MAYBE_BLOCK(pid, verdict) do { \
    (void)(verdict); \
    ks_check_block((pid)); \
} while (0)
```

**关键门控（8-30 后代码事实，旧文档"verdict==2 立即 SIGKILL"不成立）**：

1. `CFG_ENFORCE_MODE==1`：由用户态 loader 在 `KS_ENFORCE=1` 时写 `infer_config[5]` 开启；默认 0（**monitor 只告警不杀**）。
2. 干跑期：`infer_config[6]` = boot 秒数 + `KS_ENFORCE_WARMUP_SEC`（默认 120s），未过则不杀（冷启动防护）。
3. kill 阈值：`infer_config[7]` 默认 70（`KS_ENFORCE_KILL_THRESHOLD` 可覆盖）——verdict==2 隐含 risk≥70，但阈值可调。
4. 豁免：`protected_pids`（自身 pid + 祖先链 ≤8 跳 + pid 1）或（`protected_comms` 命中 且
   exe_path 不在 /tmp、/dev/shm、/var/tmp）——防误杀自身与关键系统进程。

`ks_check_block()` 查询 `block_decisions` map，命中且未过期则：
- **Modern**：调用 `bpf_send_signal(9)` 立即 SIGKILL（受 `ks_current_protected()` 豁免保护），返回 1。
- **Legacy/Ancient**：仅返回 1（命中标记），不主动发信号。

### 3.3 verdict 语义

`infer_event()` 返回值：`0=放行 / 1=告警 / 2=阻断`。仅当 **enforce 开启且未过干跑期且非保护名单**
时，`verdict==2` 才在 Modern tier 触发即时 `bpf_send_signal`；map 命中则无视 verdict 直接判
SIGKILL（持久决策优先于单次推断，同样受豁免保护）。

### 3.4 调用分支（1 个 tracepoint 内的 5 个决策分支）

⚠️ 旧文档写"5 个 syscall exit 探针"——实际是**单个 `trace_sys_exit` tracepoint 程序内的 5 个分支**
（`raw_syscalls/sys_enter` 白名单跟踪的 9 个 syscall 之一部分）：

| 决策分支 | syscall | 事件类型 | 说明 |
|---------|---------|----------|------|
| exec | 59 | `EVENT_PROCESS_EXEC` | 仅 59（execve）；execveat(322) 不在白名单 |
| open | 2 / 257 | `EVENT_FILE_OPEN` | open / openat |
| connect | 42 | `EVENT_NET_CONNECT` | 仅 connect（412 不在白名单） |
| ptrace | 101 | `EVENT_PROC_PTRACE` | 仅 ptrace |
| kill | 62 | `EVENT_PROC_SIGNAL` | 仅 kill（tgkill=234 不在白名单） |

sys_enter 还跟踪 read(0)/write(1)/finit_module(313)（313 失败时发 LKM 事件），但不参与阻断分支。
每个分支在 `infer_event()` 后立即调用 `KS_MAYBE_BLOCK(pid, verdict)`，阻断决策在事件提交 ringbuf 之前生效。

## 4. 用户态阻断

### 4.1 BlockManager

定义于 `crates/ks-engine/src/blocker.rs`，维护**纯内存**的 `HashMap<u32, BlockedPid>`：

```rust
pub struct BlockedPid {
    pub pid: u32,
    pub blocked_at_ns: u64,   // UNIX 纳秒
    pub expiry_ns: u64,       // 0 = 永久
    pub reason: BlockReason,
    pub trigger: String,      // 触发规则名 / 告警标题
}
```

核心方法：`block_pid` / `unblock_pid` / `is_blocked` / `list_blocked` /
`cleanup_expired`。`enabled=false` 时 `block_pid` 静默返回 false（安全降级开关）。

### 4.2 TTL 过期策略

- `ttl_secs=0` → 使用 `default_ttl`（默认 300s）。
- `ttl_secs=u64::MAX` → `expiry_ns=0`（永久阻断）。
- `is_blocked()` 与 `list_blocked()` 调用时懒清理过期条目；`cleanup_expired()` 主动扫描。

### 4.3 BlockReason 枚举

```rust
pub enum BlockReason {
    RuleMatch = 1,           // 规则匹配 (severity >= 阈值)
    BaselineDeviation = 2,   // 基线偏离 (z-score >= 5σ)
    MlAnomaly = 3,           // ML 异常检测
    Correlation = 4,         // 关联引擎
    Manual = 5,              // REST API 手动阻断
}
```

编码与内核 `block_value.reason` 字段定义对齐（虽然用户态表不写内核 map），`from_u8` 对未知值降级为 `Manual`。

### 4.4 REST API

实现于 `crates/ks-server/src/routes.rs`：

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/block/{pid}?ttl=&reason=&trigger=` | 添加阻断（reason 默认 5、trigger 默认 "rest_api"；block 未启用时 403） |
| DELETE | `/api/v1/block/{pid}` | 解除阻断（404 未阻断） |
| GET | `/api/v1/blocked` | 列出被阻断 PID（**注意路径是 /blocked，不是 /blocks**） |

### 4.5 CLI — ⚠️ 不存在

旧文档的以下命令**在代码中不存在**（ks-cli 只有 8 个子命令：start/stop/status/replay/serve/baseline/correlation/watch）：

```
kernelsentinel block <pid> [--ttl 600] [--reason manual]   ❌ 不存在
kernelsentinel unblock <pid>                                ❌ 不存在
kernelsentinel blocks                                       ❌ 不存在
```

阻断只能通过 REST API（`POST/DELETE /api/v1/block*`，需 start --serve 且显式鉴权配置）。

### 4.6 自动触发入口

`crates/ks-cli/src/cmds/start.rs` 在事件处理循环中调用 `block_pid`：
- 关联告警 `severity >= 阈值` → `BlockReason::Correlation`，trigger=告警标题。
- 规则告警 `severity >= 阈值` → `BlockReason::RuleMatch`，trigger=规则名。

阈值由 `block_severity_threshold` 配置项控制——**它是 severity 字符串（low/medium/high/critical），
默认 `"critical"`**（⚠️ 旧文档"默认 70，对应风险分 ≥ 70"是错的：config.rs 中该字段类型是 Severity，
与内核整数风险分无关；内核 kill 阈值是独立的 `KS_ENFORCE_KILL_THRESHOLD`，默认 70）。
`block_enabled` 默认 `false`（默认 monitor，只告警不阻断）。

## 5. 阻断决策流程（⚠️ 与旧文档的差异）

以 execve 事件为例，从检测到执行：

1. **探针触发**：`trace_sys_exit`（raw_syscalls/sys_exit tracepoint 内的 exec 分支）捕获 syscall 59 返回，构造 `exec_event`。
2. **推理判定**：`infer_event(pid, EVENT_PROCESS_EXEC, filename, ...)` 返回 `verdict`。
3. **即时阻断（Modern + enforce）**：`KS_MAYBE_BLOCK(pid, verdict)`：
   - 若 `verdict==2` 且 `CFG_ENFORCE_MODE==1`（KS_ENFORCE=1）且干跑期已过且 kill 阈值达标且非保护名单
     → `bpf_send_signal(9)` 立即 SIGKILL（探针上下文内同步执行）。
   - 调用 `ks_check_block(pid)` 查 `block_decisions` map，命中且未过期 → 再判豁免后 SIGKILL。
4. **事件提交**：`KS_SUBMIT(ctx, events, evt)` 将事件投递至 ringbuf。
5. **用户态消费**：`start.rs` 主循环读取事件，送入检测引擎 / 关联引擎。
6. **告警触发**：若规则或关联告警 `severity >= block_severity_threshold`：
   - `block_mgr.block_pid(pid, ttl, reason, trigger)` 写入用户态表。
   - ⚠️ **不会**将决策同步至内核 `block_decisions` map——用户态从不写该 map
     （grep 全仓无 `map_mut("block_decisions")` / `bpf_map_update_elem` 写入点）。
     旧文档描述的"写回内核 map → 后续 syscall 命中 SIGKILL"闭环**在代码中不存在**。
7. **后续拦截（设计意图 vs 现状）**：若未来实现用户态→`block_decisions` 写入，同一 PID 的下一次 syscall 才会
   在步骤 3 的 map 查询中命中并 SIGKILL；**当前用户态阻断仅影响自身表与告警展示，不触发内核实杀**。
8. **过期清理**：TTL 到期后 `cleanup_expired` 移除用户态条目，内核 map 无对应清理（无人写入）。

> 现状：步骤 3 的即时阻断（enforce 内核实杀）与步骤 6 的用户态阻断表是**两条平行通道**，
> 只有前者能真正杀掉进程；后者用于决策记录、展示与未来扩展。

## 6. 安全考量

### 6.1 误判风险

- `bpf_send_signal(SIGKILL)` 不可阻断、不可捕获，误判会导致合法进程被杀。
- 缓解（多层冷启动防护，真机验证过误杀 sshd 教训后补强）：默认 monitor 只告警不杀；
  enforce 必须显式 `KS_ENFORCE=1` + 干跑期 `KS_ENFORCE_WARMUP_SEC`（默认 120s）+ 独立 kill 阈值
  （默认 70）+ `protected_pids`（自身+祖先链+pid1）+ `protected_comms`（默认 11 项 + exe_path 反伪装）；
  `block_enabled=false` 时用户态自动阻断静默禁用。

### 6.2 不可撤销性

- SIGKILL 已发送后无法撤回；用户态 `unblock_pid` 只能清除自身表，对未来无需生效的内核实杀无能为力
  （内核实杀由 enforce 门控 + 保护名单兜底，不做回滚机制）。
- 永久阻断（`expiry_ns=0`）需人工确认，REST API 的 `DELETE /block/:pid` 是唯一回收手段。

### 6.3 Tier Fallback

| Tier | 内核版本 | 行为 |
|------|---------|------|
| Modern | 5.8+ (`KS_RINGBUF=1`) | verdict=2 + enforce 门控通过后 `bpf_send_signal(9)`；map 命中判豁免后发信号 |
| Legacy | 4.x | 仅 `ks_check_block` 查表标记，不主动发信号（无 bpf_send_signal helper） |
| Ancient | 3.10+ | 同 Legacy；helper 不存在，强制降级为纯标记 |

Legacy/Ancient tier 无内核实杀能力，阻断由用户态检测/BLOCK 告警呈现。生产环境如需实杀，用 5.8+ Modern + enforce。
真机验证：2026-07-29 5.15 enforce 模式 SIGKILL 触发进程 EXIT=124/137，自身与父链豁免不再被杀（G2.1 已验证）。

### 6.4 资源限制

- `block_decisions` LRU_HASH 上限 4096 条，超出后 LRU 淘汰最旧条目（虽然当前无人写入）。
- 用户态 `BlockManager` 无上限（依赖 TTL + `cleanup_expired` 主动回收）。

## 7. 测试覆盖

### 7.1 内核态

- `ks_check_block` 命中 / 未命中 / 过期三分支（verifier 编译验证 + modern tier 真机）。
- `KS_MAYBE_BLOCK` 在 Modern / Legacy 两套宏下的展开一致性（编译期断言，`#if KS_RINGBUF`）。
- 5 个 sys_exit 决策分支的 `verdict==2` 路径：**已实机验证**（2026-07-29 5.15，enforce 触发
  SIGKILL EXIT=124/137，G2.1 完成；e2e-modern.sh / e2e_attacks.rs 14 测试覆盖用户态阻断链路）。

### 7.2 用户态（`blocker.rs` 单元测试，10 个）

| 测试 | 覆盖点 |
|------|--------|
| `test_block_pid_basic` | 基本阻断 + 计数 |
| `test_block_disabled_returns_false` | `enabled=false` 静默降级 |
| `test_unblock_pid` / `test_unblock_nonexistent` | 解除阻断 |
| `test_block_ttl_expiry` | TTL 过期自动失效（1s TTL + sleep） |
| `test_list_blocked` / `test_cleanup_expired` | 列表与批量清理 |
| `test_block_reason_display` / `from_u8` | 枚举序列化与降级 |
| `test_default_ttl_used_when_zero` | ttl=0 回退默认值 |
| `test_update_existing_block` | 同 PID 重复阻断覆盖更新 |

### 7.3 集成

- REST API 端到端：`POST /api/v1/block/{pid}` → `GET /api/v1/blocked` → `DELETE /api/v1/block/{pid}` 往返
  （ks-server 集成测试，含 block 未启用 403 / 404 分支）。
- `start.rs` 告警触发链路：注入高 severity 事件，验证 `block_pid` 被调用且 `BlockReason` 正确（e2e_attacks.rs `test_e2e_block_lifecycle`）。

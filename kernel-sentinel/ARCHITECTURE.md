# 内核哨兵 (KernelSentinel) — 架构设计文档

> 版本：2026-08-31 重写（基于当前代码库事实，含未提交工作区改动）
> 适用范围：kernel-sentinel/ 仓库全部 crates、eBPF 源码、部署物。
> 本文档替代旧版（2026-08-26 版）。所有探针数、Map 清单、事件编号、阈值均从代码 `SEC(...)` 段、
> `.maps` 定义与常量实测核对，不以早期设计文档为准。
> 配套文档：[ROADMAP.md](ROADMAP.md)（路线图）、[docs/phase-e-summary.md](docs/phase-e-summary.md)（Phase E 决策）、
> [docs/performance-design.md](docs/performance-design.md)（性能）、[docs/deployment.md](docs/deployment.md)（部署）、
> [docs/HANDOFF-2026-08-11.md](docs/HANDOFF-2026-08-11.md)（交接/服务器清单）。

---

## 1. 项目定位

基于 eBPF 的 **Linux 服务器端内核级威胁检测系统**（国安杯 guoancup 申报书项目）。

一句话定义：用 eBPF 把感知探针植入系统调用、VFS、网络栈、进程调度等内核关键路径，在内核态完成
"进程树拓扑 + TCP 流状态机 + 六维频率基线 + 风险分推理 + 事件智能过滤"，用户态用 Rust 做
"规则匹配 + 跨事件关联 + z-score/EWMA 基线偏离 + 攻击链还原"，取证日志用 JSONL + SHA-256 哈希链防篡改；
Modern tier 还支持内核态 `bpf_send_signal(SIGKILL)` 零延迟阻断。

**现状快照（2026-08-31）**：

| 维度 | 状态 |
|------|------|
| 真机验证 | 三台云主机（6.1 Debian / 5.15 Ubuntu / 3.10 CentOS 7）端到端全通过，9 套规则全触发不误杀（ks-test-evidence/perf-2026-08-13/） |
| 测试 | `cargo test --workspace` 实测 2026-08-31：**168 个测试全过** |
| 交付形态 | musl 静态单二进制（约 36MB，无动态依赖），`scripts/pack.sh` 打 tar.gz 交付包 |
| 长稳 | 8 月修复 ml_detector/baseline 表膨胀 OOM（加 LRU + 淘汰守卫），本地 RSS 1.4GB→3.9MB，误报 150 万→33 |
| 内核兼容 | 5 tier 条件编译 + 运行时 tier_detect 自动路由，3.10 no-BTF stock 内核走 C loader 旁路 |
| 阻断能力 | enforce 模式真机验证能 SIGKILL（5.15），多层冷启动防护（protected_pids/comms + warmup + kill 阈值），默认 monitor 只告警不杀 |

> ⚠️ 本文按当前工作区代码撰写，其中 6 个文件为**未提交改动**（8-30）：`ks_probes_smart_filter.h`（过滤逻辑重构）、
> `ks_probes_syscall.h`（argv 全 tier 采集 + finit_module 事件）、`ks_loader.c`（syscall_ctxs 384B）、
> `ks_main.bpf.c`（include 顺序）、`aggregator.rs`（exec 参数分段解码）、`rules/privilege_escalation.yml`（LD_PRELOAD regex）。

---

## 2. 总体架构

```
┌────────────────────────────────────────────────────────────────────┐
│                        CLI 层 (ks-cli)                              │
│  start / stop / status / replay / watch / baseline / correlation   │
│  serve(示意) + --serve 内嵌 REST  + 单实例锁 + 规则热加载           │
├────────────────────────────────────────────────────────────────────┤
│                  服务/API 层 (ks-server, axum)                      │
│  REST /api/v1/* + WebSocket /ws/alerts + Prometheus /metrics       │
│  Bearer token + TLS/mTLS + 限流(GCRA) + 审计日志                    │
├────────────────────────────────────────────────────────────────────┤
│                  用户态引擎层 (ks-engine, Rust)                      │
│  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐ ┌─────────┐    │
│  │ 事件源    │ │ 聚合解码  │ │ 检测引擎 │ │ 关联引擎  │ │ 基线/ML │    │
│  │ ringbuf/ │ │ IPv4/6   │ │ YAML规则│ │ 窗口/序列/│ │ z-score │    │
│  │ perfbuf/ │ │ argv分段 │ │ +异常评分│ │ 进程树    │ │ + EWMA  │    │
│  │ C loader │ │ +LRU窗口 │ │ 双模    │ │ 三模式    │ │ 双模型  │    │
│  └──────────┘ └──────────┘ └────────┘ └──────────┘ └─────────┘    │
│  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌──────────┐                 │
│  │ 进程树    │ │ 攻击链    │ │ 取证日志 │ │ 用户态阻断 │                │
│  │ 拓扑+异常 │ │ MITRE 10 │ │ JSONL  │ │ BlockMgr  │                │
│  │ 关系+LRU │ │ 阶段还原  │ │ 哈希链  │ │ +注入保护 │                │
│  └──────────┘ └──────────┘ └────────┘ └──────────┘                 │
│  ┌───────────────────────────────────────────────────────┐         │
│  │ tier_detect 路由: modern→aya ringbuf                   │         │
│  │   legacy→aya perfbuf / ancient→aya perfbuf             │         │
│  │   *nobtf→CLoaderSource (fork+exec ks_loader --stream)  │         │
│  └───────────────────────────────────────────────────────┘         │
├────────────────────────────────────────────────────────────────────┤
│              内核层 (ks-ebpf, eBPF C, 16 探针 / 5 tier)              │
│  ┌─────────────┐ ┌──────────────────┐ ┌────────────────────┐       │
│  │ 探针层       │ │ 推理引擎          │ │ 智能过滤层           │       │
│  │ 5 tracepoint│ │ 风险分 0-100      │ │ process_whitelist  │       │
│  │ 11 kprobe   │ │ 4 维推理函数      │ │ safe_patterns      │       │
│  └─────────────┘ │ verdict 0/1/2    │ │ freq anomaly 放行   │       │
│                  └──────────────────┘ └────────────────────┘       │
│  进程树 map │ 网络流 map │ 频率计数 map │ 24 个 BPF map             │
│  ┌────────────────────────────────────────────────────┐            │
│  │ events ringbuf 16MB (modern) / perfbuf 256 (老内核)│            │
│  └────────────────────────────────────────────────────┘            │
└────────────────────────────────────────────────────────────────────┘
```

关键架构事实：

1. **内核态做重活**：进程树、TCP 流、频率计数、风险推理、事件过滤全部在内核完成，用户态只消费"值得看"的事件。
2. **四层检测防线**：内核推理（确定性规则 + 风险分）→ 用户态规则引擎（YAML 规则）→ 跨事件关联（时序/序列/拓扑）→ 基线偏离（六维 z-score + EWMA 双模型）。
3. **一条数据通路**：所有事件（除树/流/频率专用 ringbuf）经 `events` 通道进入用户态聚合器，统一解码、统一落取证日志、统一过四道检测。
4. **阻断双通道**：内核态 `bpf_send_signal`（仅 modern + enforce）+ 用户态 BlockManager（告警级阻断决策表）。

---

## 3. 技术栈

| 层次 | 技术 | 说明 |
|------|------|------|
| 内核探针 | eBPF C，clang-18/-19 `-target bpf` | 16 个探针程序（5 tracepoint + 11 kprobe，从 SEC 段实测），5 tier 条件编译 |
| 内核推理 | eBPF C + BPF Map | 风险分累积（0-100）+ 4 维推理函数 + 智能过滤 |
| 用户态引擎 | Rust (edition 2021) + tokio + aya-rs | 事件解码/规则匹配/关联/基线/ML/取证 |
| eBPF 加载 | aya（modern/legacy/ancient）/ ks_loader.c sidecar（nobtf） | 3 条采集路径：ringbuf / perfbuf / 子进程 stdout 帧流 |
| 服务 API | axum 0.7 + tokio + tower 系列 | REST + WebSocket + 中间件（审计/鉴权/限流） |
| ML 检测 | 纯 Rust 自研（无外部 AI 依赖） | EWMA 自适应 + Welford 方差 + LRU 内存守卫 |
| 配置 | 环境变量 KS_*（19+ 个）+ YAML API 预留 | 命令行参数直覆盖（YAML 文件未接入主程序，见 §9.8） |
| 部署 | musl 静态单二进制 + systemd Type=notify + Docker | `deploy/install.sh` + `scripts/pack.sh` |
| 可观测 | Prometheus（6 指标）+ tracing JSON 日志 + Grafana | `/metrics` 端点 + deploy/grafana + prometheus.yml |
| 取证 | JSONL + SHA-256 哈希链 + gzip 归档 | `HashAlgorithm` trait 可换算法 |

---

## 4. 仓库布局

```
kernel-sentinel/
├── crates/
│   ├── ks-core/     核心类型：事件结构体(C/Rust 对齐)、Field 枚举规则、告警/UUID
│   ├── ks-ebpf/     eBPF C 源码 + build.rs + ks_loader.c (C loader) + audit-3.10-compat.sh
│   ├── ks-engine/   用户态引擎：源码 + build.rs(5 tier 编译矩阵) + tests + benches(criterion)
│   ├── ks-server/   axum REST + WebSocket + 安全加固
│   └── ks-cli/      命令行入口 kernelsentinel
├── rules/           9 套 YAML 检测规则（23 条规则）
├── scenarios/       6 个攻击模拟脚本 sim_*.sh
├── deploy/          systemd unit + install/uninstall.sh + docker-entrypoint + prometheus/grafana
├── scripts/         pack.sh / build.sh / build-musl.sh / e2e-*.sh / extract-offsets.sh / ecs-ks-diag.sh
├── docs/            HANDOFF / phase-e-summary / deployment / performance-design / security-design /
│                    ml-design / blocking-design / api-design / cloader-protocol / adr / 教学相关
├── ks-test-evidence/  真机验证证据（perf-2026-08-05 / perf-2026-08-13）
├── logs/ logs-collected/  运行日志（gitignore）
├── Dockerfile / docker-compose.yml
└── vendor/          vendored aya（本地 patch，btf_fd=None 时清零 btf_key/value_type_id）
```

crates 依赖关系：`ks-cli → {ks-engine, ks-core, ks-server}`；`ks-server → {ks-core, ks-engine}`；`ks-engine → ks-core`。
`ks-ebpf` 不是 workspace 成员（纯 C，由 ks-engine 的 build.rs 编译并 `include_bytes!` 内嵌）。

---

## 5. 内核探针层 (ks-ebpf)

### 5.1 探针矩阵 — 16 个程序（5 tracepoint + 11 kprobe，从 SEC 段实测）

唯一编译入口 `src/bpf/ks_main.bpf.c`：`KS_EVENT_MAP(events, 16*1024*1024)` 后按固定顺序
include 10 个探针头。末尾 `char LICENSE[] SEC("license") = "GPL"`。

| SEC 段名 | 类型 | 所在文件 | 事件类型 | 捕获内容/触发条件 |
|---|---|---|---|---|
| `tracepoint/raw_syscalls/sys_enter` | tracepoint | ks_probes_syscall.h | —（上下文存 map） | 白名单 syscall：59 execve / 2 open / 257 openat / 0 read / 1 write / 42 connect / 101 ptrace / 62 kill / 313 finit_module；execve 无条件读 argv[0..4] 各 64B |
| `tracepoint/raw_syscalls/sys_exit` | tracepoint | ks_probes_syscall.h | 1/10/20/30/31/81 | 按 syscall_nr 分发：59→exec、2/257→file_open、42→net_connect（读用户态 sockaddr，v4/v6）、101→ptrace、62→signal、**313 且 ret<0→LKM 事件**（8-30 新增） |
| `tracepoint/sched/sched_process_fork` | tracepoint | ks_probes_process_tree.h | 40 | 仅当子进程带 anomaly 关系或父 risk≥40 时发 TREE_FORK |
| `tracepoint/sched/sched_process_exec` | tracepoint | ks_probes_process_tree.h | 41 | TREE_EXEC，更新 process_tree 的 exe_path |
| `tracepoint/sched/sched_process_exit` | tracepoint | ks_probes_process_tree.h | 42 | TREE_EXIT，随后删 process_tree 节点 |
| `kprobe/vfs_open` | kprobe | ks_probes_vfs.h | — | 只更新智能过滤统计（不产出事件） |
| `kprobe/vfs_write` | kprobe | ks_probes_vfs.h | 12 | 仅 `count >= 1024` 才发 |
| `kprobe/vfs_unlink` | kprobe | ks_probes_vfs.h | 13 | 文件删除 |
| `kprobe/tcp_v4_connect` | kprobe | ks_probes_net.h | 20 | CONNECT + 更新网络流；读 inet_sock 源地址端口 |
| `kprobe/tcp_v6_connect` | kprobe | ks_probes_net.h | 20 | CONNECT（仅 dport/daddr6，无 saddr） |
| `kprobe/udp_sendmsg` | kprobe | ks_probes_net.h | 22/24 | **dport==53 事件类型改 24(DNS)**，否则 22(SEND) |
| `kprobe/tcp_set_state` | kprobe | ks_probes_netflow.h | 51 | TCP 状态机：SYN_SENT→ESTABLISHED→FIN_WAIT→CLOSED；CLOSED 后删流 |
| `kprobe/tcp_sendmsg` | kprobe | ks_probes_netflow.h | — | 累加 byte/packet 计数；>100MB 置 DATA_EXFIL 标志 |
| `kprobe/commit_creds` | kprobe | ks_probes_container.h | 80 | 容器逃逸；ns_inum/cap_eff 字段为 0 占位（待完善） |
| `kprobe/do_init_module` | kprobe | ks_probes_lkm.h | 81 | LKM 加载（insmod/modprobe 入口） |
| `kprobe/security_bpf_prog_free` | kprobe | ks_probes_self_protect.h | 82 | 本项目 BPF 程序被卸载/篡改 |

> ⚠️ 已知重复：`connect` 同时被 sys_exit tracepoint（42）与 tcp_v4_connect kprobe 上报，同一连接产生两条事件。
> kprobe 路径（vfs/net/流）不过智能过滤，只有 sys_exit tracepoint 路径受过滤/阻断。

### 5.2 BPF Map 清单（24 个，从各探针文件 `.maps` 段收集）

| 名称 | 类型 | key/value | max | 用途 |
|---|---|---|---|---|
| events | RINGBUF 16MB（modern）/ PERF_EVENT_ARRAY 256（legacy/ancient） | — | — | 主事件通道 |
| infer_config | ARRAY | 4/4 | 32 | 推理配置；**实际只生效 key 5/6/7（enforce 三项）**，见 §5.4 |
| block_decisions | LRU_HASH | 8/16 | 4096 | 用户态下发的"阻止"裁决（expire_ns+reason） |
| protected_pids | LRU_HASH | 4/1 | 256 | 豁免进程（引擎注入自身+父链+pid1） |
| protected_comms | LRU_HASH | 16/1 | 64 | 豁免 comm（11 个默认 + KS_PROTECTED_COMMS） |
| process_tree | LRU_HASH | 4/312 | 65536 | 进程树节点（含 exe_path[256]） |
| risk_scores | LRU_HASH | 4/4 | 4096 | 每进程风险分 0-100 |
| ip_whitelist | LRU_HASH | 4/1 | 256 | IP 白名单 |
| net_conn_history | LRU_HASH | 12/8 | 8192 | 连接次数/频率（60s 窗） |
| freq_counters | LRU_HASH | 4/48 | 4096 | 60s 频率计数 + anomaly_flags |
| syscall_ctxs | HASH | 8/384 | 10240 | sys_enter 上下文（含 exec_args[320]，8-30 起全 tier 采集 argv） |
| ks_scratch | PERCPU_ARRAY | 4/1024 | 1 或 256 | 非 ringbuf tier 的事件暂存 |
| process_whitelist | LRU_HASH | 4/1 | 256 | 智能过滤进程名单 |
| safe_patterns | HASH | 48/1 | 128 | 安全访问模式（comm+path_prefix） |
| filter_stats_map | PERCPU_ARRAY | 4/24 | 1/256 | passed/blocked 统计 |
| filter_events | RINGBUF 1MB/PERF_ARRAY | — | — | **定义了但无人写入（死 map）** |
| freq_events | RINGBUF 1MB/PERF_ARRAY | — | — | 频率更新/异常事件 |
| net_flows | LRU_HASH | 20/48 | 8192 | 网络流状态表 |
| port_scan_map | LRU_HASH | 4/24 | 4096 | 端口扫描跟踪 |
| flow_events | RINGBUF 1MB/PERF_ARRAY | — | — | 流事件 |
| tree_events | RINGBUF 1MB/PERF_ARRAY | — | — | 进程树事件 |
| anomaly_relations | HASH | 32/2 | 64 | 父子 comm→异常类型映射 |
| pt_scratch_map | PERCPU_ARRAY | 4/936 | 1/256 | 进程树 scratch（3 个 process_node，防 512B 栈超限） |
| syscount_map | PERCPU_ARRAY | 4/24 | 1/256 | enter/exit/drop 计数（性能诊断） |

> 注意：loader 端 `known_maps` 表（ks_loader.c）含 25 项，其中 `freq_thresholds`、`filter_config` 两个 map
> 在 C 代码中已不存在（死表项），loader 会预创建无人使用的 map。
> ancient tier 下 LRU_HASH 退化为普通 HASH，`block_decisions`/`freq_counters` 等无 LRU 淘汰，长跑可能满 map（已知限制）。

### 5.3 事件类型与结构体

`struct ks_event` 公共头（common.h:499，64 字节）：event_type + timestamp_ns + pid/tid/uid + ppid + comm[16] + syscall_nr + retval。
`fill_header` 默认 ppid/syscall_nr 填 0，探针按需覆写。

| 编号 | 名称 | 结构体 | 发射点 |
|---|---|---|---|
| 0 | UNKNOWN | — | — |
| 1 | PROCESS_EXEC | exec_event（filename[256]+args[512]） | sys_exit 59 |
| 2/3 | EXIT/CLONE | — | **定义了但无探针发射**（fork 走树事件 40） |
| 10 | FILE_OPEN | file_event（filename[256]+bytes+fd+flags） | sys_exit 2/257（受智能过滤） |
| 11 | FILE_READ | file_event | **无探针发射**（规则层可用） |
| 12/13 | FILE_WRITE/DELETE | file_event | vfs_write（≥1024B）/ vfs_unlink |
| 14/15 | RENAME/CHMOD | file_event | **定义未发射** |
| 20 | NET_CONNECT | net_event（saddr/daddr/sport/dport/proto/family/saddr6/daddr6） | sys_exit 42 + tcp_v4/v6_connect kprobe |
| 21/23 | ACCEPT/RECV | net_event | 定义未发射 |
| 22/24 | NET_SEND/DNS | net_event | udp_sendmsg（dport==53 时 24） |
| 30/31 | PROC_PTRACE/SIGNAL | signal_event（target_pid+signal） | sys_exit 101/62 |
| 40-43 | TREE_FORK/EXEC/EXIT/ANOMALY | process_tree_event（parent_comm+parent_risk+anomaly_type） | 40/41/42 发射；43 未发射 |
| 50-54 | FLOW_CREATE/STATE/DATA/CLOSE/ANOMALY | net_flow_event | 50（仅 anomaly 时）/51 发射；52/53/54 未发射 |
| 60/61 | FREQ_UPDATE/ANOMALY | freq_update_event / freq_anomaly_event | 60 每 100 次 syscall；61 首次异常一次（FREQ_REPORTED 去重） |
| 70-72 | FILTER_PASS/BLOCK/STATS | — | 常量仅供统计语义，无事件发射 |
| 80 | CONTAINER_ESCAPE | container_escape_event | commit_creds kprobe |
| 81 | LKM_LOAD | lkm_load_event（module_name[64]+comm[16]） | **双发射点**：do_init_module kprobe + sys_exit 313（8-30 新增，module_name 写死 "finit_module"） |
| 82 | EBPF_TAMPER | ebpf_tamper_event（prog_name[64]+action[16]） | security_bpf_prog_free |

### 5.4 内核推理引擎（common.h）

函数：`infer_event` 入口按事件类型分发 → 各维度函数累积 `risk_scores[pid]`（0-100 封顶），返回
verdict：**0=正常 / 1=可疑（有加分项但未达阈值）/ 2=高风险（risk≥CFG_RISK_THRESHOLD，默认 70）**。

| 维度函数 | 评分规则 | 阈值来源 |
|---|---|---|
| `infer_sensitive_file` | `/etc/shadow`+40、`/etc/sudoers`+40、`/etc/gshadow`+35、`/root/.ssh`+30（逐字节前缀比较，无 strncmp 避免 helper） | 硬编码 |
| `infer_suspicious_net` | IP 白名单直接返回 0；dport∈{4444,1337,31337,5555,6666,6667,9999,12345,23456}+50；dport>1024 且非 {8080,8443,3306,5432,6379,27017,33060}+10；60s 窗内同 (pid,daddr,dport,proto) 重复建连 +5 | IP 白名单查 map，端口硬编码 |
| `infer_bulk_file_ops` | WRITE/DELETE/RENAME 每次 +2 | — |
| `infer_process_injection` | PTRACE +35、SIGNAL +20 | — |

- 阈值语义：`CFG_RISK_THRESHOLD` 默认 70（≥70 且 enforce 时阻断），40 分以上标记高风险事件（smart filter 放行依据之一）。
- ⚠️ **`get_config` 死代码缺陷**（common.h:320-331）：switch 对 key 0-4（风险阈值/端口扫描阈值/时间窗等）直接 return 硬编码默认值，
  `bpf_map_lookup_elem(&infer_config)` 永远执行不到这 5 个 key。用户态只能通过 infer_config[5/6/7] 配置 enforce 三项，
  风险阈值/时间窗等配置会静默失效。
- 注：fork 探针另有"父 risk≥40 → 子进程标 ANOMALOUS"逻辑（process_tree.h）。

### 5.5 智能过滤层（ks_probes_smart_filter.h，含 8-30 重构）

> ⚠️ 语义陷阱：函数名是 `should_send_event`，但返回的 `decision.action` 含义是**"是否抑制"**
> —— action=1 → 丢弃事件，action=0 → 放行（`ks_should_drop` 直接 `return d.action`）。
> 命名与语义相反，改写/维护时勿按名字理解。

8-30 重构后的完整决策链（按序短路）：

1. `process_whitelist` 命中 → 丢弃（WHITELIST）；
2. 事件 10-12 且 (comm, path_prefix) 命中 `safe_patterns` → 丢弃（SAFE_PATTERN）；
3. `risk_scores[pid] >= 40` → 放行；
4. `freq_counters[pid].anomaly_flags > 0` → 放行；
5. FILE_OPEN(10)/FILE_READ(11) → 丢弃（有 freq 记 NORMAL_FREQ，无 freq 记 LOW_RISK）；**其余所有事件类型默认放行**。

对比旧版（826 commit）：旧版"有 freq_counter 且无 anomaly → 所有事件一律丢弃"，只放行 exec/ptrace/signal/connect；
新版过滤面收窄——**低风险进程的 exec/connect/signal 事件照发，仅文件 open/read 恒被过滤**。
`FC_MAX_NORMAL_FREQ`/`FC_BLOCK_RATE_TARGET` 常量已无实际用途（`get_filter_config` 返回硬编码值，不查 map）。

### 5.6 内核态阻断（bpf_send_signal，仅 modern/ringbuf tier）

- `KS_MAYBE_BLOCK(pid, verdict)`（common.h:249-264，`#if KS_RINGBUF` 分支）：当 `verdict==2` 且 `CFG_ENFORCE_MODE==1` 时：
  - 干跑期：`CFG_ENFORCE_WARMUP_UNTIL_SEC`（boot 秒，默认 0=关闭）未过则不杀；
  - kill 阈值：`CFG_ENFORCE_KILL_THRESHOLD` 默认 70；
  - 豁免：`ks_current_protected()` = protected_pids 命中，或（protected_comms 命中 且 exe_path 不落在 /tmp、/dev/shm、/var/tmp）；
  - 满足则 `bpf_send_signal(9)` SIGKILL。
- 随后无论是否 enforce 都查 `block_decisions[pid]`（用户态写入的裁决，未过期且非 protected → SIGKILL）。
- **legacy/ancient tier 不屏蔽**：`KS_MAYBE_BLOCK` 忽略 verdict，`ks_check_block` 只返回命中标记，不发信号
  （3.10/4.19 无 `bpf_send_signal` helper）——阻断退化为纯标记。
- 用户态注入（loader.rs）：`inject_protected_pid`（自身 pid + 祖先链 ≤8 跳 + pid 1）、`inject_protected_comms`
  （11 默认 + KS_PROTECTED_COMMS）；enforce 三配置写 infer_config[5/6/7]。
- 默认 **monitor 模式**（`KS_ENFORCE != 1`），只告警不杀。

### 5.7 5 tier 条件编译（build.rs 在 ks-engine，宏在 common.h:17-69）

| tier | 宏 | KS_RINGBUF | KS_LRU_HASH | probe_read 系列 | .BTF.ext | 跑在 |
|---|---|---|---|---|---|---|
| modern | KS_TIER_MODERN | 1 | 1 | 原生 | 保留 | 5.8+（ringbuf） |
| legacy | KS_TIER_LEGACY | 0 | 1 | 原生 | 保留 | 4.x（perfbuf） |
| ancient | KS_TIER_ANCIENT | 0 | 0 | **重定向** | 保留 | 3.10+（perfbuf） |
| ancient_nobtf | KS_TIER_ANCIENT+KS_NOBTF | 0 | 0 | 重定向 | **剥离** | 3.10.0-1160 系列 |
| legacy_nobtf | KS_TIER_LEGACY+KS_NOBTF | 0 | 1 | 重定向 | **剥离** | 4.19. 系列 |

probe_read 重定向的条件是 `#if defined(KS_TIER_ANCIENT) || (defined(KS_TIER_LEGACY) && defined(KS_NOBTF))`
（common.h:31-36）——**带 BTF 的 ancient 也重定向**（3.10 内核本就没有 probe_read_user/kernel 等新 helper），
只有 modern 与带 BTF 的 legacy 用原生 helper。

KS_NOBTF 还控制：
- `BPF_CORE_READ(ptr, field)` 重定义为 `KS_NOREAD_<field>`：无 CO-RE 时用**硬编码结构体偏移**
  （`__sk_common` 0、`path.dentry` 8、`dentry.d_name.name` 40、`file.f_path` 16、`sin6_port` 2；
  inet_saddr/inet_sport：legacy=728/736，ancient=776/784 —— 来自 `scripts/extract-offsets.sh`
  从 CentOS 7 debuginfo RPM 用 pahole 提取，换内核版本需重新提取）；
- lkm/self_protect 的 module/aux 指针偏移硬编码（mod+16、aux+8 取 name）。
- **`syscall_ctxs` 384 字节无 tier 差异**：8-30 起去掉了 exec_args 的 `#ifndef KS_NOBTF` 守卫，
  所有 tier 恒采集 argv[0..4]（旧版 noble 下 64B 且不读 argv）。ks_loader.c 的 `syscall_ctxs` 表项 value_size 同步 64→384。
  ⚠️ 两处必须同时生效，否则 ancient_nobtf 下 map 值域不匹配。
- KS_RINGBUF=0 的影响：events 变 PERF_EVENT_ARRAY(256)；`KS_RESERVE` 走 ks_scratch PERCPU_ARRAY（ancient 退化为按
  CPU id 索引的 ARRAY，max=256，>256 CPU 需调大）；`KS_SUBMIT` 用 `bpf_perf_event_output`；`KS_DISCARD` 为空操作
  （perf 模式无法撤销已填充的 scratch）。

编译矩阵（`crates/ks-engine/build.rs`，260 行）：clang 探测顺序 clang-18/clang-19/clang；5 个 tier 各编译一次
`ks_main.bpf.c` → `ks_main_<suffix>.o`（`-g -O2 -target bpf -D__TARGET_ARCH_x86 -D<KS_TIER_*> [-DKS_NOBTF] -I src/bpf -I /usr/include/bpf`）；
nobtf 两 tier 编译成功后 `llvm-objcopy` 剥离 `.BTF.ext` 与 `.rel.BTF.ext`（只剥 .BTF.ext 不剥 .BTF，.BTF 留给 aya parse_btf_maps）；
随后 `cc -static -O2 -Wall ks_loader.c -lelf -lzstd -lz` 预编静态 loader（nobtf 路径去 gcc 依赖）；
`write_ebpf_objects` 生成 `ebpf_objects.rs` 用 `include_bytes!` 内嵌 5 个 .o + ks_loader 静态二进制。
单 tier 失败仅告警跳过；全部失败才 panic；modern 失败告警"5.8+ 无法加载"。

> `crates/ks-ebpf/build.rs`（59 行）是遗留通用编译路径（无 tier 逻辑），真正矩阵在 ks-engine/build.rs。
> `src/bpf/vfs_probe.bpf.c` 是 0 字节空文件（残留）。
> `vmlinux.h` 162,167 行，`bpftool btf dump` 产物风格，但 **bpf_func_id 枚举与主线不同**（probe_read_user 等为 112-115，
> 标准内核为 35-38）——来自打过补丁的 kernel-plus，audit 脚本按此编号静态审计。

### 5.8 ks_loader.c — 3.10 stock 内核专用 C loader（855 行）

- **流程**：`--stream`（默认 `--load-only`）→ setrlimit(RLIMIT_MEMLOCK=∞) → bpf() 冒烟测试 → libelf 打开 .o →
  Step1 `find_maps`：找 `.maps` 段 + SHT_SYMTAB，对每个 STT_OBJECT 符号按 `known_maps` 硬编码表
  `create_map_for`（**map 属性不来自 ELF BTF，来自硬编码表**）→ Step2 逐 PROGBITS|EXECINSTR 段 `load_prog` →
  Step3 为每个 PERF_EVENT_ARRAY map 每 CPU 建 `PERF_COUNT_SW_BPF_OUTPUT` perf event + mmap → Step4 attach
  （tracepoint 读 tracefs id，kprobe 写 `kprobe_events` 标签 `ks_<func>`）+ poll 循环。
- **帧协议**（stdout）：`[u32 LE length][u8[length] payload]`；`length=0` 心跳帧每 30s；日志/错误走 stderr。
  Rust 端 `CLoaderSource` 异步读帧、忽略心跳、stderr 环形保留末尾 512B 诊断。
- **3.10 兼容技巧**：裸 `syscall(__NR_bpf=321, ...)`/`__NR_perf_event_open=298`；`attr_size` 截断到
  `offsetof(kern_version)+4`；kern_version 从 /proc/version 解析；map 预创建后 ELF 重定位 `BPF_PSEUDO_MAP_FD` 注入；
  ringbuf 不可用→全 PERF_EVENT_ARRAY；verifier log 截尾 4KB。
- **已知弱点**：map 尺寸不做 ELF 声明 vs 实际创建校验；attach 失败只告警不中止；退出只 close fd（无 bpf_link）。
- `scripts/audit-3.10-compat.sh`（228 行）：llvm-objdump 静态审计 .o——5.5+/5.8+ helper 出现次数必须为 0，
  回退 helper（probe_read=4、probe_read_str=45、perf_event_output=25）必须出现；scratch map 符号 ≥3；nobtf 模式校验 .BTF.ext 已剥离。

---

## 6. 用户态引擎层 (ks-engine)

### 6.1 事件源与 tier 路由

`SourceKind`：`EbpfModern / EbpfLegacy / EbpfAncient / EbpfAncientNoBtf / EbpfLegacyNoBtf / Mock / FileReplay`（FileReplay 仅枚举存在）。

tier 判定（tier_detect.rs，读 /proc/sys/kernel/osrelease）：
- major>5 或 (5,8+) → EbpfModern（ringbuf）；
- major≥4 → EbpfLegacy（perfbuf）；
- (3,10+) → EbpfAncient；
- 其余 → None（fallback mock）。
- BTF：`/sys/kernel/btf/vmlinux` 存在。Legacy 且无 BTF → EbpfLegacyNoBtf；Ancient 且无 BTF → 保持 Ancient 但加载路径选 nobtf。
- **release 前缀守卫**：ancient_nobtf 要求 `3.10.0-1160` 前缀（如 3.10.0-957 拒绝加载）；legacy_nobtf 要求 `4.19.`
  前缀。不匹配直接 bail，避免静默错误偏移。

路由（event_source.rs::default_event_source()）：
- Modern：aya 加载成功 → EbpfModernSource（5 个 ringbuf 轮询）；失败 → fallback Mock。
- Legacy：aya → EbpfPerfSource。
- LegacyNoBtf：先 `try_cloader_source_legacy()`（ks_loader + ks_main_legacy_nobtf.o）→ CLoaderSource；失败 fallback mock。
- Ancient：无 BTF 先试 CLoaderSource（ancient_nobtf + 3.10.0-1160 守卫），失败再走 aya + ks_main_ancient_nobtf.o → EbpfPerfSource；有 BTF 直接 aya + ks_main_ancient.o；任一失败 fallback Mock。
- 未知/太老 → fallback Mock（静默降级，仅 warn）。

`CLoaderSource`：tokio::process::Command fork+exec `ks_loader --stream <obj>`，13 个单元测试覆盖正常帧/心跳/EOF/管道断裂。
⚠️ `CLoaderSource::kind()` 恒返回 `EbpfAncientNoBtf`（legacy_nobtf 路径标注不准）。

### 6.2 聚合解码 (aggregator.rs，含 8-30 argv 改动)

- 解码覆盖：1→exec（filename + **args 分段拼接**）；10..=15→file（filename+bytes）；20..=24→net（IPv4 大端转点分 /
  IPv6 冒号分隔 / proto 转 TCP/UDP）；30|31→signal；2|3→仅 header；**80→container_escape、81→lkm_load、82→ebpf_tamper**；其他→仅 header + warn。
- **`exec_args_to_cmdline`（8-30 新增）**：内核侧 `args[512]` 语义是 **5×64B 定长槽位**（argv[0..4] 各 64B），
  每槽独立 cstr 截断，非空槽以空格 join，全空返回 None。替代旧版"整 512B 单 cstr"（遇无 '\0' 会全量污染）。
  边界：单槽恰 64B 无 '\0' 会带下槽首字节；argv[5+] 丢弃（内核也只存 5 个）。
- 环形缓冲 `VecDeque`（buffer_size 可配，默认 10000）；`by_pid / recent / by_time_range`。
- `pid_windows` LRU：`HashMap<pid, VecDeque<timestamp_ns>>`，60s 窗口；>10000 时按窗口内最早时间淘汰至 9000（max_pids - max_pids/10）。

### 6.3 检测引擎 (detector.rs) — 双模

**模式一：YAML 规则引擎**（确定性）
- `Field` 枚举 25 个字段（comm/pid/ppid/uid/syscall_nr/filename/args/file_bytes/saddr/daddr/sport/dport/proto/
  saddr6/daddr6/family/target_pid/signal/module_name/prog_name/source_ns_inum/target_ns_inum/cap_eff/action/event_type），
  类型安全，拼错在加载时报错。⚠️ `all_yaml_names()` 返回 24 项**不含 event_type**（与枚举 25 变体不一致，已知小坑）。
- `Operator` 10 个：equals/contains/starts_with/regex/gt/lt/gte/lte/not_equals/not_regex；数值字段支持比较，
  字符串字段上的 gt/lt 退化为数值 parse；**Family 仅支持 equals**；Saddr6/Daddr6 与 Saddr/Daddr 共用同一字符串存储。
- AND 语义（所有 conditions 满足）；Regex/NotRegex 预编译缓存（编译失败 warn，运行时恒 false）。
- 规则热加载：start.rs 每 5s 扫 rules 目录 mtime，变更则原子替换 DetectionEngine（失败保留旧规则）。

**模式二：异常评分 anomaly_score**（统计，累加后 min(1.0)，阈值 0.7）
- 频率：60s 内 syscall >500→+0.4，>100→+0.2。
- 敏感文件（三档，只取最高命中档）：`/etc/shadow,/root/.ssh,/etc/ssl/private,/root/.gnupg`+0.5；
  `/etc/passwd,/etc/sudoers,/etc/crontab,/etc/ssh/sshd_config`+0.35；`/var/log,/proc/,/etc/hosts`+0.15。
- 可疑命令模式（comm/args 含其一，break）：`bash -i`/`/dev/tcp`/`nc -e`+0.5；`python -c`/`chmod +s|u+s|4755`/
  `LD_PRELOAD`/`ptrace`+0.4；`base64 -d`/`mkfifo`+0.3；`wget`/`curl`/`nohup`+0.2。
- 勒索后缀：`.encrypted/.locked/.crypto/.ryuk/.wanna/.cerber/.crypt/.cry/.locky`+0.4。
- 端口：恶意端口表+0.5；dport>10000 且非 {27017,33060,6379}+0.2；非私有 IP（RFC1918 + fc/fd/::1）外连+0.1。

### 6.4 跨事件关联 (correlation.rs) — 三模式

`CorrelationEngine`：事件窗 VecDeque（max 2000）+ 8 条内置规则 + 独立追踪器 `(rule_idx, pid)`（max 10000，超限按
`last_step_timestamp_ns` 淘汰至 9000）。窗口大小由外部传入（start.rs 用 300s）。

| 模式 | 内置规则（8 条） | 置信度 |
|---|---|---|
| Window 窗口关联×4 | ①30s 读 /etc/shadow→外连 4444（critical T1041）②60s 读 .ssh→任意外连（high T1048）③5s bash -i→外连（critical T1059.004）④60s 重复 DNS→DNS（high T1071.004，高噪声：任意两次 DNS 都命中） | 基础 0.6；前件同 pid +0.2；前件数≥2 +0.1（cap 1.0） |
| Sequence 序列×2 | ①10s 内 读 .encrypted→写→删（勒索链，critical T1486）②60s 内 chmod +s→写 sudoers（critical T1548.001） | 完成链 0.7；首尾 <3s +0.2；gap 超限重置 |
| ProcessTree ×2 | sshd→nc（T1059.004）、cron→wget（T1053.003） | 固定 0.8 |

### 6.5 统计基线 (baseline.rs) — 六维 z-score

- 六维：Syscall/FileOps/NetOps/DnsOps/PtraceOps/SignalOps 频率。`StatBaseline{mean,stddev,max}`（总体标准差）。
- 快照窗口 60s；`max_history_windows=20`；`min_samples=5`（completed 窗口 ≥5 且每窗 syscall_count>1 才建基线——
  **短命进程进不了 baselines**）。
- `established_pids` **一次性训练锁定**（建基线后不再重算，除非 refresh_baseline()）。
- `INHERENTLY_HIGH_FREQ` 18 个 comm 子串（wget/curl/python/node/java/chrome/nginx/sshd/cron 等）。
- **freq_history 守卫（OOM 修复核心）**：所有 PID 先写 `freq_history`（max_pids=10000），超限按 `snaps.last().timestamp_ns`
  最小者淘汰至 9000，并同步清理 baselines+established_pids。旧实现"只看 baselines 淘汰"因短命进程进不了 baselines
  而永不触发（RSS 1.4GB 泄漏根因）。
- 固定阈值 fallback（无基线/冷启动）：syscall 5000 / file 500 / net 100 / dns 50 / ptrace 3 / signal 10（60s）。
- z = (val−mean)/stddev；stddev==0 且 val>mean → z=3；无基线时 val>固定阈值 → z=5；**z>2.0 记偏差**。
  severity：<2 Normal / <3 Low / <4 Medium / <5 High / ≥5 Critical。`overall_score = min(max_z/5, 1)`。

### 6.6 自适应 ML (ml_detector.rs) — EWMA 双模型补充

- EWMA 参数：α=0.3；`variance = (1−α)·(variance + α·diff²)`（Welford 风格）；`COLD_START_SAMPLES=5`（<5 窗口用固定阈值）；
  `DEFAULT_Z_THRESHOLD=2.0`；误报反馈：`false_feedback(pid, true)` → 阈值 multiplier ×1.1，100 个正常样本后 ÷1.1 衰减回原值。
- **5 张 per-PID 表**：states（每 PID×6 维 EWMA）、current_windows、pid_sample_counts、threshold_multipliers、
  normal_samples_since_feedback。
- 窗口 60s；学习期 `observe_until_ns`（/proc/uptime + `KS_ML_OBSERVE_SEC`，默认 180s，期内 detect 返回 None）。
- **LRU 淘汰（OOM 修复）**：`current_windows.len() > 10000` → 按 `timestamp_ns` 最小者删至 9000，并级联清理其余 4 表 + states.retain。
- 输出：z 分 + `AnomalyModel::{Ewma,ColdStart}`；`overall_score = min(max_z/5, 1)`。
- 与 BaselineManager 双模型**并集**：任一触发即告警，severity 取较高（EWMA 擅趋势突变，baseline 擅稳定偏离）。

### 6.7 进程树 (process_tree.rs)

- `ProcessNode{pid,ppid,comm,exe_path,create_time_ns,exit_time_ns,flags{is_root,is_container,is_orphan,is_anomalous},risk_score,events,children}`。
- `update_from_event`：事件 1 更新 comm/exe_path，事件 2 记退出；每节点事件上限 100。
- **6 条 anomaly_patterns**：systemd→nc、cron→nc、bash→wget、sshd→bash、bash→sudo、bash→insmod（各带 MITRE 标注）。
- `get_family(root)` BFS；`all_families()`；`anomalous_families()`（has_anomalous_process 或 anomaly_relations 非空）——
  start.rs 每 500 事件全量扫描，每条 anomaly_relation 出一条 High 告警（rule_name="process_tree_anomaly"）。
- **LRU**：max_nodes=10000，按 create_time_ns 最小者删至 9000（同秒创建节点淘汰顺序不稳定，已知）。
- ⚠️ **风险分继承未实现**：`ProcessNode.risk_score` 字段恒 0——用户态没有从 `risk_scores` map 回灌或父子继承；
  风险分只存在于内核侧 map（供 REST /api/v1/stats 展示）。

### 6.8 攻击链还原 (chain.rs)

- `AttackPhase` 9 阶段 + Unknown：InitialAccess/Execution/Persistence/PrivilegeEscalation/DefenseEvasion/
  CredentialAccess/Discovery/LateralMovement/Exfiltration（LateralMovement 枚举存在但 classify_phase 无分支产出它）。
- 时间窗 300s（从首事件 base_ns 起，超窗事件跳过，非滑窗）；同阶段相邻事件合并。
- 分类依据：bash -i|/dev/tcp、nc -e、ssh -R→InitialAccess；wget/curl/python -c→Execution；/etc/cron、authorized_keys→Persistence；
  chmod +s、LD_PRELOAD、sudo→PrivilegeEscalation；ptrace、strace、/proc/*/mem、rm -rf /var/log→DefenseEvasion；
  /etc/shadow|passwd→CredentialAccess；find|ls|cat+/etc|/proc→Discovery；恶意端口外连→Exfiltration。
- 置信度：`min(phase_count×0.15, 0.8)`；含 InitialAccess/Exfiltration/PrivilegeEscalation 任一段 +0.2（cap 1.0）；
  事件<3 且阶段≥3 → ×0.6。start.rs 仅 confidence>0.5 打印。

### 6.9 取证日志 (forensic.rs)

- 格式：JSONL，每条内容 JSON（BTreeMap 键排序保证确定性）→ `hash = SHA256(内容)`，记录带 `prev_hash`+`hash`；
  GENESIS_HASH=64 个 '0'；事件与告警共用一条哈希链。
- **写路径双层**：`ForensicLogger` 本体是同步写（BufWriter 64KB；`log_event` 每 1000 条 flush；`log_alert`
  每条立即 flush；Drop 兜底）；**start.rs 主循环经 `tokio::sync::mpsc` channel（容量 65536）把事件/告警
  非阻塞发给 forensic_worker task 串行消费**（异步取证写阶段 1 已实现——主循环不等序列化+哈希+落盘，
  见 performance-design §6.4）。轮转 gzip 才用 `std::thread::spawn` 后台压缩（detached 无错误回传）。
- 轮转：max_file_size 默认 100MB → rename `events_YYYYmmdd_HHMMSS.jsonl` → 异步 gzip → 30 天保留清理。
- 链恢复：`recover_chain_state` 扫最后一条含 "seq" 的行续链（告警行无 seq 会被跳过）。
- `verify_chain`：Genesis 起逐行校验 prev_hash 连续性 + 重算 hash，返回 `ChainVerification{total_records,is_valid,broken_at}`。
- `HashAlgorithm` trait + Sha256Hash（可替换）。
- ⚠️ mpsc 满时事件丢失（warn 日志）；worker 崩溃后写入告警丢失。

### 6.10 用户态阻断 (blocker.rs)

- `BlockReason`：RuleMatch=1/BaselineDeviation=2/MlAnomaly=3/Correlation=4/Manual=5。
- `BlockManager{blocked: HashMap<pid, BlockedPid>, enabled, default_ttl=300s}`；TTL：0 用默认，u64::MAX 永不过期。
- ⚠️ 本模块是**纯用户态状态表**，不写内核 `block_decisions` map；真正的强制阻断在内核侧（enforce 模式 SIGKILL）。
  start.rs 用 `config.detection.block_enabled/block_ttl/block_severity_threshold`（默认 critical）驱动告警级阻断决策。

### 6.11 eBPF 加载器 (loader.rs) / LinuxBpfMapReader

- `EbpfLoader` attach 16 探针（hardcoded 列表，tracepoint 5 + kprobe 11，最后 1 个 attach 失败仅 warn）；
  5 个 ringbuf：events/tree_events/freq_events/flow_events/filter_events（legacy/ancient 走 PerfEventArray page_count=64）；
  Drop 打印 syscount（enter/exit/drop 诊断计数）。
- `ProbeConfig/ProbeState` 枚举存在但未实际驱动 attach（文档遗留结构）。
- `BpfMapReader` trait：`read_map/read_map_structured/list_maps/list_map_stats`；`MockBpfMapReader` 6+6 map 桩。
- `LinuxBpfMapReader`：SHARED_MAPS 6 个（risk_scores/ip_whitelist/net_conn_history/freq_counters/infer_config/protected_comms）
  typed 读取（`#[repr(C)]` 键值 + Pod），`/api/v1/stats` 暴露真实 entry_count。只读展示，无回写。
- 保护注入：`inject_protected_pid`（自身+祖先链≤8跳+pid1）、`inject_protected_comms`（11 默认 + KS_PROTECTED_COMMS）。
- `.o` 来源：优先 KS_EBPF_DIR 外部覆盖，否则内嵌 `ebpf_object_for(suffix)`；跨 tier 错误直接 bail。

### 6.12 配置 (config.rs)

- `Config{engine, detection, forensic, network, performance}` 5 子配置；`load_from_file/load_from_yaml/apply_env_overrides/validate`。
- 关键默认值：buffer_size 10000；ring_buffer_size_kb 256；batch_size 64；rules_dir /etc/ks/rules/；
  anomaly_threshold 0.7；block_enabled false；block_ttl 300s；block_severity_threshold critical；log_dir /var/log/ks/；
  max_log_size_mb 100；retention_days 30；hash_chain true；serve_port 3000；bind 127.0.0.1；ws_enabled true。
- **19 个 KS_* 环境变量**：KS_ENGINE_*、KS_DETECTION_*、KS_FORENSIC_*、KS_NETWORK_*、KS_PERFORMANCE_*（解析失败仅 warn）。
- ⚠️ **YAML 配置未接入主程序**：start.rs 用 `Config::default()` + env 覆盖 + CLI 直覆盖（rules_dir/log_dir/serve_port）；
  `load_from_file` 只在测试使用；ring_buffer_size_kb/batch_size/performance.* 无消费点。
- enforce/ML 相关 env：KS_ENFORCE=1、KS_ENFORCE_WARMUP_SEC（默认 120）、KS_ENFORCE_KILL_THRESHOLD（默认 70）、
  KS_ML_SYSCALL_60S 等 5 个、KS_ML_OBSERVE_SEC（默认 180）、KS_EBPF_DIR、KS_LOADER_PATH、KS_PROTECTED_COMMS、KS_AUTH_TOKEN。

---

## 7. 核心类型层 (ks-core)

### 7.1 事件结构体（C/Rust 内存对齐）

`EventHeader` 64 字节 `#[repr(C)]`（编译期 size 断言）：event_type u32 + timestamp_ns u64 + pid/tid/uid u32 + ppid u32 +
comm[16] + syscall_nr i32 + _pad u32 + retval i64。派生结构体：ExecEvent（+filename[256]+args[512]）、FileEvent（+filename[256]+bytes/
fd/flags）、NetEvent（+saddr/daddr/sport/dport/proto/family + saddr6/daddr6[16]）、SignalEvent（+target_pid+signal）、
ContainerEscapeEvent（+ns_inum×2+cap_eff）、LkmLoadEvent（+module_name[64]+comm[16]）、EbpfTamperEvent（+prog_name[64]+action[16]）。

越界保护 `RawEvent::from_bytes` 两阶段：① len ≥ sizeof(EventHeader)；② 按 event_type 查 `min_event_size` 再验。

### 7.2 规则 (rule.rs)

`DetectionRule{name, description, severity(low|medium|high|critical), conditions: Vec<Condition>, alert_message, mitre_tactic, mitre_technique}`
+ `Condition{field: Field, operator: Operator, value: String}`。匹配结果 `MatchResult{rule_name, severity, alert_message, matched_conditions}`。
另外 `lib.rs` 提供 `event_type_from_syscall_nr`（EXECVE→1 / OPEN|OPENAT→10 / CONNECT→20 / PTRACE→30 / KILL→31）与 x86_64/aarch64 syscall 号常量。

### 7.3 告警 (alert.rs)

`Alert{id: Uuid, timestamp_ns, severity, title, description, rule_name, process: ProcessInfo, network: Option<NetworkInfo>,
file: Option<FileInfo>, event_ids, mitre: Option<MitreInfo>, status: AlertStatus, feedback: Option<bool>}`。
`ProcessInfo{pid,ppid,comm,uid,exe_path,cmdline}`；`NetworkInfo{saddr,daddr,saddr6,daddr6,family,sport,dport,proto}`；
`FileInfo{path,operation,bytes}`；`FileOperation` 映射（open=10/read=11/write=12/delete=13/rename=14/chmod=15）。
告警状态流转：new → investigating(ack) / resolved / false_positive(feedback)。

---

## 8. 服务/API 层 (ks-server)

### 8.1 REST 端点（routes.rs 实测，19 个 route）

| 方法/路径 | 鉴权 | 说明 |
|---|---|---|
| GET /api/v1/alerts?limit=100 | ✅ | 告警列表（内存环形，MAX_ALERTS=10000） |
| GET /api/v1/alerts/:id | ✅ | 告警详情 |
| POST /api/v1/alerts/:id/ack | ✅ | → Investigating |
| POST /api/v1/alerts/:id/resolve | ✅ | → Resolved |
| POST /api/v1/alerts/:id/feedback {is_false_positive} | ✅ | 更新 feedback + 调 ml_detector.false_feedback |
| GET /api/v1/stats | ✅ | {total, by_severity(high 合并 Critical), by_status, map_stats[]} |
| GET /api/v1/health | 免 | ⚠️ uptime_secs 硬编码 0 |
| GET /api/v1/tier | ✅ | 纯文本 "tier: {label}" |
| POST /api/v1/reload | ✅ | **stub，返回 202 但无实际操作** |
| GET /api/v1/version | ✅ | CARGO_PKG_VERSION |
| GET /api/v1/baselines | ✅ | 六维行为基线列表 |
| GET /api/v1/correlations?limit=100 | ✅ | 关联告警列表 |
| POST /api/v1/block/:pid?ttl&reason&trigger | ✅ | 用户态阻断（未启用返回 403 FORBIDDEN） |
| DELETE /api/v1/block/:pid | ✅ | 解除阻断 |
| GET /api/v1/blocked | ✅ | 阻断列表 |
| GET /api/v1/maps | ✅ | map 列表 / 503 无 reader |
| GET /api/v1/maps/:name | ✅ | 白名单 6 个：process_tree/net_flows/freq_counters/filter_stats/risk_scores/block_decisions；返回 {map, entry_count, entries} |
| GET /ws/alerts | 免 | WebSocket 推送（broadcast，服务器→客户端 JSON Alert，无心跳无鉴权） |
| GET /metrics | 免 | Prometheus 文本（6 指标） |

### 8.2 安全加固（Phase F4）

- **鉴权 auth.rs**：Bearer token（`--auth-token` 或 KS_AUTH_TOKEN）；白名单 `/health` `/api/v1/health` `/version` `/metrics` +
  全部 `/ws` 前缀；constant_time_eq 固定时间比较；401 {"error":"missing or invalid token"}。
  ⚠️ **安全假象坑**：CLI 未给 token 时 `AuthToken.enabled=true` 但 token=None，中间件直接放行所有请求——与
  status 打印的 "401 for all authed endpoints" 文案矛盾。部署必须显式 `--auth-token`。
- **TLS/mTLS tls.rs**：rustls 0.23 + ring provider；`--tls-cert/--tls-key/--tls-client-ca`；client_ca 存在即 mTLS
  （WebPkiClientVerifier）；alpn h2+http/1.1；证书生成命令见 docs/deployment.md。
- **限流 rate_limit.rs**：tower_governor GCRA，每 IP 每分钟 limit 次（默认 100，`--rate-limit`）；
  ⚠️ 缺失 ConnectInfo（如代理场景）返回 500；0 表示不加层。
- **审计 audit.rs**：每请求 JSONL 一行 {timestamp, client_ip(x-forwarded-for 优先，可伪造), token_id(SHA-256 前 4 字节),
  method, path(含 query), status, latency_ms}，默认 /var/log/kernelsentinel/audit.log。
- **metrics.rs**：6 指标——ks_events_total{event_type}、ks_alerts_total{severity}、ks_map_entries{map_name}、
  ks_event_processing_seconds{event_type}、ks_tier_status{tier}、ks_ringbuf_lost_total。
- 中间件顺序（layer 后入先出，实际执行：rate_limit → auth → audit → 业务）。
- 启动：start.rs `--serve <port>` 内嵌服务（默认跑在 127.0.0.1）；独立二进制 `ks-server-bin` 读 KS_SERVER_PORT（默认 8443），
  默认 insecure。⚠️ watch/baseline/correlation CLI 默认 server 端口 3000，与 ks-server 默认 8443 不一致。

---

## 9. CLI 层 (ks-cli)

### 9.1 子命令一览

| 命令 | 参数 | 说明 |
|---|---|---|
| `start` | -r/--rules-dir、-l/--log-dir、--serve <port>、--sd-notify、SecurityArgs（--no-auth/--auth-token/--tls-cert/--tls-key/--tls-client-ca/--rate-limit/--audit-log） | 主程序：加载 eBPF→规则→引擎→热加载→事件循环→安全退出 |
| `stop` | — | 读 /tmp/ks-status.json → SIGTERM |
| `status` | --watch、--interval（默认 2s） | 16 探针表 + map 快照 + 推理说明 + 规则集 + 配置概览；--watch 实时刷新 |
| `replay` | -f/--file、--json | 哈希链校验 + 事件/告警解析 + sparkline 时间线 + 统计摘要 + MITRE 映射 + 进程画像 |
| `watch` | -s/--server（默认 3000）、-i/--interval、--max、--json | 轮询 /api/v1/alerts 去重输出，JSON 行流可喂 SIEM |
| `baseline` | -s/--server、--json | GET /api/v1/baselines 表格输出 |
| `correlation` | -s/--server、-l/--limit（默认 50）、--json | GET /api/v1/correlations |
| `serve` | -p/--port（默认 8443） | **纯提示文本，不启动任何服务**（CLI-first 模式，真正的服务在 start --serve） |

全局 flag：-l/--log-level（默认 warn）、--color auto|always|never、--json（部分子命令）。main() 启动时
setrlimit(RLIMIT_MEMLOCK=∞)（Linux）。UI 统一用 colored + comfy-table（ui.rs：banner/severity 上色/severity_badge/new_table/step）。

### 9.2 start 主循环（单线程事件泵）

1. `singleton::acquire()` 单实例 fcntl 写锁（/run/ks.lock 或 /tmp/ks.lock）；
2. Config::default + env 覆盖 + validate；tier_detect → default_event_source；
3. --serve 则起 ks-server（共享 map_reader/state）；
4. 加载规则（0 条时警告，只用异常评分）；组装五件套：EventAggregator + BaselineManager + CorrelationEngine(300s) +
   ProcessTreeManager + AdaptiveDetector + BlockManager + ForensicLogger（主循环经 mpsc 65536 异步发给 forensic_worker 串行写，见 §6.9）；
5. 规则热加载线程（5s mtime 扫描，原子替换）+ sd_notify READY（--sd-notify）；
6. 主循环 tokio::select!（ctrl_c / source.next_bytes）；**每事件**：decode → forensic.log_event → baseline.update
   （跳过 protected_pids）→ process_tree.update → correlation.detect_correlations_with_tree（告警输出+阻断）→
   detector.match_event（告警输出+阻断）→ anomaly_score+recent_syscall_count；
   每 50 条轻量扫描（baseline 同步到 serve_state、deviation/ML 告警）；`need_heavy_scan = consumed % 500 == 0 || 有匹配`
   → anomalous_families 全量扫描（process_tree_anomaly 告警）+ chain 重构（confidence>0.5 打印）；
   每 10 条打印进度；
7. 安全退出：drop source（Loader Drop 打印 syscount 诊断）→ flush 取证 → 统计 + 链尾哈希 + prof 摘要（/tmp/ks-prof.log，9 个计时桶）。

### 9.3 replay 详解

`verify_chain` 哈希链完整性 → 逐行解析（type=="alert" 区分告警/事件）→ 8 个阶段输出：
链校验 → 解析 → 统计摘要 → 事件类型分布（comfy-table + sparkline bar）→ 告警等级分布 → MITRE 映射 →
攻击链还原（48 桶 sparkline，按 severity/MITRE 排序）→ 进程行为画像。--json 输出汇总 JSON。

---

## 10. 检测规则集 (rules/)

9 个文件 23 条规则（8-30 后 LD_PRELOAD 规则改为 regex `LD_PRELOAD=[^ ]+\.(so|so\.[0-9])`，空值不再误报）：

| 文件 | 条数 | 覆盖攻击 | MITRE |
|---|---|---|---|
| reverse_shell.yml | 2 | 反弹 shell | TA0001/T1059.004 |
| ransomware.yml | 2 | 勒索（写+删+后缀） | TA0040/T1486 |
| privilege_escalation.yml | 6 | SUID/ptrace/LD_PRELOAD/cron/容器 | TA0004/T1548、T1574.006 |
| data_exfil.yml | 3 | 数据外传 | TA0010/T1041 |
| dns_tunnel.yml | 1 | DNS 隧道 | TA0011/T1071.004 |
| rootkit_detect.yml | 5 | rootkit 加载/隐藏 | TA0005/T1014 |
| container-escape.yml | 1 | 容器逃逸（event_type=80） | TA0004/T1611 |
| lkm-load.yml | 2 | LKM 加载（event_type=81） | TA0005/T1547.006 |
| ebpf-tamper.yml | 1 | eBPF 自身防护（event_type=82） | TA0005/T1070 |

---

## 11. 数据流全链路（端到端）

```
攻击行为（模拟脚本 scenarios/sim_*.sh）
   │ 系统调用 / VFS / 网络栈 / 调度
   ▼
16 个 eBPF 探针（内核态）
   ├─→ 推理引擎：风险分累积（4 维函数，0-100）
   │     ├─ verdict==2 且 enforce → bpf_send_signal(SIGKILL)（仅 modern，有豁免/干跑期防护）
   │     └─ risk≥40 → 事件无条件放行
   ├─→ 智能过滤：白名单/safe_patterns → 丢；风险分或频次异常 → 放行；文件 open/read 恒丢；其余放行
   ├─→ 进程树/网络流/频率计数 map（树/流/频率专用 ringbuf）
   ▼
events ringbuf 16MB（modern）/ perfbuf（老内核）/ C loader stdout 帧流（nobtf）
   ▼
用户态聚合器（两阶段越界校验 + IPv4/IPv6 解码 + argv 分段拼接 + pid_windows LRU）
   ▼
四道检测（每事件同步串行）：
   ① YAML 规则引擎（Field 枚举匹配 + 异常评分 ≥0.7）
   ② 跨事件关联（窗口/序列/进程树，300s 窗）
   ③ 基线偏离（六维 z-score，每 50 条批量）+ EWMA ML（双模型并集）
   ④ 进程树 family 扫描 + 攻击链还原（每 500 事件重扫描）
   ▼
告警（severity + MITRE + 事件关联）→ 阻断决策（BlockManager → 告警级）
   ▼
取证日志（JSONL + SHA-256 哈希链 + 100MB 轮转 + gzip 归档）
   ▼
REST /api/v1/* + WebSocket /ws/alerts + /metrics（可选 --serve）
```

---

## 12. MITRE ATT&CK 覆盖（已实现，23 规则 + 关联 + 推理引擎）

| 战术 | 技术 | 载体 |
|------|------|------|
| TA0001 初始入侵 | T1059 反弹Shell | reverse_shell.yml + 关联 |
| TA0002 执行 | T1059 Python/Perl | chain.rs 分类 + 异常评分 |
| TA0003 持久化 | T1053 Cron | privilege_escalation.yml + vfs_write |
| TA0004 提权 | T1548 SUID / T1055 ptrace / T1574.006 LD_PRELOAD | privilege_escalation.yml + 推理引擎 +35/+20 |
| TA0005 防御规避 | T1070 清日志 / T1014 Rootkit / T1547.006 LKM / T1070 eBPF 篡改 | rootkit/lkm/ebpf-tamper + vfs_unlink + chain |
| TA0006 凭据访问 | T1003 /etc/shadow、.ssh | ransomware.yml + 敏感文件评分 |
| TA0009 横向移动 | ssh 凭据窃取、外连 | data_exfil.yml + 关联 |
| TA0010 数据窃取 | T1041 外传 / T1071 DNS 隧道 | data_exfil.yml + dns_tunnel.yml + udp_sendmsg |
| TA0011 命令控制 | DNS/HTTP C2 心跳 | dns_tunnel + netflow(C2 心跳标志) |
| TA0040 影响 | T1486 勒索 | ransomware.yml + vfs_write/vfs_unlink |

---

## 13. 验证状态（2026-08-31 快照）

### 13.1 自动化测试（实测 168 全过）

| 套件 | 数量 | 覆盖 |
|---|---|---|
| ks-cli 单元 | 5 | start.rs 关联告警转换等 |
| ks-core 单元 | 7 | 结构体对齐/越界/最小尺寸 |
| ks-engine 单元 | 103 | 聚合/检测/关联/基线/ML/树/链/取证/阻断/loader/CLoaderSource 等 |
| ks-engine e2e_attacks | 14 | 12 攻击场景 + 正常无误报 + 阻断生命周期 + 误报反馈 |
| ks-engine integration | 12 | 6 全链路（构造字节流→decode→规则→取证→链）+ 6 事件解码/安全探针正反例 |
| ks-server（单元+集成） | 27 | 端点/鉴权 9/metrics 3/限流 4 |

### 13.2 真机验证

- **三机端到端 2026-08-13**（ks-test-evidence/perf-2026-08-13/三机端到端验证.md）：
  - 3.10 CentOS 7（ancient_nobtf, C loader）：完整 Rust 链路 12 分钟，17,650+ 事件 / 5,092+ 告警，
    取证 23,579 条混合记录 replay 哈希链完整；
  - 5.15 Ubuntu（modern）：1566 告警，map_stats 真实 entry_count 非零，EXIT=0；
  - 6.1 Debian（modern）：62 告警，EXIT=0。
- **长稳 soak**：三机 systemd 部署（Type=notify + CapabilityBoundingSet），monitor 模式，RSS 无增长，取证轮转正常。
- **enforce 阻断**：2026-07-29 5.15 真机验证 bpf_send_signal SIGKILL，触发进程 EXIT=124/137，自身+父链豁免不被杀，
  干跑期防护生效（见 README + ROADMAP G2.1-verify）。
- **本机 7.0**：16/16 探针 verifier 通过，3902 事件 / 20 告警 / 0 丢包 / RSS 2.6MB（2026-07-04）。

### 13.3 性能数据（详见 docs/performance-design.md）

| 指标 | 值 |
|---|---|
| criterion 微基准 | decode 165ns / 规则匹配 677ns-1.19μs / correlation 603-666ns / baseline 37ns / ml 68ns |
| 真机用户态吞吐 | 优化后 1197-1977 events/s（三机），优化前 589-841 |
| 内核侧捕获 | 13.6-52 万 syscall/s（远超申报书 10 万目标） |
| detector_match | 优化前 794-1147μs → 优化后 1.12-2.24μs（~500×，正则预编译） |
| 瓶颈 | **取事件环节**（next_bytes 770μs/事件，CLoaderSource 管道往返+调度）而非处理环节（61μs/事件，理论 16400/s） |
| RSS | 52-94MB（三机真机，<100MB 申报书上限）；本地 loadgen 修复泄漏后 3.9MB |

已验证无效的优化：加大 ringbuf（1MB→16MB）、yield_now 替代 sleep——佐证瓶颈在取事件层。

---

## 14. 关键设计决策（含教训）

1. **内核态做重活**：进程树/网络流/频率计数/风险推理/过滤全在内核，降低用户态负载与 ringbuf 压力。
2. **5 tier + 运行时路由**：modern(5.8+ ringbuf) / legacy(4.x perfbuf) / ancient(3.10) / ancient_nobtf / legacy_nobtf；
   tier_detect 按 osrelease + BTF 存在性选路，3.10 stock 内核走 C loader 旁路（不依赖 aya）。
3. **NOBTF 三层联动**：aya 本地 patch（btf_fd=None 清零 type id）+ build.rs objcopy 剥离 .BTF.ext + 硬编码结构体偏移
   （extract-offsets.sh 从 debuginfo 用 pahole 提取）；单层方案会留下未解析重定位。
4. **C loader 帧协议用 stdout 管道**：内核自动缓冲、子进程崩溃立即 EOF、tokio 原生支持；事件量级 <10K/s 足够；
   心跳帧（30s）区分"无事件"与"卡死"。未来 >100K/s 再上共享内存 ring。
5. **C/Rust 结构体严格对齐**：`#[repr(C)]` + 编译期 size 断言（EventHeader==64）+ 两阶段越界校验。
6. **SHA-256 哈希链取证**：每条记录链接前条 hash，任意篡改后面全断；回复 replay 可验证（三机 23,579 条链完整）。
7. **枚举类型安全规则**：Field/Operator 枚举 + YAML 加载时报错，防静默不匹配。
8. **基线一次性锁定**：established_pids 建基线后不重算，异常数据不会拉偏基线。
9. **双模型并集**：z-score baseline（稳定偏离）+ EWMA（趋势突变），任一命中即告警。
10. **per-PID 结构必配 LRU**（OOM 教训）：ml_detector 5 表 + baseline freq_history 全部加 max_pids=10000 淘汰守卫，
    守卫查真正膨胀的表（旧守卫查 baselines 导致短命进程泄漏，RSS 1.4GB→3.9MB）。
11. **eBPF 无浮点**：风险分 0-100 整数 + 阈值判断；verdict 0/1/2 三态。
12. **阻断分层降级**：modern 内核实杀（bpf_send_signal），legacy/ancient 纯标记，用户态 BlockManager 告警级决策；
    默认 monitor 只告警不杀，enforce 带多层冷启动防护（protected_pids/comms + 干跑期 + kill 阈值 + exe_path 反伪装）。
13. **零外部 AI 依赖**：检测/推理全部手工实现，无 GPU/模型文件。
14. **单二进制交付**：musl 静态（glibc 2.17 起步），5 tier .o + ks_loader 静态二进制 `include_bytes!` 内嵌，零运行时依赖。

---

## 15. 已知坑 / 设计限制（诚实清单）

| # | 坑 | 影响 | 建议 |
|---|---|---|---|
| 1 | `should_send_event` 命名与语义相反（action=1 是丢弃） | 维护易踩坑，filter_stats passed/blocked 计数反转 | 重命名或注释 |
| 2 | `get_config` 死代码：infer_config key 0-4 查不到 | 风险阈值/时间窗/端口扫描阈值配置静默失效 | 修复 switch 或启用 map 查询 |
| 3 | connect 双通道重复上报（tracepoint 42 + kprobe） | 同一连接两条事件，规则可能重复告警 | 二选一或去重 |
| 4 | commit_creds 事件 ns_inum/cap_eff 全 0 | 容器逃逸检测无命名空间信息，仅 comm 规则 | 待补 |
| 5 | LKM 事件双发射点（kprobe 81 + sys_exit 313），313 不在 freq 统计白名单 | 同一 loading 两条事件；finit_module 失败也发 | 合成/去重 |
| 6 | 用户态↔内核 anomaly_flags 无闭环 | "用户态检测反馈内核过滤"未实现 | 待实现 |
| 7 | 风险分继承未实现（ProcessNode.risk_score 恒 0） | 进程树告警缺风险分维度 | 待实现 |
| 8 | YAML 配置文件未接入主程序（只用 env + CLI） | docs/deployment 声称的配置文件不生效 | 接入 load_from_file |
| 9 | ks-server 无 token 时放行所有请求（与文案矛盾） | **安全假象**，部署必须显式 --auth-token | 修复或文档警示 |
| 10 | /api/v1/reload 是 stub；health uptime 硬编码 0 | 语义不完整 | 实现或移除 |
| 11 | NOBTF inet 偏移靠 extract-offsets.sh 针对特定内核 release | 换内核版本偏移漂移导致读错 | 限定 3.10.0-1160 / 4.19. 前缀守卫已兜底 |
| 12 | vmlinux.h helper 编号与主线不同（112-115） | 用标准编号的工具会误判 | audit 脚本内置本项目编号 |
| 13 | process_tree LRU 按 create_time_ns 淘汰，同秒节点顺序不稳定；all_families 每 500 事件全量 BFS | 1 万节点规模开销 | 分桶/惰性 |
| 14 | correlation 窗口规则 ④ 任意两次 DNS 都命中 | 高噪声 | 加频次条件 |
| 15 | forensic_worker mpsc(65536) 满时丢事件（warn）；本体每 1000 条才 flush | 极端洪峰下崩溃可能丢事件 | 有界队列+落盘批量化 |
| 16 | 取证 gzip 线程 detached 无错误回传；CLoaderSource::kind() 恒标 ancient_nobtf | 运维盲区/信息不实 | 修 |
| 17 | ks-cli `serve` 子命令不干事；watch/baseline/correlation 默认端口 3000 vs ks-server 8443 | 使用困惑 | 对齐端口 |
| 18 | auth 白名单含 `/health` 但无该路由；/version（免）与 /api/v1/version（鉴权）不一致 | 配置困惑 | 清理 |
| 19 | x-forwarded-for 直接信任；CORS permissive | 审计 IP 可伪造 | 配置化 |
| 20 | 3.10 之前内核（2.6）→ 静默 fallback mock | 假装检测中 | 显式告警 |

---

## 16. 路线图对照

- **Phase E（多 tier 端到端 + 生产化 + 检测扩展）**：14 项全部完成（E1 现代 tier、E2 3.10 ECS、E3 文档/systemd、
  E4 三个安全探针）。
- **Phase F（工程化：CI/CD + Docker + 可观测性 + 安全加固）**：完成（F1-F4）。
- **Phase G（检测深化：自适应检测 + 内核阻断 + e2e + 压测 + 教学）**：完成（G1-G6）。
- **进行中/待办**（见 docs/HANDOFF-2026-08-11.md）：5.15 机器 6 小时 soak 数据补齐、enforce 误判治理（扩 protected_comms）、
  3.10 机器 SSH 恢复、规则热更验证、告警通道、SIEM 对接（F-7 未开始）、ARM64（F-4 未开始）、分布式（F-6 未开始）。

详细 roadmap 见 [ROADMAP.md](ROADMAP.md)，Phase E 决策汇总见 [docs/phase-e-summary.md](docs/phase-e-summary.md)。
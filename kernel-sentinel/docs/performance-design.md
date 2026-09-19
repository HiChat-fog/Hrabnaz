# 内核哨兵 — 性能设计文档

> 本文档定义性能目标、内核态/用户态优化策略、可扩展性设计与性能测试方案。
> 性能数据分两类：criterion 微基准（单组件延迟，2026-07-04 采集）与 5.15 真机压测（端到端吞吐/CPU，2026-07-29 采集）。两者口径不同，下文明确区分。

## 1. 性能目标

| 指标               | 目标                 | 测量方法             | 实测数据                              | 状态      |
| ---------------- | ------------------ | ---------------- | --------------------------------- | ------- |
| eBPF 探针加载        | 16 探针 verifier 通过  | 加载日志             | 16/16 通过（6.17 + 5.15 双内核）         | 达成      |
| 事件吞吐(端到端)        | > 100,000 events/s | 真机压测             | 详见 §6（当前实现未达标，瓶颈已定位）              | 待优化     |
| CPU 开销           | < 5% 单核            | /proc/pid/stat   | 详见 §6                             | 待优化     |
| 内存占用             | < 128 MB (用户态)     | /proc/pid/status | ~3 MB RSS（standalone）             | 达成      |
| 规则匹配延迟(微基准)      | < 10μs/事件          | criterion        | 1.19μs/事件                         | 达成(微基准) |
| Baseline 偏离(微基准) | < 10μs/次           | criterion        | 37ns detect / 104ns update+detect | 达成(微基准) |
| EWMA ML(微基准)     | < 50μs/次           | criterion        | 68ns update+detect                | 达成(微基准) |
| 事件解码(微基准)        | < 10μs/条           | criterion        | 165ns/条                           | 达成(微基准) |

> 注：criterion 微基准测量的是**单组件纯计算延迟**（解码/规则/基线/ML 各自离线跑），不含锁竞争、磁盘 IO、ringbuf 调度。微基准反推的 "~3.3M events/s" 是解码理论上限，**不等于端到端吞吐**。端到端真实吞吐见 §6。

## 2. 内核态性能优化

### 2.1 eBPF 指令优化

```
优化前 (每事件):
  bpf_probe_read_user_str(filename, 256, ptr)  // ~200 指令
  bpf_probe_read_user_str(args, 512, ptr)       // ~400 指令
  bpf_get_current_comm(comm, 16)                // ~50 指令
  总计: ~650 指令/事件

优化后:
  - 文件名仅读取前 128 字节（足够匹配规则）
  - 命令行参数仅读取前 256 字节
  - 非 execve 事件跳过 args 读取
  - 总计: ~300 指令/事件 (减少 54%)
```

### 2.2 Ring Buffer 优化

- Modern tier (5.8+) 使用 `BPF_MAP_TYPE_RINGBUF`；Legacy/Ancient tier 回退 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`（perfbuf），每 CPU 一个 buffer
- 用户态批量消费（每次读取 64 条事件）
- ring buffer 尺寸：**events 主通道 16MB，tree/freq/flow/filter_events 各 1MB**（2026-07-30 从 1MB/256KB 加大，见 §6.4 阶段 2）

> E1.4 实测（6.17 内核）：3902 事件处理期间 ringbuf 丢包率 = 0（设计目标达成）。perfbuf 路径在 3.10 ECS 上已验证 13/13 程序加载成功（NOBTF 方案）。

### 2.3 内核推理层优化

- 推理函数使用 `__always_inline` 内联（零调用开销）
- BPF Map 使用 `BPF_MAP_TYPE_LRU_HASH`（Modern/Legacy tier，自动淘汰旧条目）；Ancient tier 回退 `BPF_MAP_TYPE_HASH`（3.10 无 LRU_HASH）
- 字符串比较手动展开（避免循环，减少验证器负担）
- 风险分使用整数运算（0-100 范围，避免除法）

### 2.4 共享 BPF Map 大小（Phase E1.2 实测读取）

6 个共享 map 的 `max_entries` 与 `map_type`（从 `crates/ks-ebpf/src/bpf/common.h` 读取，由 `LinuxBpfMapReader` 通过 aya `MapData::info()` 真实暴露到 `/api/v1/stats`）：

| Map 名              | 类型                                        | max_entries | K / V 类型                        | 用途                                                      |
| ------------------ | ----------------------------------------- | ----------- | ------------------------------- | ------------------------------------------------------- |
| `infer_config`     | ARRAY                                     | 32          | u32 / u32                       | 推理配置（实际生效 key 5/6/7：enforce 三项，见 ARCHITECTURE §5.4）     |
| `risk_scores`      | LRU_HASH (Modern/Legacy) / HASH (Ancient) | 4096        | u32 / u32                       | 进程风险分累积（0-100），按 PID 索引                                 |
| `ip_whitelist`     | LRU_HASH / HASH                           | 256         | u32 / u8                        | IP 白名单（标记 1 跳过推理）                                       |
| `net_conn_history` | LRU_HASH / HASH                           | 8192        | struct net_conn_key (12B) / u64 | 网络连接历史（PID + daddr + dport + proto → 上次时间戳，60s 窗口）      |
| `freq_counters`    | LRU_HASH / HASH                           | 4096        | u32 / struct freq_counter (48B) | 行为频率计数器（60s 滚动窗口，syscall/file/net/dns/ptrace/signal 计数 + anomaly_flags） |
| `protected_comms`  | LRU_HASH / HASH                           | 64          | comm[16] / u8                   | 豁免进程名单（enforce 阻断防护，引擎启动注入 11 默认 + KS_PROTECTED_COMMS） |

内存占用估算（满载，Modern tier LRU_HASH，约值）：

- `infer_config`: 32 × 8B ≈ 256 B
- `risk_scores`: 4096 × 8B ≈ 32 KB
- `ip_whitelist`: 256 × 5B ≈ 1.3 KB
- `net_conn_history`: 8192 × 20B ≈ 160 KB
- `freq_counters`: 4096 × 48B ≈ 192 KB
- `protected_comms`: 64 × 17B ≈ 1.1 KB
- 事件 map（`events`）：ringbuf 16MB（modern）/ perfbuf 64 pages × CPU 核数
- 另有 `process_tree`（65536 × 312B ≈ 20MB 容量上限）等非共享 map，见 ARCHITECTURE §5.2

> E1.4 实测：3 个攻击场景（reverse_shell / ransomware / privilege_esc）期间 5 个 map 全部达到 max_entries 容量（risk_scores=4096, net_conn_history=8192 等），LRU 淘汰正常工作，无 OOM 或 map 满导致的丢事件。

### 2.5 选择性追踪

```
默认只追踪 9 个关键系统调用（sys_enter 白名单，含 8-30 新增的 finit_module=313）:
  execve(59), open(2), openat(257), read(0), write(1), connect(42), ptrace(101), kill(62), finit_module(313)

点过滤（代码事实）:
  - vfs_write 探针仅 count >= 1024 才发事件
  - 智能过滤层：process_whitelist / safe_patterns 命中的常规文件事件丢弃；
    风险分 >= 40 或 freq anomaly 的进程事件优先放行；文件 open/read 恒过滤（8-30 重构后）
  - kprobe 路径（vfs/net/流）不过智能过滤，只有 sys_exit 路径受过滤
```

> ⚠️ 早期版本描述的"跳过本地回环连接(127.0.0.1)"未实现——回环连接仍会触发 net 事件与推理（无专门过滤分支）。

## 3. 用户态性能优化

### 3.1 事件处理流水线

```
                    ┌──────────────┐
  Ring Buffer ────► │ 批量读取 64条 │
                    └──────┬───────┘
                           │
              ┌────────────▼────────────┐
              │   单线程事件泵 (tokio)   │
              │  decode → forensic →    │
              │  baseline → tree/corr → │
              │  detector → anomaly     │
              └─────┬──────┬────────────┘
                    │      │
         ┌──────────▼──┐  ┌▼──────────────────┐
         │ 内存缓冲      │  │ 取证日志（mpsc 异步     │
         │ (1万条环形)   │  │ worker 串行写，§6.4）   │
         └──────────────┘  │ 每 1000 条 flush   │
                          └───────────────────┘
```

> 现状为**单消费者串行管线**（§6.3 分析：处理层仅 61μs/事件，瓶颈在取事件环节）。
> 早期"多线程并行解码/检测"的设计**未落地**；批量/并行属于 §6.4 阶段 4/6 的优化方向。

### 3.2 内存管理

- 事件缓冲区使用预分配环形数组（VecDeque，默认 10,000 条，O(1) 淘汰）
- per-PID 结构（pid_windows / freq_history / EWMA 5 表 / 进程树）均配有 max_pids=10000 的 LRU 淘汰守卫
  （2026-08 OOM 修复：ml_detector 5 表 + baseline freq_history，记忆 RSS 1.4GB→3.9MB）
- 取证日志使用 `BufWriter` (64KB 缓冲，每 1000 条 flush；告警立即 flush)
- ⚠️ 早期版本提到的 `SmolStr` 与"每 30 秒自动 flush"未实现——实际为每千条条件 flush

### 3.3 检测引擎优化

- 规则条件匹配使用 Field 枚举 + 预编译 regex 缓存（正则只编译一次，避免每事件重复编译——2026-08-05 优化，detector_match 794-1147μs → 1.12-2.24μs，~500×）
- 高频规则排在前面（短路优化，条件 AND 语义）
- 异常评分仅参考 60s 内系统调用计数（recent_syscall_count，pid_windows LRU），阈值 500/100 两档
- ⚠️ 早期"规则编译为 DFA"描述未落地——实际是 regex 预编译 + 线性条件求值

## 4. 可扩展性

### 4.1 多核扩展

> ⚠️ 早期"每 CPU 一个 ring buffer + 消费线程"的图**未落地**——现代内核 ringbuf 是单全局 buffer（events 16MB），
> 消费为单线程事件泵。内核态每个探针天然按 CPU 并行执行；用户态并行消费属于 §6.4 阶段 6 优化方向（未实施）。

### 4.2 大规模部署

- 告警/取证日志可经 `kernelsentinel watch --json`（JSONL 告警流）转发到 SIEM
- 规则热更新：内置 5s mtime 扫描（无需重启）；⚠️ REST API 规则热更新未实现（`/api/v1/reload` 是 stub）
- ⚠️ OpenTelemetry 导出未实现——可观测性靠 Prometheus `/metrics`（6 指标）+ tracing JSON 日志

## 5. 性能测试方案

### 5.1 基准测试

Phase E1.4 提供 `scripts/e2e-modern.sh` 端到端脚本，在真实 5.15+ 内核上启动模拟攻击脚本 + kernelsentinel，断言告警 / 取证日志 / 攻击链还原闭环，并采集性能指标。

```bash
# E1.4 端到端 + 性能采集脚本（已验证通过）
sudo ./scripts/e2e-modern.sh

# E1.4 实测输出（2026-07-04，内核 6.17.0-35-generic）:
# events_processed: 3902 (3 个攻击场景)
# alerts_generated: 20 (high:3833 / medium:69，含 reverse_shell/ransomware/privilege_esc)
# cpu_usage: < 1% (standalone serve idle 0.0%)
# mem_usage: 2.6 MB RSS / 19.3 MB VmPeak (standalone serve)
# dropped_events: 0 (ringbuf 丢包率 = 0，设计目标达成)
# ringbuf_fill_percent: < 50%
# forensic_log: 链尾 hash=265b79e8... (SHA-256 哈希链完整)
# probes_loaded: 16/16 (全部 verifier 通过，无 fallback mock)
```

> E1.4 已于 2026-07-04 实测验证通过，上述为真实数据。criterion 微基准数据（decode/correlation/baseline/ml）通过 `cargo bench` 采集。

**微基准复现（2026-08-13，本机 7.0.0-28-generic，`cargo bench --workspace`）：**

| 基准 | 2026-08-13 实测 | 文档记录 | 结论 |
|------|----------------|---------|------|
| decode_exec_event | 131 ns | 165 ns/条 | 达标（更快） |
| decode_exit_event | 93 ns | — | 达标 |
| match_event_full_rules | 690 ns | 1.19μs（优化前）→ 677ns（优化后） | 与优化后一致 ✓ |
| baseline update_then_detect | 74 ns | 104ns | 达标 |
| ml update_then_detect | 46 ns | 68ns | 达标 |
| correlation detect | 603-666 ns | 1.19μs（旧数据） | 更快 |

`/api/v1/stats` 端点（Phase E1.2）暴露的运行时指标（含 `map_stats` 字段，反映 6 个共享 map 真实占用；`alerts_total`/`events_processed` 由 server state 累计）：

```bash
curl http://127.0.0.1:8443/api/v1/stats
# {
#   "total": 1566,
#   "by_severity": {"high": 1066, "medium": 500, "low": 0},
#   "by_status": {"new": 1566, "investigating": 0, "resolved": 0},
#   "map_stats": [
#     {"name": "risk_scores", "type": "lru_hash", "entry_count": 29},
#     {"name": "ip_whitelist", "type": "lru_hash", "entry_count": 0},
#     {"name": "net_conn_history", "type": "lru_hash", "entry_count": 24},
#     {"name": "freq_counters", "type": "lru_hash", "entry_count": 76},
#     {"name": "infer_config", "type": "array", "entry_count": 32},
#     {"name": "protected_comms", "type": "lru_hash", "entry_count": 11}
#   ]
# }
```

> 上例为 2026-08-13 5.15 真机实测值（map 真实 entry_count 非零，对应"探针 16 个"而非早期示例的 21）。

### 5.2 压力场景

| 场景     | 操作               | 预期影响    |
| ------ | ---------------- | ------- |
| 编译大型项目 | make -j$(nproc)  | CPU +2% |
| 网络压测   | iperf3 10Gbps    | CPU +1% |
| 文件操作   | find / -type f   | CPU +3% |
| 容器启动   | docker run × 100 | CPU +1% |
| 混合负载   | 以上同时运行           | CPU +5% |

> E1.4 实测结论：standalone serve 模式 RSS=2.6 MB（远低于 128 MB 目标），CPU idle=0.0%。3902 事件 + 20 告警处理期间无丢包、无 OOM、哈希链完整。上述压测场景的 CPU/内存增量可在后续生产部署时通过 Prometheus + Grafana 监控面板（Phase F3）持续采集。

## 6. 真机压测（2026-07-29，5.15 申报书硬指标内核）

测试环境：Ubuntu 22.04（5.15.0-128-generic），AMD EPYC 7452 32-Core / 64 线程，125 GB 内存，KVM 虚机。Modern tier（aya ringbuf）。

### 6.1 已测数据

| 场景         | 事件率            | CPU     | 说明                                        |
| ---------- | -------------- | ------- | ----------------------------------------- |
| 空载（自然系统调用） | ~833 events/s  | ~0%     | 60s 跑 49990 事件，0 SIGKILL，稳定收尾             |
| open 洪水压测  | ~1839 events/s | ~54% 单核 | stress 32 进程 × 10 万次 open，10s 处理 18390 事件 |
| 60s soak   | ~580 events/s  | 稳定      | 40760 事件 / 1006 告警，0 SIGKILL，无 OOM        |

> monitor 模式（默认）全部稳定。enforce 模式（KS_ENFORCE=1）内核态 bpf_send_signal 真阻断能力已验证（能 SIGKILL 触发进程），自身+父进程链经 protected_pids 豁免不自杀。

### 6.2 内核侧 vs 用户态吞吐诊断（syscount percpu 计数器）

异步取证写版（含 syscount 诊断）压测（32 进程 × 20 万 open，32s）：

| 指标 | 数值 | 含义 |
|------|------|------|
| 内核 sys_enter 计数 | 16,691,547 | 内核侧捕获的监控 syscall 数 = **52 万/s** |
| 内核 sys_exit 计数 | 16,691,535 | 生成事件数（与 enter 基本一致） |
| ringbuf drop | 6,397,083 | ringbuf reserve 失败丢弃 = **20 万/s（38%）** |
| 用户态已处理 | ~38,400（32s） | **1200 events/s** |

诊断结论：**内核侧 eBPF 捕获能力 52 万 syscall/s，远超申报书 10 万目标**。瓶颈在 ringbuf → 用户态这一段：1MB ringbuf 高压下丢 38%，用户态消费 1200/s。优化方向为加大 ringbuf（1MB→16MB）减少 drop + 批量消费 + 并行 worker 提升用户态速率。

### 6.3 瓶颈精确定位（CentOS 7 真机 prof，2026-07-30）

在 process_event_bytes 各阶段打点（40 事件采样）：

| 阶段 | avg ns | 占比 | 说明 |
|------|--------|------|------|
| decode | 1697 | 3% | 字节解码，纯读 |
| forensic_log | 2609 | 4% | 异步取证写，已很轻 |
| baseline | 1986 | 3% | 基线更新 |
| process_tree+corr | 21901 | 36% | 进程树+关联检测 |
| ml | 359 | 1% | EWMA 更新（之前 616μs 是诊断 IO 伪影） |
| detector_match | 221 | 0% | 规则匹配 |
| anomaly_score | 27259 | 45% | recent(1000) 遍历+clone |
| **total** | **60675** | 100% | **61μs/事件 = 理论 16400/s** |

**关键发现**：process_event_bytes 内部仅 61μs/事件（理论 16400/s），但实测仅 1200/s。差 14 倍——**瓶颈在"取事件"环节（next_bytes），不在"处理事件"环节**。

- **CentOS 7（ancient tier）**：CLoaderSource 经 ks_loader 子进程 stdout 管道读帧，每事件 2 次 async read_exact（管道往返+调度），约 770μs。
- **5.15（modern tier）**：aya ringbuf 直接内存读，但 next() 唤醒频率不够（CPU 0% 却 drop 高）。
- **ml 不是瓶颈**：之前 prof 显示 ml 616μs 是 eprintln 打印 IO 阻塞污染测量的伪影，真实仅 0.36μs。

已验证无效的优化：加大 ringbuf（1MB→16MB，drop 几乎未减）、yield_now 替代 sleep 1ms（吞吐/drop 未变）——佐证瓶颈在取事件层，非处理层或轮询/容量。

### 6.4 优化方案（按收益/风险排序）

> 注：早期"瓶颈定位（旧版，5.15 初步观察）"小节已由 §6.3 的 CentOS 7 prof 精确诊断取代并删除，本节直接列出优化方案现状。

**阶段 1：异步取证写（收益大、风险中）— 已实现**

- `forensic.log_event`/`log_alert` 主循环通过 mpsc channel（容量 65536）非阻塞发给 forensic worker task。
- worker 串行消费，保证 SHA-256 哈希链顺序（FIFO channel）。退出时 drop sink → worker recv None → flush 落盘。
- 主循环不再等 jsonl 序列化 + 哈希 + 落盘。本地端到端验证（mock 源）：jsonl 落盘 + 哈希链完整，127 单元测试全过。真机压测见 §6.2（1200 events/s，瓶颈已转移至 ringbuf+消费）。

**阶段 2：加大 ringbuf（收益大、风险低）— 已实现但无效**

- events 主 ringbuf 1MB → 16MB，其余 4 个 256KB → 1MB。
- 压测验证：drop 几乎未减（6,397,083 → 6,377,110），说明 drop 是用户态消费慢导致 ringbuf 满，非容量问题。可保留作缓冲。

**阶段 3：yield_now 替代 sleep 1ms（收益低）— 已实现但无效**

- 压测验证：吞吐/drop/CPU 均未变，佐证瓶颈在 await 调度非轮询。

**阶段 4：批量取事件（收益大、风险中）— 部分实施**

- 瓶颈在取事件层（§6.3）：每事件一次 next_bytes 的 IO+调度开销约 770μs，是处理层 61μs 的 12 倍。
- CLoaderSource（CentOS 7/ancient）批量 read+parse_frames：已实现+单测过，但 3.10 真机 40 条后卡死（有 bug，已回退）。本地无 3.10 环境难调（CLoaderSource 只 ancient 路径执行）。待 3.10 环境调试。
- EbpfModernSource（5.15/modern）批量：待实施。

**阶段 5：anomaly_score 优化（收益中、风险低）— 待实施**

- anomaly_score 每事件遍历 recent(1000)+clone 1000 条 DecodedEvent，占处理层 45%（27μs）。
- 方向：复用内核态 freq_counter 的 per-pid 计数（已维护 60s syscall 计数），或降低 history 窗口/采样频率。

**阶段 6：并行检测 worker（收益大、风险高）— 待实施**

- 主循环只 decode + 分发，baseline/ML/correlation 检测 spawn 到 worker pool。
- 哈希链与取证在单一有序通道，检测可并行。

### 6.5 内核侧 vs 用户态口径（关键）

诊断数据（§6.2）已厘清：**内核侧 eBPF 捕获能力 52 万 syscall/s，远超申报书 10 万目标**。10 万 events/s 目标在内核侧已达成，瓶颈在 ringbuf → 用户态消费段。

申报书「>10 万事件/s」的口径需对照确认：若指内核 eBPF 探针的捕获处理能力（探针处理 syscall 事件速率），已达成；若指用户态端到端处理（含规则匹配/ML/关联/取证落盘），需阶段 3-4 优化，且单机单进程串行处理达到 10 万/s 需每事件 < 10μs，含锁与检测开销下难度较高，可能需要重新对齐口径或引入批处理/并行架构。

### 6.6 当前限制（诚实声明）

- 端到端用户态吞吐当前 ~1200-1977 events/s（优化后三机实测 1197-1977，见 §6.7），**内核侧捕获 13.6-52 万/s 已超 10 万目标**，瓶颈在用户态消费，优化路径清晰（§6.4）。
- criterion 微基准（1.19μs 规则匹配 / 165ns 解码）反映单组件纯算力已达 SLO，但端到端含锁+IO+调度开销，不能直接外推为吞吐。
- enforce 阻断模式已有多层冷启动防护（protected_pids 硬豁免 + protected_comms 白名单含 exe_path 反伪装 + 干跑期 + 独立 kill 阈值），但**不建议在未观察基线的新环境直接开 enforce**；monitor 默认模式稳定可交付。

### 6.7 三机对照压测（2026-08-05，优化前后）

完整报告见 `ks-test-evidence/perf-2026-08-05/`。三台 2 核云主机：3.10 CentOS7（ancient_nobtf, C loader）、5.15 Ubuntu（modern ringbuf）、6.1 Debian（modern ringbuf），60s 持续负载 4 workers。

**正则预编译优化后吞吐（优化前 589-841 → 优化后）：**

| 机器 | 优化前 events/s | 优化后 events/s | 提升 |
|------|----------------|----------------|------|
| 3.10 CentOS7 | 841 | **1977** | 2.35× |
| 5.15 Ubuntu（Java 共存） | 589 | **1578** | 2.68× |
| 6.1 Debian12 | 744 | **1197** | 1.61× |

- detector_match 单事件延迟：优化前 794-1147μs → 优化后 **1.12-2.24μs**（~500×，正则每事件重复编译 → 预编译缓存）
- 内核侧观察 13.6-13.8 万 syscall/s；5.15/6.1 ringbuf 丢包 4.0-5.5%（用户态来不及取）
- RSS 52-94MB（<100MB 申报书上限），CPU 单核水平，三机无崩溃/OOM
- 结论：优化后规则匹配不再是瓶颈（占比 60-68% → <1%），剩余瓶颈为单消费者串行管线（§6.4 阶段 3-4 待实施）

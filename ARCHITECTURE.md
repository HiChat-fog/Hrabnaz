10.15架构设计文档

---

## 1. 项目定位

基于 eBPF 的 Linux 服务器端内核级威胁检测系统。

用 eBPF 把感知探针植入系统调用、VFS、网络栈、进程调度等内核关键路径，在内核态完成
"进程树拓扑 + TCP 流状态机 + 六维频率计数 + 风险分推理 + 事件智能过滤"，用户态用 Rust 做
"规则匹配 + 跨事件关联 + z-score/EWMA 基线偏离 + 攻击链还原"，取证日志用 JSONL + SHA-256 哈希链防篡改；
阻断走双路径：Modern 内核 `bpf_send_signal(SIGKILL)` 现场直杀，Legacy/Ancient 由用户态 killer 轮询补杀。

现状

| 维度 | 状态 |
|------|------|
| 真机验证 | CentOS 7.2（3.10）与 Debian 12（6.1）两台云服务器常驻，systemd 部署；4.19 在 VM 上完成功能验证（16/16 attach + LKM 命中） |
| 攻击场景 | 六类攻击场景（反弹 Shell/勒索/提权/DNS 隧道/Rootkit/数据窃取）端到端全部命中；阻断闭环在两种执行路径分别真机验证（3.10 用户态补杀 1.5s 内；6.1 内核直杀退出码 137） |
| 测试 | `cargo test --workspace` 实测 2026-10-10：**175 个测试全过**（含 BTF 等价性与毒化回归） |
| CI | GitHub Actions 六 job：全量测试、五档 eBPF 编译产物断言、clippy -D warnings、rustfmt、ShellCheck、cargo audit |
| 交付形态 | musl 静态单二进制，无运行时依赖，`scripts/pack.sh` 打 tar.gz 交付包 |
| 长稳 | 8 月修复 ml_detector/baseline 表膨胀 OOM（加 LRU + 淘汰守卫），本地 RSS 1.4GB→3.9MB，误报 150 万→33 |
| 阻断能力 | 规则级 enforce 闸门（默认全 audit），系统进程双侧豁免（comm + exe 路径复核），裁决表 TTL 300s |
| 上游贡献 | aya PR #1661（sk_skb/sk_msg FdLink）已合并；PR #1751（无 BTF map 创建修复）在审 |

---

## 2. 总体架构

四层架构，自下而上：

```
┌──────────────────────────────────────────────────────────────────┐
│  CLI 交互层 (ks-cli)                                              │
│  start / stop / status / replay / watch / baseline / correlation │
│  block / unblock / blocked / watchdog / rules-digest             │
│  单实例锁 + SIGTERM 优雅退出；start 为薄壳(UI渲染+信号)            │
├──────────────────────────────────────────────────────────────────┤
│  用户态引擎层 (ks-engine)                                          │
│  事件源(tier路由) → 聚合解码(两阶段越界保护)                           │
│   → 规则引擎 → 关联引擎(窗口/序列/进程树)                             │
│   → 统计基线(六维z-score) → 自适应异常(EWMA+冷启动)                   │
│   → 取证哈希链(JSONL)   → 用户态 killer(补杀)                        │
├──────────────────────────────────────────────────────────────────┤
│  内核态原语与语义层 (ks-ebpf/src/bpf)                               │
│  状态原语: process_tree / freq_counters /                         │
│           net_conn_history / risk_scores                         │
│  检测语义: infer_* 风险映射 / KS_MAYBE_BLOCK 阻断决策                │
│  裁决通道: block_decisions map / 保护名单                           │
├──────────────────────────────────────────────────────────────────┤
│  内核探针层 (17 个挂载点)                                           │
│  raw_syscalls enter/exit │ sched fork/exec/exit                  │
│  vfs open/write/unlink │ tcp_v4/v6_connect │ udp_sendmsg         │
│  tcp_set_state │ tcp_sendmsg │ do_init_module │ ...              │
└──────────────────────────────────────────────────────────────────┘
```

核心数据流：探针捕获 → 内核过滤（低价值事件丢弃，不进缓冲）→ 内核状态更新与风险评分 →
上行事件（携带内核判定）→ 用户态四层检测 → 告警/取证/裁决。正常行为零事件上行。

---

## 3. 技术栈

| 层 | 选型 | 说明 |
|---|---|---|
| 内核态 | C（libbpf 风格头文件） | 2179 行，`SEC(...)` 显式挂载，CO-RE |
| 加载器 | aya 0.14.0 vendor fork（+6 处老内核补丁，清单见 vendor/aya/PATCHES.md） | 纯 Rust 加载器，自维护不随上游 |
| 用户态 | Rust stable | 引擎 + CLI，运行期 unsafe 0 处 |
| 规则 | YAML | 14 个文件 40 条规则，加载期枚举校验 |
| 取证 | JSONL + SHA-256 哈希链 | 链尾外置，BTreeMap 规范化序列化 |
| 构建 | build.rs + clang/llvm-18 | 五档编译产物，CI 断言数量 |
| 部署 | systemd Type=notify | capability 限 CAP_BPF/CAP_PERFMON |

---

## 4. 仓库布局

```
kernel-sentinel/
├── Cargo.toml              # workspace: ks-cli / ks-core / ks-ebpf / ks-engine
├── crates/
│   ├── ks-cli/             # 命令行入口，start 主循环（单线程事件泵）
│   ├── ks-core/            # 事件/规则/告警核心类型（C/Rust 内存对齐契约）
│   ├── ks-ebpf/            # eBPF 源码（src/bpf/*.h 分层）+ AyaUp_ebpf 嵌入
│   └── ks-engine/          # 引擎：事件源/聚合/检测/关联/基线/ML/取证/阻断/加载器
├── rules/                  # 14 个 YAML 规则文件，40 条规则
├── scripts/                # pack.sh / install.sh / uninstall.sh / e2e 脚本
├── scenarios/              # 六类攻击场景触发脚本 sim_*.sh
├── deploy/                 # systemd unit
└── .github/workflows/ci.yml
```

注意：`realdocs/` 为本地文档目录（gitignored），`vendor/aya` 为带补丁的 aya 副本（2.3 万行）。

---

## 5. 内核探针层 (ks-ebpf)

### 5.1 探针矩阵 — 17 个挂载点（从 SEC 段实测）

**tracepoint（5）**：

| SEC | 文件 | 作用 |
|---|---|---|
| tracepoint/raw_syscalls/sys_enter | ks_probes_syscall.h | 16 个白名单 syscall 的行为捕获 |
| tracepoint/raw_syscalls/sys_exit | ks_probes_syscall.h | syscall 退出（返回值判定） |
| tracepoint/sched/sched_process_fork | ks_probes_process_tree.h | 拓扑建子节点、风险继承 |
| tracepoint/sched/sched_process_exec | ks_probes_process_tree.h | 更新 comm/exe、create_time 刷新、风险分重置 |
| tracepoint/sched/sched_process_exit | ks_probes_process_tree.h | 节点退出标记 |

**kprobe/kretprobe（12）**：

| SEC | 文件 | 作用 |
|---|---|---|
| kprobe/tcp_v4_connect / tcp_v6_connect | ks_probes_net.h | 出连行为与五元组捕获 |
| kprobe/udp_sendmsg | ks_probes_net.h | UDP 行为（DNS 隧道输入） |
| kprobe/tcp_set_state | ks_probes_net.h | 连接状态机里程碑（经 socket 反查绑定表） |
| kprobe/tcp_sendmsg | ks_probes_netflow.h | 外传流量累计 |
| kprobe/vfs_open / vfs_write / vfs_unlink | ks_probes_vfs.h | 文件打开/写/删（敏感文件与勒索行为） |
| kprobe/do_splice_direct | ks_probes_vfs.h | cp/cat/sendfile 落盘写（绕过 vfs_write 的 splice 路径，H-1.3） |
| kprobe/do_init_module | ks_probes_lkm.h | LKM 加载主路径（CO-RE 读 mod->name） |
| kretprobe/load_module | ks_probes_lkm.h | 3.10 无 do_init_module 符号时的回退 |
| kprobe/commit_creds | ks_probes_syscall.h | 提权（uid 变更）捕获 |
| kprobe/security_bpf_prog_free | ks_probes_self_protect.h | 自保护（eBPF 卸载感知） |
| kprobe（container 路径） | ks_probes_container.h | 命名空间/容器判定输入 |

补充发射面：sys_enter 白名单中 rename/chmod 发 FILE_RENAME/FILE_CHMOD 事件（勒索批量改名可见），
unlink/fchmod 进 freq 计频，read 维持"只计频不流式"。

### 5.2 BPF Map 清单（15 个，实测）

**状态原语（ks_state.h）**：

| Map | 类型 | 容量 | 用途 |
|---|---|---|---|
| process_tree | LRU hash | 65536 | 进程拓扑（pid/ppid/create_time/risk_score/flags） |
| freq_counters | LRU hash | 4096 | 六维 60s 滚动窗口计数 + 异常标志位 |
| net_conn_history | LRU hash | 8192 | TCP 流状态（pid+五元组键） |
| risk_scores | LRU hash | 4096 | 风险分 0-100（整数） |
| net_flows | hash | — | 流量累计 |

**裁决通道（ks_channel.h）**：

| Map | 类型 | 用途 |
|---|---|---|
| block_decisions | LRU hash，容量 4096 | 裁决表：pid → (expire, reason)，TTL 300s |
| protected_comms / protected_pids | hash | 系统进程豁免名单（comm + exe 复核） |
| process_whitelist | hash | 行为白名单 |

**过滤与统计**：

| Map | 类型 | 用途 |
|---|---|---|
| filter_stats_map / syscount_map | PERCPU_ARRAY | 过滤统计（无锁计数） |
| port_scan_map / ip_whitelist | hash | 端口扫描窗口 / 目的 IP 白名单 |
| ks_scratch / pt_scratch_map | PERCPU_ARRAY / hash | 探针间 scratch（绕验证器栈限制） |

事件通道：Modern 用 ringbuf（BPF_MAP_TYPE_RINGBUF），Legacy/Ancient 用 perfbuf。

### 5.3 事件类型与结构体（ks-core 内存对齐契约）

EventType 枚举（ks-core/src/lib.rs）：Process{Exec,Exit,Clone}=1-3、File{Open,Read,Write,Delete,Rename,Chmod}=10-15、
Net{Connect,Accept,Send,Recv,Dns}=20-24、Proc{Ptrace,Signal}=30-31，共 16 类。

结构体（repr(C) + 显式 pad + 编译期断言）：

| 结构体 | 字节数 | 断言位置 |
|---|---|---|
| EventHeader | 64 | lib.rs |
| ExecEvent | 832 | lib.rs:100 |
| FileEvent | 336 | lib.rs:101 |
| NetEvent | 112 | lib.rs:102 |
| SignalEvent | 72 | lib.rs:103 |

任何一侧字段增删导致布局漂移，编译立即失败。

### 5.4 内核态语义层（ks_semantics.h）

风险映射 infer_*：敏感文件 0-40 分、可疑网络 10-50 分（白名单 IP 跳过）、批量文件操作每次 2 分、
注入 ptrace +35 / signal +20。阻断决策 KS_MAYBE_BLOCK：verdict=2 且 KS_ENFORCE=1 时事件现场直杀，
杀前过三重豁免（干跑期 / 风险分阈值 / 保护名单）。

### 5.5 智能过滤（ks_probes_smart_filter.h）

事件级丢弃在内核完成：风险分低于阈值不发、频率正常不发、白名单组合不发。exec/ptrace/signal/网络类
默认放行，文件打开/读取默认计频不上行（敏感路径命中时升级）。过滤统计经 PERCPU_ARRAY，上行占比约 20%（实测可复算）。

### 5.6 内核态阻断（仅 Modern tier）

bpf_send_signal 需 5.5+，Modern tier 在 syscall 现场查 block_decisions 表直杀；Legacy/Ancient 由
用户态 killer 补杀（见 6.9）。执行点固定在进程上下文（syscall 入口），软中断路径经 socket 反查绑定，
避免误伤 ksoftirqd。

### 5.7 五档条件编译（build.rs + common.h）

| Tier | 事件通道 | 重定位 | 实杀 | 产物 |
|---|---|---|---|---|
| Modern（5.8+） | ringbuf | CO-RE | 内核直杀 | ks_main_modern.o |
| Legacy（4.x） | perfbuf | CO-RE | killer 补杀 | ks_main_legacy.o（+_nobtf） |
| Ancient（3.10） | perfbuf | CO-RE+编译期偏移 | killer 补杀 | ks_main_ancient.o（+_nobtf） |

三组开关：KS_RINGBUF / KS_LRU_HASH / KS_NOBTF，全部差异由 common.h 宏收敛，CI 断言五份产物数量。

### 5.8 BTF 工程化流程

四步：按目标内核内嵌（加载时按版本选取）→ 以探针实际引用为根最小化裁剪（bpftool gen min_core_btf，
30.9MB→1.6KB）→ 清洗老校验器不支持的特性（kind_flag / VAR/DATASEC / 空枚举值名）→ 加载属性按 5.0
门控（prog_btf_fd 等字段老内核整体省略）。正确性由逐指令重定位等价性测试锁死：完整 BTF 与裁剪 BTF
对同一 CO-RE 对象的重定位结果必须逐指令一致（tests/btf_relocation_test.rs），毒化 BTF 回归同在 CI。

### 5.9 C loader 旁路

3.10 stock 内核专用 C loader（855 行）保留作旁路，正常路径已切 aya perfbuf；随架构方向落地考虑退役。

---

## 6. 用户态引擎层 (ks-engine)

### 6.1 事件源与 tier 路由（event_source.rs / tier_detect.rs）

SourceKind 三档：EbpfModern（ringbuf）、EbpfLegacy（perfbuf）、Ancient。启动时 uname + BTF 存在性
探测自动选 tier，加载失败按 Modern→Legacy→Ancient 降级链回退，每次降级留日志。

### 6.2 聚合解码（aggregator.rs）

两阶段越界保护：先按 EventHeader 64B 读 event_type，再按类型校验完整长度，read_unaligned 规避对齐。
解码延迟实测 165ns/事件。

### 6.3 检测引擎（detector.rs）

YAML 规则匹配，18 个 Field 枚举变体 + 9 种操作符（等于/包含/正则/数值比较），加载期反序列化校验
（拼错字段名即报错）。正则走 Rust regex 线性引擎，ReDoS 免疫。匹配延迟实测 1.19μs/事件（40 条规则）。

### 6.4 跨事件关联（correlation.rs）

三模式：窗口关联（时间窗共现）、序列关联（按步骤顺序+步长受限，追踪器键=规则索引+pid）、进程树关联
（父子组合行为）。内置 9 条关联规则（数据窃取×2、勒索、反弹 Shell、提权持久化、DNS 隧道、进程树异常×2 等），
每条产出 0-1 置信度（同进程/快速完成/多次出现加分）。

### 6.5 统计基线（baseline.rs）

每进程六维（syscall/文件/网络/DNS/ptrace/信号）60s 窗口均值与标准差，z 超 2σ/3σ/5σ 三档偏离。
基线一次性锁定（防异常数据稀释），未建立前固定阈值兜底，固有高频进程白名单防冷启动误报。
基线更新延迟 37-104ns。

### 6.6 自适应异常（ml_detector.rs）

EWMA（α=0.3）+ 冷启动双模型：新进程保守观测，样本累积后切换 EWMA。更新延迟 68ns。
8 月曾修复本模块 LRU 表膨胀 OOM（RSS 1.4GB→3.9MB，max_pids=10000 按窗口活跃度淘汰）。

### 6.7 进程树（process_tree.rs）

消费内核拓扑增量，维护父子链与 ORPHAN 处理；用户态不重放 fork 历史。

### 6.8 攻击链还原（chain.rs）

replay 的攻击链重建：按进程聚合事件序列，映射 MITRE 战术链。

### 6.9 用户态阻断（blocker.rs）

killer 每 300ms 轮询 block_decisions（read_block_decisions 全量读），user_kill_tick 纯函数执行
豁免判定（is_exempt 闭包先于 kill，时序即正确性——真机验证真 sshd 存活、/tmp/sshd 被杀）后 SIGKILL。
exe_path_suspicious 检查 /tmp、/dev/shm、/var/tmp 前缀。PinnedBlockMap 支持 bpffs pin（跨进程手动裁决），
remove 的 ENOENT 按 SyscallError(NotFound) 匹配。

### 6.10 eBPF 加载器（loader.rs / linux_map_reader.rs / btf_source.rs / cloader_source.rs）

基于 vendor aya（四处补丁：老内核 BTF 清洗、BPF_PROG_LOAD 字段 5.0 门控、<4.17 kprobe 条目先关 perf fd
再删的 EBUSY 修复、perf fd 关闭顺序）。BpfMapReader trait 提供 read_block_decisions / pin_block_map；
DEFAULT_PROTECTED_COMMS 11 个系统进程（sshd/systemd/cron/journald/dbus-daemon/sudo/login/agetty/
rsyslogd/systemd-journal/crond），KS_PROTECTED_COMMS 可扩展。启动 setrlimit(MEMLOCK=∞)。

### 6.11 配置（config.rs）

环境变量驱动：KS_DETECTION_BLOCK_ENABLED（true 字面量）、KS_ENFORCE、KS_PROTECTED_COMMS、
KS_USER_KILL、KS_LOG_LEVEL 等。

---

## 7. 核心类型层 (ks-core) — 契约层

- **event.rs / lib.rs**：四类事件结构体 + EventType 枚举 + 编译期布局断言（见 5.3）。
  `DecodedEvent`（事件契约的 Rust 侧权威镜像）也在此：eBPF 侧 common.h 双重定义产出
  RawEvent 字节流，各事件源解码为本类型后进入检测管线；forensic 落盘、规则匹配、
  关联分析、回放还原均以它为准。**第二个前端/加载器实现应依赖本类型，而非引擎内部状态。**
- **time.rs**：单调钟 → 墙钟换算（`epoch_ms_from_monotonic_ns`，/proc/stat btime，
  换算式是记录内容的纯函数，回放可离线重算）。时钟双轨见 7.1。
- **rule.rs**：DetectionRule（含 `#[serde(default)] enforce: bool`）、18 个 Field 枚举、9 操作符、MatchResult。
- **alert.rs**：Alert 结构（severity 分级、MITRE 映射字段）。

### 7.1 公共接口面（对外契约清单，Hliðskjálf/Web 接入只依赖这些）

| 接口 | 形态 | 稳定字段/语义 |
|---|---|---|
| 事件流 | JSONL `events_YYYYMMDD.jsonl`（按天+按大小滚动，归档 `events_YYYYMMDD_HHMMSS.jsonl.gz`） | `schema_version=1`、`type="event"`、`seq`（引擎级单调，跨重启/滚动不重置）、`timestamp_ns`（单调钟）、`epoch_ms`（墙钟侧车，btime+monotonic 换算；老归档可能缺省）、`event_type`（数值）+ `event_type_name`（契约 snake_case 名）、DecodedEvent 字段、`prev_hash`/`hash` |
| 告警流 | 同一 JSONL 内 `type="alert"` 记录 | `schema_version=1`、Alert 结构（id/severity/mitre/process/network/file/event_ids）+ `timestamp_ns`/`epoch_ms` |
| 取证文件权限 | 目录 0700 / 文件 0600 | 活跃日志、归档、chain_head.log 一律私有（升级时自动收紧历史文件）；前端需以 root 或受权身份读取 |
| 链锚 | `chain_head.log`（日志目录外） | 每约 1000 事件外落 (seq, prev_hash, file)，跨文件锚定 |
| status 文件 | `/run/kernelsentinel/ks-status.json`（0700） | pid/start_time/version/status；heartbeat `ks-heartbeat.json` 10s 更新（存活=liveness 事实源） |
| block CLI | `block/unblock/blocked --json` | 单行 JSON 对象到 stdout：command/pid/expire_monotonic_ns/permanent/remain_secs/reason；pin 路径 `/sys/fs/bpf/kernelsentinel_block_decisions`（跨进程 map 契约） |
| replay/watch | `--json` 模式 | replay 摘要含 chain{valid,anchored,total_records} 与 first/last_epoch_ms；watch 逐行输出 Alert JSON |
| 进程外加载器接入 | map ABI | bpffs pin（`/sys/fs/bpf/kernelsentinel_<map>`）+ 与 common.h 逐字节对齐的 key/value；**进程不参与契约**。该结论由已退役的 C loader 倒逼得出（见下），直接适用于未来的内核下沉 runtime（同为加载方持 fd、用户态跨进程访问） |

`schema_version` 语义：破坏性字段变更递增；新增可选字段不递增，消费方必须容忍未知字段。
`event_type_name` 是稳定契约名（如 `file_write`/`net_connect`），数值仅在内核/调试侧使用。

时钟双轨约定：`timestamp_ns`（bpf_ktime_get_ns，CLOCK_MONOTONIC）是取证序权威——不可回拨；
`epoch_ms` 仅为跨主机关联的侧车换算（休眠期不计入，服务器场景可忽略）。外部消费方排序、
去重、链校验一律以单调钟为准。

C loader 状态（2026-10-17）：NOBTF tier 的 C loader 路由已退役，实现（cloader_source.rs /
pinned_map_reader.rs / ks_loader.c）保留为参考、不再激活；无 BTF 的老内核回退 mock 并明确告警。
退役原因是它属于兼容补丁而非未来加载器方向；但它倒逼出的"进程外加载器 = pin + 字节布局"
契约结论保留，见上表最后一行。

---

## 8. CLI 层 (ks-cli)

### 8.1 子命令（10 个，main.rs 实测）

start（引擎主循环：SIGTERM/Ctrl-C 双信号优雅退出、探针残留自清、单实例锁、killer spawn、
pin/unpin 裁决表）、stop、status（可 watch）、block/unblock/blocked（手动裁决，guard_pid 拒绝
pid 1/自身/不存在进程）、replay（八阶段取证回放：链校验→统计→分布→MITRE 映射→攻击链还原→进程画像）、
watch（tail JSONL 实时告警）、baseline / correlation（本地 JSONL 离线分析）。

### 8.2 start 主循环

单线程事件泵：tokio select 轮询事件源 + 信号；事件处理链 = 解码 → 规则 → 关联 → 基线/ML → 取证落盘 →
（enforce 命中时）写裁决表。killer 独立 spawn（300ms interval）。

---

## 9. 检测规则集 (rules/)

14 个 YAML 文件，40 条规则，MITRE ATT&CK 映射齐全：

| 文件 | 条数 | 主题 |
|---|---|---|
| privilege_escalation.yml | 6 | SUID/sudoers/提权前兆 |
| persistence.yml | 5 | crontab/systemd unit/ssh key/ld.so.preload |
| rootkit_detect.yml | 5 | insmod/finit_module/proc 异常（**enforce: true**） |
| defense-evasion.yml | 4 | 历史清除/审计关闭/进程隐藏 |
| command-and-control.yml | 4 | 可疑端口/非常规协议 |
| data_exfil.yml | 3 | 敏感文件外传 |
| credential-access.yml | 2 | /etc/shadow、.ssh 密钥 |
| ransomware.yml | 2 | .encrypted 批量写、影子副本删除 |
| reverse_shell.yml | 2 | bash -i /dev/tcp、pty 窃取 |
| impact.yml / lkm-load.yml / container-escape.yml / dns_tunnel.yml / ebpf-tamper.yml | 各 1-2 | 其余战术 |

仅 rootkit_detect.yml 两条规则声明 enforce: true（rootkit_module_load / rootkit_finit_module），
文件头含 enforce 规则编写守则；其余 13 个文件均为 audit。关联规则 9 条在 correlation.rs 内置。

---

## 10. 数据流全链路（端到端）

```
syscall/vfs/net 事件
  → [内核] 白名单过滤 / 频率计数 / 拓扑更新 / 流状态机 / 风险评分 / infer_* 判定
  → （verdict=2 且 enforce）block_decisions 写表 → bpf_send_signal 直杀（Modern）
  → ringbuf/perfbuf 上行（约 20%，携带内核判定）
  → [用户态] 两阶段解码 → 规则匹配（1.19μs）→ 关联（9 规则）
      → 基线（z-score）→ EWMA → 告警
  → 取证 JSONL（prev_hash/hash 链）→ replay 回放
  → （规则 enforce 命中）写裁决表 → 内核查表直杀 或 killer 300ms 补杀
  → 豁免判定（comm + exe 复核）先于 kill
```

---

## 11. MITRE ATT&CK 覆盖

40 条静态规则 + 9 条关联规则 + 内核语义层，覆盖：Execution（T1059 反弹 Shell）、Persistence（T1547
LKM、crontab 等）、Privilege Escalation（T1548.001 SUID）、Defense Evasion（T1014 rootkit、历史清除）、
Credential Access（T1003 shadow/ssh key）、Command and Control（T1048 外传、DNS 隧道）、Impact（T1486
勒索）等战术。六类攻击场景（反弹 Shell/勒索/提权/DNS 隧道/Rootkit/数据窃取）真机端到端命中，各自对应
ATT&CK 技术编号。

---

## 12. 验证状态（2026-10-12 快照）

### 12.1 自动化测试（实测 175 全过）

`cargo test --workspace`：ks-engine 130（含 BTF 等价性/毒化回归）、ks-cli 14、e2e_attacks 14、
ks-core 7、integration 5、rules_load 5。CI 另断言五档编译产物（expected 5）、clippy -D warnings、
ShellCheck、cargo audit。

### 12.2 真机验证

- **CentOS 7.2（3.10.0-1160，Ancient）**：aya perfbuf 路径全量打通；六场景命中（数据窃取 274/
  ptrace 64/勒索 20/rootkit 6/SUID 2/反弹 Shell 1）；用户态补杀实测裁决→实杀 1.5s 内；
  comm 伪造攻防实验（真 sshd 存活、/tmp/sshd 被杀）；SIGTERM 退出探针 0 残留。
- **Debian 12（6.1，Modern）**：内核直杀路径验证（退出码 137）；enforce 闸门验证（204 告警/
  裁决 0/sshd 存活）；systemd 常驻长稳。
- **4.19（VM）**：legacy 变体 16/16 attach + LKM 命中；长稳矩阵待补（计划 QEMU）。

### 12.3 性能数据

| 指标 | 实测 | 口径 |
|---|---|---|
| 内存 | 空载 RSS ~3MB；15.5h 长跑峰值 VmHWM 185MB 无泄漏 | /proc/pid/status |
| CPU | 空载 0.0%；增量编译 +2% / iperf 10G +1% / find 全盘 +3% / 混合 +5% | E1.4 探针开vs关对照 |
| 事件吞吐 | 端到端 1200~1977 events/s（压测极限值）；真实主机关心事件每秒几十~几百 | 5.15 真机压测 |
| 组件延迟 | 解码 165ns / 规则 1.19μs / 基线 37-104ns / EWMA 68ns | criterion 微基准 |
| 阻断时延 | 裁决→实杀 ≤1.5s（3.10 killer 路径） | 真机实测 |

---

## 13.设计决策

1. **内核优先**：拓扑/频率/流状态/风险分驻留内核，正常行为零上行；用户态不重建进程拓扑。
2. **默认安全**：阻断默认 monitor；实杀权规则级 enforce 显式声明（当前仅 rootkit 两条）；系统进程
   comm+exe 双侧豁免且豁免先于 kill。
3. **契约先行**：repr(C) + 显式 pad + 编译期断言；block_decisions 布局文档化；裁决表 pin bpffs 为
   跨进程契约。
4. **验证器友好**：字符串匹配展开为定长逐字符比对；下标无符号钳制；整数风险分；单程序不用 tail call。
5. **纵深非串联**：四层检测各管一段独立告警；在线漏检由离线回放兜底；取证链兜底一切。
6. **vendor aya 而非重写**：四处补丁均标注，上游化路线已在推进（#1661 已合并）。

---

## 14. 已知限制

- **引擎被 kill**：用户态检测与 killer 失效，内核探针仍挂载但无人消费；systemd 自动拉起 + 回放补偿；
  watchdog 目前是单向巡检，watchdog 自身故障无人互守。
- **4.19 无常驻真机**：功能验证在 VM，长稳 soak 待补。
- **pid 重用**：裁决表 key 仅 pid，靠 TTL 300s 稀释误杀窗口；key 加 start_time 列入接口改造。
- **内核过滤静态**：敏感路径等过滤表编译期固化，动态下发未实现。
- **FPR/FNR 未系统测量**：方法已定（Atomic Red Team + 48h 真实业务标注），第四阶段执行。
- **io_uring 部分覆盖**：实现函数 kprobe（vfs_write/tcp_connect）可见，tracepoint 级全覆盖需 5.1+。
- **检测盲区**："合法进程内低频、陌生目标、小流量"外传是真实盲区（需威胁情报信誉，未实现）。
- **取证链防篡改不防全删**：链尾外置到日志目录之外是部署要求，纯本地方案无法防御 root 全删。
- **基线正态假设**：z-score 在长尾分布下偏保守（漏报偏向）；分位数基线（中位数+MAD）列入改进。
- **吞吐未达标**：处理层 61μs/事件（理论 16K/s）vs 端到端 1200-1977/s，瓶颈在 aya 逐条 next() 的
  取事件结构；优化方向（批量 drain、缓冲复用、增量计数）全部保持在单消费者架构内。

## 

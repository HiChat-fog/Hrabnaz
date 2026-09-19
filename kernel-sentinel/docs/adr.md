# 内核哨兵 (KernelSentinel) — 架构决策记录 (ADR)

> 本文档记录 KernelSentinel 项目在架构设计过程中的关键决策，每条决策均遵循 ADR 标准格式：
> **编号与标题 / 状态 / 背景 / 决策 / 影响**。
>
> 共 12 条架构决策，覆盖内核探针选型、用户态引擎语言、事件传输机制、检测模式、取证日志完整性、规则类型安全、内核/用户态分工、攻击链还原、跨语言结构体对齐、跨平台开发策略、内核态即时阻断、以及 EWMA 在线学习自适应检测。
>
> ⚠️ 2026-08-31 更新：ADR-001/003/004/007/011 按当前代码修正了探针数量、双轨事件传输、
> KS_ENFORCE 阻断门控与"用户态不写 block_decisions map"等事实（决策理由本身不变）。

---

## ADR-001: eBPF vs Kernel Module 事件采集方案

**状态**: Accepted

### 背景

终端威胁检测需要在 Linux 内核关键路径（系统调用入口、VFS 层、网络协议栈）植入感知探针，实时捕获进程执行、文件操作、网络连接等底层行为。传统方案有两种选择：编写可加载内核模块（LKM）直接修改内核逻辑，或使用 eBPF（Extended Berkeley Packet Filter）通过沙箱化程序在内核中挂载探测点。内核模块方案虽然灵活性更高、不受功能约束，但存在内核崩溃（panic）风险、版本兼容维护成本高、部署需要重新编译等严重问题。项目定位为轻量、离线、静默部署的警务终端安全工具，内核稳定性是不可妥协的底线。

### 决策

选择 eBPF（BPF CO-RE，Compile Once - Run Everywhere）作为内核事件采集技术，而非可加载内核模块。具体实现采用 5 个 tracepoint（raw_syscalls/sys_enter、raw_syscalls/sys_exit、sched_process_fork、sched_process_exec、sched_process_exit）和 11 个 kprobe（vfs_open / vfs_write / vfs_unlink / tcp_v4_connect / tcp_v6_connect / udp_sendmsg / tcp_set_state / tcp_sendmsg / commit_creds / do_init_module / security_bpf_prog_free），共 **16 个探针程序**覆盖系统调用层、VFS、网络栈、进程调度与三个安全探针（E4.1/E4.2/E4.3）。使用 clang -target bpf 编译 eBPF C 程序，5 tier 条件编译（modern/legacy/ancient/ancient_nobtf/legacy_nobtf），BTF 路径 + NOBTF 硬编码偏移双通道兼容跨内核版本。

### 影响

**有利**：
- eBPF 程序经过验证器（verifier）静态检查，保证不会导致内核崩溃，从根本上杜绝 panic 风险；
- BPF CO-RE 模式一次编译、跨内核版本运行，大幅降低维护成本；
- 探针可动态加载/卸载，无需重启系统，满足静默部署需求；
- 社区生态成熟（libbpf / aya-rs / bpftool），工具链完善。

**不利**：
- eBPF 验证器对程序复杂度有严格限制（最大指令数、循环深度、栈大小），内核推理引擎（infer.bpf.c）需要手动展开循环、使用 `__always_inline` 内联，开发难度较高；
- kprobe 探针依赖内核内部符号，不同内核版本间函数签名可能变化，需要持续适配；
- 无法在内核态执行浮点运算，风险评分必须使用整数（0-100），精度受限；
- 部分高级安全功能（如修改系统调用返回值）在 eBPF 中受限，不如内核模块灵活。

---

## ADR-002: Rust 作为用户态检测引擎语言

**状态**: Accepted

### 背景

用户态引擎承担三大核心任务：从 ring buffer 消费内核事件、执行检测逻辑（规则匹配 + 异常评分）、写入取证日志。该引擎需要同时满足高性能（>100K events/s 吞吐、<10us 规则匹配延迟）、内存安全（长时间运行不可泄漏/崩溃）、以及可维护性（代码结构清晰、测试覆盖充分）。候选语言包括 C（性能最优但无内存安全保证）、Go（并发友好但有 GC 延迟）、Rust（零开销抽象 + 编译期内存安全）。项目还涉及 eBPF 程序生命周期管理，需要与内核侧 C 代码进行零拷贝数据交换。

### 决策

选择 Rust 作为用户态检测引擎语言，配合 aya-rs 框架管理 eBPF 程序生命周期。核心 crate 组织为：ks-core（事件/规则/告警数据类型）、ks-engine（聚合器/检测引擎/攻击链还原/取证日志/配置管理）、ks-cli（命令行入口）、ks-server（axum Web 后端）。利用 Rust 的 `#[repr(C)]` 实现与 eBPF C 侧事件结构体的零拷贝对齐；利用 serde 实现 YAML 规则反序列化；利用 tokio 异步运行时处理事件消费流水线。

### 影响

**有利**：
- 编译期内存安全保证（ownership / borrow checker），长期运行无内存泄漏风险，适合 7x24 部署；
- 零开销抽象，性能接近 C，无 GC 延迟，满足 <5% CPU 占用约束；
- aya-rs 是 Rust 原生 eBPF 框架，类型安全地管理 BPF map / program / link 生命周期；
- 强类型系统 + serde 反序列化天然支持 Field 枚举类型安全校验；
- 单二进制部署，无运行时依赖，契合"零外部依赖"定位。

**不利**：
- Rust eBPF 生态相比 C/libbpf 更小，aya-rs 文档和社区案例较少；
- Rust 编译时间长，影响开发迭代速度；
- 部分底层操作（如 BPF map 遍历）在 aya-rs 中抽象层级较高，需要深入理解 aya 内部实现才能正确使用；
- 团队成员需具备 Rust 高级特性（trait / async / unsafe）能力，学习曲线陡峭。

---

## ADR-003: Ring Buffer vs Perf Buffer 事件传输机制

**状态**: Accepted

### 背景

内核 eBPF 探针捕获的事件需要高效传输到用户态引擎进行处理。BPF 子系统提供两种内核→用户态数据传输机制：perf_buffer（BPF_MAP_TYPE_PERF_EVENT_ARRAY，自 Linux 4.4 起可用）和 ring buffer（BPF_MAP_TYPE_RINGBUF，自 Linux 5.8 起引入）。perf_buffer 为每个 CPU 维护独立缓冲区，数据按 CPU 分片传输，用户态需逐 CPU 读取并合并；ring buffer 使用全局共享缓冲区，支持跨 CPU 写入和统一读取。项目目标是实现 >100K events/s 事件吞吐，同时保证低延迟和零丢事件。

### 决策

选择 BPF_MAP_TYPE_RINGBUF 作为 **Modern tier**（5.8+）的内核→用户态事件传输机制，并在老内核保留 perf_buffer 回退——**实际实现为双轨**：`KS_RINGBUF=1` 时 events 用 ringbuf（16MB 单全局缓冲），`KS_RINGBUF=0`（Legacy 4.x / Ancient 3.10）时退回 `BPF_MAP_TYPE_PERF_EVENT_ARRAY`（per CPU 缓冲）。7 月 30 日压测后事件主环从 1MB 加大到 16MB（其余 tree/freq/flow/filter 各 1MB）。用户态使用 aya-rs `RingBuffer`/`PerfEventArray` API 消费（batch_size 64 条）。

### 影响

**有利**：
- ring buffer 使用全局缓冲区而非 per-CPU 分片，事件天然有序，无需用户态按 CPU 合并排序，简化聚合器实现；
- API 更简洁：aya-rs 的 `RingBuffer` 提供回调式消费，无需手动管理 per-CPU reader；
- 双轨设计让 3.10/4.x 老内核照常工作（perfbuf），5.8+ 享受 ringbuf 优势，互不阻塞。

**不利**：
- 双轨意味着两套消费路径（EbpfModernSource / EbpfPerfSource）与两套内核侧 `KS_RESERVE/KS_SUBMIT` 宏，维护成本增加；
- 压测证明 16MB ringbuf 在高速 syscall 洪峰下仍可能丢事件（用户态消费慢导致满），**"零丢事件"不是硬保证**——有 drop 计数与丢失率监控；
- 内核侧 ringbuf 实现细节（如缓冲区溢出时丢事件行为）社区文档较少，依赖实测调参。

---

## ADR-004: 双模检测 — 规则引擎 + 异常评分

**状态**: Accepted

### 背景

终端威胁检测面临核心矛盾：确定性规则引擎（如 Snort/YARA 模式）精确度高但僵化——新攻击模式需要人工编写新规则，无法应对零日威胁；统计异常检测（如 ML 模型）自适应但噪声大——正常行为的波动容易触发误报，且训练数据获取困难。项目定位为公安终端安全工具，要求误报率极低（避免干扰正常警务工作），同时不能漏报新型攻击。单一检测模式无法同时满足精确性和适应性两个需求。

### 决策

采用双模检测架构：模式一为确定性 YAML 规则引擎，通过 Field 枚举实现类型安全匹配，覆盖已知攻击模式（反弹 Shell、勒索软件、提权、数据窃取、DNS 隧道、Rootkit、容器逃逸、LKM 加载、eBPF 篡改）；模式二为轻量统计异常评分引擎，基于 4 个维度（系统调用频率、敏感文件访问分级、可疑进程行为模式、异常网络连接）计算加权分数，阈值 >= 0.7 触发告警。两路检测结果合并输出告警，规则引擎告警标注 rule_name，异常评分告警标注 anomaly_score。内核推理层（common.h）作为第三层前置过滤，用整数风险分（0-100）做粗粒度预判，>= 40 标记高风险；**>= 70 且 enforce 模式（KS_ENFORCE=1 + 干跑期已过 + 非 protected 名单）才阻断**——默认 monitor 模式只告警不杀（详见 ADR-011）。

### 影响

**有利**：
- 规则引擎对已知攻击模式（反弹 Shell / 勒索软件 / 提权）有极高精确度，误报率低，适合安全运维场景；
- 异常评分引擎可捕捉偏离基线的未知行为，覆盖零日攻击和组合攻击，弥补规则盲区；
- 双路告警合并后提供更完整的威胁视图——同一事件既命中规则又评分异常时，置信度最高；
- 零外部 AI 依赖——异常评分全部手工实现，不需要 GPU/模型文件/训练数据，契合离线部署需求。

**不利**：
- 异常评分阈值需要真实环境调优——当前阈值（0.7）和各维度权重（+0.5/+0.35/+0.15 等）基于理论推算，真机三机已有数据（1.12-2.24μs 匹配延迟），但权重仍可按实战微调；
- 两路检测结果合并策略需要精细化——当前为简单合并，未来可能需要去重（同一事件触发两类告警时）和优先级排序；
- 异常评分基于短期窗口（60s syscall 频率），对慢速攻击（如低频数据渗出）可能漏检，需要增加长期基线对比机制（z-score 六维基线 + EWMA 已补上）；
- 规则引擎依赖 YAML 规则文件（现 9 套 23 条），规则覆盖的全面性取决于规则编写者的经验，存在覆盖盲区风险。

---

## ADR-005: SHA-256 哈希链用于取证日志完整性

**状态**: Accepted

### 背景

内核哨兵的取证日志面向法律证据场景——公安终端安全日志需要具备不可篡改性，任何对历史记录的修改都应可检测。传统日志方案（syslog / journald）仅依赖文件权限保护，攻击者获得 root 权限后可任意修改日志内容而无法发现。设计目标为：每条日志记录与前一条形成链式依赖，修改任意一条记录会导致所有后续记录的完整性校验失败。候选哈希算法包括 DefaultHasher（Rust 标准库非加密哈希，速度快但非安全用途）、SHA-256（NIST 标准加密哈希，256 位输出）、SHA-3 / BLAKE3（更新算法但生态支持较少）。

### 决策

采用 SHA-256 哈希链方案：每条 JSONL 日志记录包含 `prev_hash`（前一条记录的 SHA-256 哈希）和 `hash`（本条记录 data + prev_hash 的 SHA-256 哈希），形成链式依赖。使用 `HashAlgorithm` trait 抽象哈希计算，便于未来扩展为 SHA-3 / BLAKE3。取证日志按大小轮转（默认 100MB），超过后自动 gzip 压缩归档，保留 30 天。BufWriter 64KB 缓冲，每 1000 条自动 flush，告警立即 flush。启动时从已有文件恢复链状态，`verify_chain()` 支持全链完整性校验。

### 影响

**有利**：
- SHA-256 是 NIST 标准加密哈希，具备抗碰撞和抗篡改特性，满足司法取证对日志不可篡改性的要求；
- 哈希链结构保证：修改任意一条记录，其 hash 值变化导致下一条 prev_hash 不匹配，从而所有后续记录校验失败，篡改可检测；
- HashAlgorithm trait 抽象使得未来切换到 SHA-3 / BLAKE3 仅需实现新 trait，不改动日志写入逻辑；
- 按大小轮转 + gzip 归档 + 30 天清理，平衡存储空间与取证数据保留期限；
- 告警立即 flush 保证关键数据不因进程异常退出而丢失。

**不利**：
- SHA-256 计算开销：每条记录需两次哈希（prev_hash + hash），在高吞吐场景（>100K events/s）下增加 CPU 占用，实测约增加 1-2% CPU；
- 哈希链要求确定性序列化——JSON 字段顺序必须固定，serde 的 `serde_json` 默认按字母序排列键名，需要确保序列化行为一致，否则相同数据在不同 Rust 版本/平台可能产生不同哈希值；
- 链断裂后的恢复机制尚未完善——如果某条记录因写入错误（如磁盘满）导致 hash 不一致，后续所有记录的 prev_hash 都无法匹配，需要设计跳过或修复策略；
- 删除日志文件（如攻击者 rm -rf /var/log/ks/）会导致整个链消失，需要配合独立存储（如远程备份链尾哈希）实现双重保护。

---

## ADR-006: YAML 检测规则 + Field 枚举类型安全

**状态**: Accepted

### 背景

检测规则需要两个看似矛盾的特性：(1) 易编写易更新——安全运维人员应能快速创建/修改规则，无需重新编译程序；(2) 类型安全——规则中引用的事件字段名必须有效，拼写错误（如把 `comm` 写成 `com`）不应静默忽略导致规则失效。YAML 格式满足易编写需求，但纯 YAML 反序列化为 HashMap 后字段名是字符串，拼写错误不会报错，规则会在运行时静默跳过无效条件。项目已定义 25 个事件字段（Comm / Pid / Ppid / Uid / SyscallNr / Filename / Args / FileBytes / Saddr / Daddr / Sport / Dport / Proto / Saddr6 / Daddr6 / Family / TargetPid / Signal / ModuleName / ProgName / SourceNsInum / TargetNsInum / CapEff / Action / EventType；⚠️ `all_yaml_names()` 返回 24 项不含 event_type，已知不一致），需要保证规则只引用这些合法字段。

### 决策

采用 YAML 格式定义检测规则，配合 Rust Field 枚举实现编译期字段名校验。YAML 规则结构包含 name / severity / conditions / mitre_tactic / mitre_technique，每个 condition 的 `field` 字段在 serde 反序列化时映射到 Field 枚举变体。Field 枚举定义 `is_numeric()` / `is_string()` / `yaml_name()` 属性方法，用于匹配时选择正确的比较函数（数值字段用 match_i32/match_u32，字符串字段用 match_str/match_opt_str）。无效字段名在 YAML 加载时直接报错，而非运行时静默跳过。IPv6 字段（Saddr6 / Daddr6）建议仅使用 equals/contains 操作符，Family 仅支持 equals（"IPv4" 或 "IPv6"）。

### 影响

**有利**：
- YAML 格式易编写易维护——安全运维人员无需 Rust 知识即可创建/修改规则，规则文件可热加载（5 秒扫描 mtime，变更时原子替换检测引擎）；
- Field 枚举在反序列化阶段校验字段名，拼写错误立即报错并拒绝加载规则，杜绝"规则存在但不生效"的隐蔽故障；
- Field 的 `is_numeric()` / `is_string()` 方法自动选择匹配函数，数值字段使用精确比较（Equals/GT/LT），字符串字段使用模式匹配（Equals/Contains/StartsWith/Regex），逻辑清晰不易出错；
- 9 套 23 条内置规则（ransomware / reverse_shell / privilege_escalation / data_exfil / dns_tunnel / rootkit_detect / container-escape / lkm-load / ebpf-tamper）提供实战参考。

**不利**：
- YAML 解析依赖 serde_yaml crate，该 crate 在 Rust 生态中存在维护不确定性（serde_yaml 原作者已标记为 unmaintained，社区转向 serde_yml）；
- Field 枚举变体需要与 eBPF 侧事件结构体字段保持同步——新增字段时需同时修改 Rust Field 枚举和 YAML 规则文档，否则新字段无法被规则引用；
- 正则表达式操作符（regex）依赖 regex crate 预编译，复杂正则可能增加规则匹配延迟；
- IPv6 字段的匹配策略受限（不建议 regex），因为 IPv6 地址格式（冒号分隔 + ::压缩）不适合正则匹配，可能遗漏某些 IPv6 攻击模式。

---

## ADR-007: 两阶段内核/用户态检测架构

**状态**: Accepted

### 背景

终端威胁检测系统需要在两个约束之间寻找平衡：eBPF 验证器严格限制内核态程序的复杂度（最大指令数、栈大小、无浮点运算），使得在内核中实现完整的规则匹配和异常评分几乎不可能；但如果所有检测逻辑都放在用户态，内核探针只能无差别转发所有事件，在高负载场景下事件洪峰会淹没用户态引擎（勒索软件爆发期间每秒可产生数万条文件操作事件）。理想方案是：内核态做粗粒度过滤减少事件量，用户态做精细检测保证准确性。

### 决策

采用两阶段检测架构：内核推理层（common.h）在 eBPF 约束内实现 4 维推理函数（敏感文件访问 / 可疑网络连接 / 批量文件操作 / 进程注入），使用 LRU Hash Map 累积整数风险分（0-100），**enforce 模式下** >= kill 阈值（默认 70）时 bpf_send_signal 阻断进程，>= 40 分时标记高风险事件。用户态引擎接收所有事件（含高风险标记），执行精确 YAML 规则匹配和统计异常评分。内核推理层的作用是减少用户态需要精细处理的事件量——高风险事件优先处理，低风险事件快速归档，而非替代用户态检测。阻断实际前置条件：`KS_ENFORCE=1` 时 loader 写 infer_config[5]=1、infer_config[6]=warmup_until（默认 120s 干跑期）、infer_config[7]=kill 阈值（默认 70），且进程不在 protected_pids/protected_comms 豁免名单（否则只标记不杀）；legacy/ancient tier 无 bpf_send_signal helper，仅查 block_decisions 表标记。注：get_config 对 infer_config key0-4 直接返回硬编码默认值（死代码缺陷），用户态目前只能配置 enforce 三项。

### 影响

**有利**：
- 内核推理层可在纳秒级做出粗粒度阻断决策（enforce 模式下 >= kill 阈值直接 bpf_send_signal），对反弹 Shell / 勒索软件等已知高危模式实现即时响应，无需等待用户态处理；
- 高风险标记（>= 40 分）让用户态引擎优先处理重要事件，降低低优先级事件的处理延迟；
- 内核推理使用整数运算（0-100），避免 eBPF 不支持的浮点运算，逻辑简单满足验证器约束；
- 推理函数使用 `__always_inline` 内联 + 字符串比较手动展开，零调用开销，探针延迟 < 1us。

**不利**：
- 内核推理逻辑受 eBPF 验证器严格限制——最大 100 万指令、**8 级**调用深度（5.2+ 提升，早期 4-5 级）、512 字节栈，4 维推理函数需要精心设计才能通过验证，开发调试成本高；
- 整数风险分的粒度有限——0-100 范围无法精细表达复杂威胁模式，某些边界情况（如风险分 69 vs 70）可能导致阻断决策不精确；
- 内核推理层与用户态检测引擎的阈值需要协同调优——内核 >= 40 分标记高风险但用户态异常评分 >= 0.7 才告警，两个阈值体系的不一致可能导致告警重叠或遗漏；
- bpf_send_signal 阻断功能仅在 5.8+ modern tier 可用且需 enforce 门控（3.10/4.x 无该 helper，阻断退化为纯标记），生产环境需谨慎开启并先观察基线。

---

## ADR-008: 进程树攻击链还原

**状态**: Accepted

### 背景

现代攻击通常不是单一动作而是多阶段组合——攻击者通过反弹 Shell 入侵（初始入侵），注入进程获取提权（权限提升），批量加密文件（影响），外传数据（数据窃取）。如果检测系统仅报告单个告警（"发现反弹 Shell"、"发现 ptrace 注入"），安全运维人员需要手动关联这些告警才能理解完整攻击叙事，效率低下且容易遗漏。项目需要一种机制自动将离散告警串联为攻击时间线，呈现攻击者的完整行动路径。

### 决策

实现 ChainReconstructor 攻击链还原模块：以进程树（PID + PPID 关系）为分组维度，将同一进程树下的所有事件按时间排序，归类到 **9 个 MITRE ATT&CK 战术阶段 + Unknown**（初始入侵 / 执行 / 持久化 / 提权 / 防御规避 / 凭据访问 / 发现 / 数据窃取 / 影响；LateralMovement 枚举存在但分类函数无产出分支）。每个攻击链计算置信度分数（`phase_count × 0.15` cap 0.8，含 InitialAccess/Exfiltration/PrivilegeEscalation 任一段 +0.2），300 秒窗口内的事件归入同一链（超窗事件跳过，非滑窗）。攻击链当前在 start 主循环打印（confidence>0.5），⚠️ 早期设计"REST API 和 WebSocket 实时推送"未实现（ks-server 无 chains 路由）。

### 影响

**有利**：
- 自动将离散告警串联为攻击叙事，安全运维人员无需手动关联，直接查看完整攻击路径；
- 基于 MITRE ATT&CK 框架分类，提供标准化的攻击阶段描述，便于跨团队沟通和情报共享；
- 置信度分数量化攻击链的可信程度——高置信度链（多阶段、密集事件）优先关注，低置信度链（孤立事件）降低优先级；
- 实时推送攻击链更新，前端可展示动态攻击进程树和时间线视图。

**不利**：
- PID 树分组维度存在局限——跨进程攻击（如 A 进程通过网络触发 B 进程执行）无法自动关联，需要增加网络连接关联维度；
- PID 回收（进程退出后 PID 被新进程复用）可能导致错误关联，需要结合时间窗口和 comm 字段交叉验证；
- 300 秒窗口参数需要实战调优——慢速攻击（如APT 潜伏数天）可能跨窗口被拆分为多条链，快速攻击可能被合并为一条过长的链；
- MITRE ATT&CK 阶段分类依赖硬编码规则（如 execve -> 执行阶段），新攻击模式可能不属于现有 10 个阶段，需要扩展分类逻辑。

---

## ADR-009: #[repr(C)] C/Rust 共享结构体布局

**状态**: Accepted

### 背景

内核哨兵的 eBPF C 探针在内核态生成事件数据（EventHeader / FileEvent / NetEvent / SignalEvent 等），用户态 Rust 引擎从 ring buffer 读取原始字节并解码为 Rust 结构体。两侧必须对事件结构体的字段顺序、字段大小、对齐方式、总大小达成完全一致——任何偏差（如字段顺序不同、padding 位置不同、枚举大小不同）都会导致解码错误或越界访问。C 语言编译器按 ABI 规则自动插入 padding，Rust 默认布局与 C ABI 不同，两侧结构体的二进制表示可能不一致。

### 决策

对所有内核→用户态共享的事件结构体使用 `#[repr(C)]` 标注，强制 Rust 侧采用 C ABI 布局规则（字段顺序与声明顺序一致，padding 按 C 规则插入）。EventHeader 设计为 64 字节，包含显式 `_pad: u32` 字段填充对齐间隙。NetEvent 扩展 IPv6 支持（saddr6 / daddr6 各 16 字节 + family 1 字节）。在 Rust 侧使用 `size_of::<EventHeader>() == 64` 等静态断言验证结构体大小，在单元测试中验证 `size_of::<NetEvent>()` 等与 C 侧预期一致。解码时采用两阶段越界保护：from_bytes 先校验 data.len() >= sizeof(EventHeader)，再按 event_type 校验 data.len() >= min_event_size(event_type)。

### 影响

**有利**：
- `#[repr(C)]` 保证 Rust 侧结构体的二进制布局与 C ABI 一致，实现内核→用户态零拷贝数据传输——无需序列化/反序列化，直接从 ring buffer 原始字节引用转换；
- 显式 padding 字段（`_pad: u32`）使对齐意图清晰可见，避免编译器自动插入隐式 padding 导致两侧不一致；
- `size_of` 静态断言在编译期验证结构体大小，任何修改导致大小变化都会立即报错，杜绝"结构体改了但忘记更新 C 侧"的隐蔽错误；
- 两阶段越界保护（先校验 header 大小，再按 event_type 校验完整结构体）防止恶意构造的超短/超长数据导致内存安全问题。

**不利**：
- `#[repr(C)]` 结构体需要两侧同步维护——修改任何字段（增删改）都必须同时更新 C 侧 eBPF 程序和 Rust 侧 ks-core，否则对齐失效，维护成本高；
- 显式 padding 字段增加结构体定义复杂度，需要精确计算每个字段的对齐位置和间隙大小，容易出错；
- NetEvent 的 IPv6 扩展使结构体大小从固定值变为依赖 IPv4/IPv6 判断，解码逻辑更复杂——需要根据 family 字段决定读取哪些字段；
- 当前仅使用 `size_of` 静态断言验证大小一致，未验证字段偏移量（offset_of）一致，极端情况下大小相同但字段位置不同仍可导致解码错误——需要补充 offset_of 断言。

---

## ADR-010: MockEventSource 跨平台开发策略

**状态**: Accepted

### 背景

内核哨兵的 eBPF 探针和 aya-rs 加载器仅在 Linux 平台运行，但团队成员的开发环境为 Windows/macOS。如果 eBPF 相关代码在非 Linux 平台编译失败，开发者无法在本地运行事件消费、检测引擎、取证日志等用户态逻辑的集成测试，开发效率严重受限。项目需要一种机制让非 Linux 环境也能运行完整的用户态流水线，覆盖事件解码、规则匹配、异常评分、攻击链还原、取证日志写入等核心逻辑。

### 决策

采用 `EventSource` trait 抽象事件来源，Linux 平台实现 eBPF 真实消费（modern ringbuf / legacy+ancient perfbuf / nobtf C loader 三路径），非 Linux 平台实现 `MockEventSource`（从预构造的测试数据生成事件）。eBPF 加载器同样使用条件编译：`#[cfg(target_os = "linux")]` 使用 aya-rs 真实加载 + C loader 旁路，`#[cfg(not(target_os = "linux"))]` 使用 `MockBpfMapReader` 模拟 BPF Map 数据（现覆盖 6 个共享 map：risk_scores / ip_whitelist / net_conn_history / freq_counters / infer_config / protected_comms，含 `read_map_structured` 结构化读取）。用户态引擎（聚合器/检测引擎/取证日志/攻击链还原）的所有逻辑不依赖 eBPF 具体实现，仅依赖 `EventSource` trait 和 ks-core 数据类型，可在任意平台运行和测试。

### 影响

**有利**：
- Windows/macOS 开发者可以运行完整的用户态流水线，覆盖事件解码、规则匹配、异常评分、攻击链还原、取证日志等所有核心逻辑，无需 Linux 环境；
- MockEventSource 可构造各种边界情况的事件（超短数据、IPv6 事件、未知 event_type），用于单元测试和集成测试，覆盖真实内核不易触发的场景；
- EventSource trait 抽象使得未来扩展事件来源（如从 JSONL 文件回放、从远程 Agent 接收）仅需实现新 trait，不改动引擎逻辑；
- 条件编译确保生产环境（Linux）不引入 Mock 代码，不影响性能和安全性。

**不利**：
- MockEventSource 生成的事件可能与真实内核事件存在细微差异——如 C 字符串的 null terminator 位置、网络字节序的字段填充、内核时间戳的精度等，Mock 测试通过不代表真实环境一定正确；
- MockBpfMapReader 模拟的 BPF Map 数据是静态预构造的，无法模拟真实内核推理引擎的动态行为（如风险分累积、LRU 淘汰），用户态逻辑对 Map 数据的依赖可能在真实环境中表现不同；
- 条件编译导致 Linux 和非 Linux 平台的代码路径不同，某些 bug（如 aya-rs API 调用错误）只能在 Linux 环境发现，非 Linux 测试无法覆盖；
- Mock 数据需要与 eBPF 侧结构体定义持续同步——每次修改 C 侧事件结构体，MockEventSource 的构造逻辑也需要相应更新，否则 Mock 测试验证的是过时的数据格式。

---

## ADR-011: eBPF 内核态即时阻断（bpf_send_signal SIGKILL）

**状态**: Accepted

### 背景

传统 EDR 方案在用户态检测到恶意行为后，通过信号（kill/SIGSTOP）终止进程。但用户态阻断存在时间窗口：从内核事件产生 → ring buffer 传输 → 用户态解码 → 规则匹配 → kill 系统调用，延迟可达数毫秒，恶意进程在此期间可继续执行破坏操作。对于 critical 级别攻击（如容器逃逸 commit_creds、内核模块加载 insmod），任何延迟都可能导致防线被突破。项目需要一个"检测即阻断"的零延迟方案。

### 决策

在 eBPF 内核态引入阻断机制：

1. **`block_decisions` LRU_HASH Map**：设计为"用户态检测引擎发现高危行为后，将 PID 写入此 Map（带 TTL 过期时间），eBPF 探针在后续系统调用查询此 Map，命中则 `bpf_send_signal(SIGKILL)`"。**⚠️ 2026-08-31 现状：用户态（blocker.rs / start.rs / ks-server）从不写该 map**——全仓无写入点；当前用户态阻断是纯内存表（BlockManager），与内核 map 是两条平行通道。该闭环属于设计意图，尚未实现。
2. **`infer_event` verdict 返回值**：内核态推理引擎返回 verdict=2（应阻断）时，探针在 **enforce 门控通过后**调 `bpf_send_signal(9)` 终止进程。门控条件：`CFG_ENFORCE_MODE==1`（KS_ENFORCE=1）、干跑期已过（infer_config[6]）、risk >= kill 阈值（infer_config[7]，默认 70）、且非 protected（protected_pids / protected_comms + exe_path 反伪装）。

通过 `KS_MAYBE_BLOCK(pid, verdict)` 宏统一封装：
- **Modern tier**（5.8+，`KS_RINGBUF=1`）：门控通过后 verdict==2 时 SIGKILL + 查询 block_decisions map；block 命中（未过期、非 protected）也 SIGKILL
- **Legacy/Ancient tier**（3.10/4.x）：仅查询 block_decisions map 返回命中标记，**从不调 bpf_send_signal**（老内核无该 helper，避免 verifier 拒绝/panic）

### 影响

**有利**：
- verify==2 且 enforce 门控通过时的 critical 攻击在内核态零延迟终止，恶意进程无法继续执行任何系统调用；
- 分 tier 策略确保 Ancient 内核（3.10）不会因调用不支持的 helper 导致 panic（已真机验证：7-29 5.15 enforce SIGKILL 生效，自身/父链经 protected_pids 豁免不自杀）；
- LRU_HASH Map 自动淘汰过期条目，无需手动清理。

**不利**：
- `bpf_send_signal` 仅在 5.8+ 内核可用，老内核回退到用户态标记（无实杀能力）；
- 内核态阻断不可撤销——SIGKILL 已发出即无法中断，误判会直接杀掉正常进程（8 月真机曾误杀 sshd，已补 protected_comms + exe_path 反伪装 + 干跑期缓解）；
- 用户态→内核 map 写入闭环尚未实现（当前用户态阻断表不影响内核实杀）；
- 当前 verdict 返回值仅 0/1/2 三级，无法表达"限流""降权"等中间处置策略。

---

## ADR-012: EWMA 在线学习自适应检测模型

**状态**: Accepted

### 背景

传统规则引擎依赖硬编码阈值（如"60 秒内 >5000 次系统调用即异常"），无法适应不同工作负载——数据库服务器正常高频 I/O 会被误报，轻量容器内少量异常即漏报。`BaselineManager`（z-score 滑动窗口）虽能建立基线，但需要 5 个完整窗口（5 分钟）才能生效，冷启动期间无防护。项目需要一种能快速适应、逐步学习进程正常行为模式的检测模型，在冷启动期也能提供基础防护。

### 决策

引入 `AdaptiveDetector`（EWMA 指数加权移动平均），与 `BaselineManager` 并行运行、取并集告警：

- **EWMA 模型**：`mean = α × current + (1-α) × old_mean`，α=0.3（新数据权重 30%，约 7 个样本后旧数据权重 <5%）。方差同步更新，z-score = |current - mean| / stddev。
- **冷启动 fallback**：样本数 <5 窗口时用固定阈值（syscall 5000/file 500/net 100/dns 50/ptrace 3/signal 10），不依赖统计模型。
- **误报反馈闭环**：用户标记误报后阈值 ×1.1（提升 10%），后续 100 个正常样本后衰减回原值。
- **双模型并集**：BaselineManager（稳定基线）和 AdaptiveDetector（趋势变化）任一触发即告警，severity 取较高。

### 影响

**有利**：
- 冷启动期即有防护（固定阈值 fallback），不依赖历史数据积累；
- EWMA 对趋势变化响应快（α=0.3，7 个样本收敛），适合渐变型攻击；
- 误报反馈闭环让用户纠正误报后系统自动调整阈值，减少重复误报；
- 双模型并集覆盖更多攻击模式——BaselineManager 擅长稳定基线偏离，AdaptiveDetector 擅长趋势突变。

**不利**：
- 双模型并行增加内存开销（每个 pid 维护 6 个 EwmaState + 6 个 StatBaseline）——2026-08 OOM 修复后按 pid LRU 淘汰（max_pids=10000，按窗口活跃度淘汰至 9000，ml_detector 5 张 per-PID 表与 baseline freq_history 全加守卫，RSS 1.4GB→3.9MB，误报 150万→33）；
- EWMA α 值需手动调优——α 太大噪声敏感、太小响应慢，当前 0.3 是经验值，未在不同工作负载下验证；
- 误报反馈后阈值 ×1.1 是线性提升，极端高频场景可能需多次反馈才能抑制误报；
- 冷启动固定阈值与 EWMA 阈值可能不一致，模型切换时可能出现告警抖动。
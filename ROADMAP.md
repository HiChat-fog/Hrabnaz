# Hrabnaz Roadmap

---

## Phase H — 当前工作（按优先级）

### H-1 检测与取证缺陷修复

|  | 缺陷 | 根因（已核实） | 修复方向 | 验收标准 |
|------|------|---------------|---------|---------|
| H-1.1 ✅ 代码完成 | **verify_chain 跨文件续链锚点假阳性** | 校验器要求文件首条 prev_hash=创世值；日志按天滚动/重启续链后首条锚指向前代文件（常被轮转清理），replay 误报"第 1 条断裂"。实测文件内 127,973 条记录零断裂、逐条哈希正确——链完好，校验器假阳性 | 改为"文件内连续性 + 逐条自身哈希"校验；首条锚点非创世时如实标注"锚定于上一世代"；补单测：锚定文件通过、真篡改仍失败、跨文件续链通过 | 真机 replay 显示"链完整性 通过"，人工篡改一条仍能精确定位（2026-10-15：verify_chain 语义改为文件内连续性+逐条自身哈希，ChainVerification 增加 anchored 字段，replay 人读版与 --json 均标注锚定；+5 单测（含半行容错）。**真机复核通过**: 6.1 replay 234454 条"通过 (首条锚定于上一世代)"；解析失败行（写中途 kill/活动文件半行）计入 broken_at 定位行号而非整体 Err；两机初现的"断裂"经三重排查（seq 衔接/Rust 重算/replay 复跑）确认为验证脚本双写者窗口遗留，非篡改非引擎 bug，教训已记录复验报告） |
| H-1.2 ✅ | **3.10 udp_sendmsg 地址提取失效** | Ancient 编译档（nobtf）下 daddr/dport 恒 0（实测 76 条 udp 事件全 0），DNS 判定分支（dport==53）永不可达；tcp_connect 路径正常 | 核对 3.10 struct sock 布局修正偏移；等价性测试补 udp 路径用例 | CentOS 上 DNS 隧道场景出告警（对照 Debian ×60）（2026-10-15 完成：根因非 sock 布局而是**函数签名**——内嵌 3.10 BTF FUNC_PROTO 核实 udp_sendmsg 带 kiocb 首参（4.2 前签名），探针按 args[0] 取 sk 拿到 iocb 指针；修复=KS_TIER_ANCIENT 下 4 参声明 sk=args[1]，反汇编双 tier 验证；真机 123.56.146.16 复测：UDP 事件带真实地址、dport=53 事件 164 条、dns_tunnel 规则+关联双告警命中；+1 字节级解码等价性测试，workspace 180 测试。见 ks-test-evidence/h12-2026-10-15/） |
| H-1.3 ✅ | **文件写探针覆盖缺口** | cp（copy_file_range）/cat（splice）绕过 vfs_write kprobe，勒索场景零命中；dd 走 write 正常命中 ×10。另 vfs_write 有 count<1024 采集门槛 | 增挂 copy_file_range/splice 点位；评估 1024 门槛对勒索检测的影响（真实勒索软件以 write 为主，但批量小文件写是常见变体） | cp/cat 加密变体场景出告警（2026-10-15 完成：新增 kprobe/do_splice_direct 写出侧探针——3.10 BTF 核实 cp(copy_file_range)/sendfile/cat 在 RHEL 上都回落 do_splice_direct，一个点位覆盖三类来源且与 vfs_write 无双计；file_out 必须 regular file 滤掉 sendfile→socket 噪音，≥1024B 门槛与 vfs_write 一致；探针数 16→17（loader/status/CI 断言同步）。真机：6.1 cp/cat 各出 FILE_WRITE 事件，3.10 cp/cat 各 128 条（8MB 分 chunk）；1024 门槛保留——批量小文件勒索变体由 anomaly_score 频率维度兜底，真机未见漏报） |
| H-1.4 ✅ | **基线白名单无配置入口** | INHERENTLY_HIGH_FREQ 为编译期常量（wget/curl/python/nginx…），部署方无法按环境扩展；且包含匹配大小写敏感（Chrome_ChildIOT 未命中 chrome） | 白名单配置化（环境变量或 YAML），匹配改不区分大小写 | 桌面/服务器环境可各自配置，冷启动误报显著下降（2026-10-15 完成：KS_BASELINE_HIGHFREQ 逗号扩展 + 匹配大小写不敏感（Chrome_ChildIOT 命中 chrome，+2 单测）；白名单进程同时跳过基线偏离与 ML 冷启动告警——冷启动固定阈值下白名单进程正常突刺是误报主源） |
| H-1.5 ✅ | **规则文件完整性校验缺失** | root 可篡改 YAML 将 enforce 改 audit（威胁模型内 root 是管理者，但纵深上应有防线） | 加载时对规则集做哈希比对，基线哈希由部署方保管；不一致时告警并可选拒载 | 篡改规则后启动产生完整性告警（2026-10-15 完成：rules_integrity 模块——目录指纹（文件名+逐文件 SHA-256 组合，重命名/删文件必变）+ `ks rules-digest` 子命令生成基线 + KS_RULES_DIGEST 环境比对；MISMATCH 产生 High 审计告警进取证哈希链留痕，KS_RULES_DIGEST_STRICT=1 拒绝启动；热加载同步落快照；快照常落 rules_integrity.log 供无基线回溯。真机 6.1 验证：MISMATCH 告警落链 ✓；+4 单测） |
| H-1.6 ✅ | **watchdog 缺失** | 引擎被 kill 后用户态检测与 killer 失效，内核探针残留空转（systemd Restart 可拉起，但停机窗口无覆盖） | 探针活性自检（ringbuf 消费心跳）+ 可选独立守护进程 | kill 引擎后 ≤N 秒自动恢复消费（2026-10-15 完成：引擎主循环 10s 原子写心跳文件（/run/kernelsentinel/ks-heartbeat.json，含 pid/时间戳/消费数，退出清理）；`ks watchdog` 子命令读心跳判停摆（默认 60s=6 周期），SIGTERM 前做 /proc 身份校验（复用 stop 同款判定防 PID 复用误杀），--dry-run 巡检模式；deploy/ 新增 kernelsentinel-watchdog.service+timer（每分钟巡检，KS_WITH_WATCHDOG=1 安装启用），systemd Restart 闭环=停摆后 ≤1min 恢复消费。真机 6.1 验证：心跳文件 ✓ watchdog 心跳正常判定 ✓） |

### H-2 架构主线：aya 上游化与 BTF 内嵌正式化

3.10 真机已证明 CO-RE 重定位可完全在用户态完成，内核侧 BTF 支持并非必要条件，这项能力如果有可能则应回到上游生态本体。

- **路径 A（并行）：aya 上游化**
  - 三层 vendor 补丁整理成可提交系列：老内核 BTF 清洗（kind_flag/位域结构/空枚举值名）、BPF_PROG_LOAD 字段按 5.0 门控、<4.17 kprobe 条目先关 perf fd 再删的 EBUSY 修复
  - PR #1751（无 BTF 场景 map 创建修复）跟进评审直至合并
  - H-1 修复中产生的新补丁随修随提
- **路径 B（优先）：自主 BTF 内嵌正式化**
  - 保持零依赖交付形态：BTF 采集在构建期完成（按发行版 release 采集或由 debuginfo+pahole 现场生成），裁剪后随单二进制发布，加载时按内核版本自动选取
- **共同收尾**：vanilla 4.4/4.9（Debian 9/Ubuntu 16.04 世代）下限验证；Ubuntu 4.15/5.4、RHEL8/9 等常见企业内核 BTF 预埋扩容（每份约十分钟接入，等价性测试自动验证）；nobtf 编译档与 C loader 退役

### H-3 吞吐优化与性能基准 ✅ (2026-10-15 代码完成+真机对照)

- 优化落地（单消费者架构内）：
  - ✅ anomaly by_pid 全量 clone 消除（by_pid_arcs + reconstruct(&[Arc<DecodedEvent>])，Arc 引用计数替代深拷贝）
  - ✅ 每 tick 批量 drain（batch_size=64 统一处理）+ 满批自适应 busy-poll（yield_now 直通，空批维持退避）
  - ✅ 复用缓冲消除每事件 to_vec（EventSource::next_bytes_reuse + aya ringbuf/perfbuf 直读覆写）
- 对照结果（真机 KS_PROF 剖析）: 处理层 61μs → 30.1μs/事件（**-51%**），理论 16.4K/s → 33.2K/s；端到端高负载 6.1 1250/s、3.10 1422/s（受 loadgen 产速率上限制约，0 drop）；详见 ks-test-evidence/h3-2026-10-15/
- P99 延迟长时数据随 H-4 ART 校准阶段补充
- 不做（维持）：多线程化

### H-4 质量与长稳

- **unsafe 收敛 ✅ (2026-10-16)**：运行时 unsafe 20 处 → **8 处**（sys.rs 6 个 libc FFI 块 + linux_map_reader 2 个 aya Pod 声明），业务代码零 unsafe。聚合器字节流解析用固定偏移手工提取替代 union 指针读（union 删除，逐字段下界检查越界置 0）；测试/回放编码走 zerocopy IntoBytes（含显式化尾部对齐填充）；libc 边界收拢 `ks-engine/src/sys.rs`（CLI 经依赖复用，FFI 只剩一份）。等价性：mock 前 300 条告警序列逐字段一致、告警率 1.3510→1.3520；真机双机 15 万+ 真实 eBPF 字节走安全解码，H-2/H-3 回归正常。187 测试全绿。后续剩余 8 处也已归零：libc 边界改走 nix 安全封装，`linux_map_reader` 的 Pod 声明删除（aya 对 `[u8; N]` 自带实现）；当前全仓库 `unsafe {` 为 0。
- **检出率校准**：Atomic Red Team 公开样本库跑规则集对应 T 编号，检出率从"场景命中"升级为可复现量化指标；48h 真实业务基线人工标注测 FPR（目标 <10 条/天/台）
- **长稳矩阵**：4.19 补入 systemd 长稳 soak（本地 QEMU），与 3.10、6.1 同标准验收；3.10/6.1 现有常驻继续积累运行时长

### H-5 新探针贡献架构：单一来源注册表 ✅ (2026-10-17)

当前新增一个探针需要同时修改 7 处、分散在 4 个文件（探针头、ks_main.bpf.c 的 include、build.rs 的 rerun-if-changed、loader.rs 的硬编码清单与 attach 宏调用、status.rs 报表），且漏改任何一处都不会编译失败——漏注册是静默失效，漏 rerun 是假绿。这个接入成本对后续贡献者过高。

- **方案**：探针头文件自带注册段（宏声明的 SEC 元数据：探针名/类型/挂载点/依赖内核符号），构建期从编译产物 `.o` 的 SEC 段自动枚举全部探针，loader 按枚举结果生成 attach 循环（含缺符号跳过逻辑），build.rs 按 SEC 段自动生成 rerun-if-changed，status.rs 报表同源。不维护任何手工清单
- **配套**：CONTRIBUTING.md 增加"如何添加探针"章节（新头文件 + 注册段 + 可选新事件类型，三步）；CI 增加断言——`.o` 内 SEC 探针数与 status 报表数一致，防静默失效回归
- **事件类型门槛不放宽**：新探针复用现有事件类型零门槛；需要新事件类型必须走 ks-core 契约（结构体 + 编译期断言 + 解码分支），契约先行不为方便放宽
- **落地 (2026-10-17)**：SEC 注解即注册——`build.rs` 内置 ELF64 解析器从各 tier 编译产物的可执行 SEC 段自动枚举程序名/类型/挂载点，生成 `probes_generated.rs`；loader 删除 17 项硬编码清单与 attach 宏，按注册表 attach（仅保留两张**策略**表：do_init_module/load_module 二选一回退组、security_bpf_prog_free attach 容错）；status 报表同源按 ProbeKind 统计；build.rs 改递归 rerun（新增头文件自动触发）；未知 SEC/段内无函数/一段多函数均编译期报错；CI 断言用同一解析器复核嵌入 `.o` 的 SEC 段与注册表逐条一致。验收演示：只改探针头文件新增 `SEC("kprobe/do_mount")` 探针，注册表 18→19→18，未改 loader/build/status 任何清单。213 测试；双机部署：3.10 实挂 `r:kprobes/aya_..._r_load_module`（回退组生效），6.1 的 file_write/net_connect/file_delete/file_rename 等 kprobe 事件正常流通

### H-6 CLI 可用性打磨 ✅ (2026-10-23)

定位：交付、演示与脚本化的最小实现。原问题是子命令帮助大量空白、start 残留 serve 参数、watch 只能靠 grep、错误直接抛 anyhow 链、status 没有机读输出。

- **帮助**：所有子命令与参数有一句话说明；根命令给常用示例；watch 用 `long_about/after_help` 固化过滤语义，不再需要现场解释
- **watch**：`--rule/--comm/--severity/--pid/--file`，同一 flag 多次为 OR、不同 flag 之间为 AND；rule/comm 是大小写敏感 glob（`*`/`?`），severity 是最低级别而非精确匹配，file 是路径子串且要求告警自带文件上下文
- **watch 行为**：默认 follow；`--no-follow` 读完当前日志即退出；`--max` 在 follow 下统计新告警、在 no-follow 下截断输出；`--json` 输出 JSONL（follow 时不回显历史）；启动回显最近 20 条匹配历史；轮转/截断按 dev/ino 跟随，不把归档误当活跃文件
- **status**：人读版保留；`--json` 输出 `schema_version=1` 的单行快照，probes 按 tracepoint/kprobe/kretprobe 分项，`config_defaults` 明确是编译期默认值而非运行实例配置；`--watch --json` 输出 JSONL
- **错误与退出码**：clap 用法错误 exit 2；运行期错误统一 `error: <人话>` + exit 1；anyhow 调用链只在 `-l debug|trace` 时输出；下游关闭管道（`watch --json | head`）时安静退出 0，不输出 broken-pipe panic（start 保留收尾路径）
- **补全**：`completion bash|zsh|fish|powershell|elvish` 生成静态脚本，不引入新依赖
- **副作用收敛**：`setrlimit(RLIMIT_MEMLOCK)` 只在 start 执行，status/replay/completion 等不再向 stderr 输出无关警告
- **纯度**：只改 `crates/ks-cli` 与文档。过滤发生在告警产生并写入取证日志之后，不触碰 `ks-core`/`ks-ebpf`/`ks-engine`，不新增告警 schema，`status --json` 不进入取证日志或 replay 判定
- **验收**：231 测试全绿（CLI 新增 6 个单元测试 + 8 个进程级集成测试）；`git diff -- crates/ks-core crates/ks-ebpf crates/ks-engine` 为空
- 不做：交互式 TUI、进度动画、配置向导

### H-7 引擎内聚：让 ks-engine 可被独立消费 ✅ (2026-10-16)

- 落地：`ks-engine/src/engine.rs` 新增 `Engine` 公共 API——`start(EngineOptions)` 生命周期（tier 路由→规则+完整性→组件→阻断通道 pin/killer→取证 worker→心跳→热加载）+ `tick()`/`process_event()` 两个处理入口 + `shutdown()` 收尾；检测结果以 `EngineEffect`（Alert/Blocked/Score/Chain，按发生顺序）返回，**引擎零 UI 输出**，呈现由消费方决定
- CLI start.rs：1222 行 → 约 420 行薄壳（单例锁/参数/UI 渲染/信号/状态文件），业务逻辑零残留；`correlation_to_alert` 下沉为 `CorrelationAlert::to_alert()`
- **等价性证明**：重构前后 mock 全场景前 300 条告警序列逐字段完全一致，每事件告警率 1.3526→1.3528（噪声级）；187 测试全绿
- **可嵌入性证明**：`crates/ks-engine/examples/embed_demo.rs`（~90 行）直接消费 ks-engine 跑通全链路（34 事件→28 告警→取证链 62 条校验通过），无需 root/内核
- 意外红利：引擎 e2e 测试（Provided mock 源）使 CI 无 root 覆盖全检测主链（规则/关联/取证链/统计断言）
- 循环控制权保留在消费方（tick 模式而非回调），CLI 的信号处理/心跳/killer 路径行为不变

---

## Phase I — 结题

| # | 交付物 | 内容 |
|---|---|---|
| I-1 | 性能对照报告 | H-3 产出，含三组对照 × 双内核矩阵 |
| I-2 | 检出率报告 | H-4 产出，ART 校准结果 + FPR 数据 |
| I-3 | 演示视频 | 六场景检测、阻断（双路径）、取证回放全流程 |
| I-4 | 部署包 | musl 静态单二进制 + 规则集 + 场景脚本 + install/uninstall（pack.sh 已有） |
| I-5 | 文档终版 | 部署说明、使用手册、YAML 规则编写指南（含 enforce 守则）、跨内核兼容设计文档 |
| I-6 | 源码仓库公开 | 随比赛要求；含上游贡献记录（#1661/#1751） |

> 依赖 H-1~H-4 的修复与优化落地后

---

## Phase J — 长期方向

| 编号 | 方向 | 说明 | 前置 |
|------|------|------|------|
| J-1 | 取证脱敏配置化 | 命令行/路径/地址按合规要求脱敏（等保场景），默认保持完整性优先 | — |
| J-2 | 分位数基线 | 中位数+MAD 替代 z-score，对长尾分布与训练期投毒稳健 | H-4 |
| J-3 | 规则热更新 + 内核过滤表动态下发 | 新增敏感路径规则不必重启；过滤表从编译期固化改为运行时可下发 | — |
| J-4 | 链尾外置自动化 | 远端 syslog/对象存储自动外发链尾，补"root 全删日志"盲区 | — |
| J-5 | 威胁情报目的信誉 | 补"合法进程内低频、陌生目标、小流量外传"盲区（qa 专题已定性） | — |
| J-6 | io_uring 全覆盖 | 5.1+ io_uring tracepoint（3.10 平台不适用，按 tier 标注） | — |
| J-7 | eBPF 程序 Fuzz | libAFL + harness，验证器边界与 map 越界 | — |
| J-8 | ARM64 适配 | 条件编译 + syscall 号映射（原 F-4 顺延） | 交叉编译环境 |
| J-9 | 事件驱动唤醒 killer | 替代 300ms 轮询，缩短老内核阻断时延 | H-3 |

**明确不做**Web 前端、分布式部署、SIEM 对接

---

## milestone

| Phase | 内容 | 状态 |
|---|---|---|
| Phase E | 多 tier 端到端（E1-E4，14 工作项）：aya 三路径事件源、tier_detect 自动路由、Ancient 3.10 真机 13/13 探针、容器逃逸/eBPF 自保护/LKM 探针 | ✅ |
| Phase F | 工程化：CI/CD（test/lint/ebpf-compile/shellcheck/release）、安全加固（mTLS/Bearer/限流/审计，后随 serve 删除部分退役）、criterion 压测骨架 | ✅ |
| Phase G | 检测深化：EWMA 自适应 + 冷启动 fallback、内核态阻断 block_decisions + KS_MAYBE_BLOCK、BPF Map 结构化读取、e2e 12 攻击场景（14 测试）、误报反馈闭环 | ✅ |
| 中期节点 | 删 serve 回归 CLI-only；探针五头分层解耦；enforce 闸门 + 双侧豁免 + 时序即正确性；aya #1661 合并；3.10/6.1 双路径实杀真机验证；六场景全命中；性能三组数字（延迟 68ns-1.19μs / CPU +5% 上限 / RSS 3MB-185MB） | ✅ 2026-10 |

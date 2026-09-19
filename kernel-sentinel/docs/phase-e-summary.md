# Phase E — 交付物与技术决策汇总

> 本文档汇总 Phase E 四个子阶段（E1/E2/E3/E4）的交付物清单与关键技术决策。
> 配套阅读：[../ARCHITECTURE.md](../ARCHITECTURE.md) 的 "Phase E — 全路线图" 章节、[../ROADMAP.md](../ROADMAP.md) 的 "Phase E 子阶段状态" 表格、[deployment.md](deployment.md)、[performance-design.md](performance-design.md)。

---

## 1. 子阶段交付物

### E1 — Modern tier 端到端 + 自动化 .BTF.ext 剥离

| 子项 | 文件 | 说明 |
|------|------|------|
| E1.1 | `crates/ks-engine/build.rs`（编译矩阵） | 5 tier 各编译一次 `ks_main.bpf.c`，nobtf 两 tier 用 `llvm-objcopy --remove-section .BTF.ext --remove-section .rel.BTF.ext`，让产物不带 CO-RE 重定位信息（注意：剥离逻辑在 ks-engine/build.rs，不在 ks-ebpf/build.rs——后者只是遗留的通用编译路径） |
| E1.2 | `crates/ks-engine/src/linux_map_reader.rs` | aya `MapData::info()` 真实读取 **6** 个共享 map 的 `map_type` 与 `max_entries`（risk_scores / ip_whitelist / net_conn_history / freq_counters / infer_config / protected_comms），替换 MockBpfMapReader |
| E1.2 | `crates/ks-server/src/routes.rs` | `/api/v1/stats` 增加 `map_stats` 字段，前端可显示真实 map 占用 |
| E1.3 | `tests/integration_test.rs` | ransomware / privilege_escalation 全链路场景补全（12 个集成测试全过） |
| E1.4 | `scripts/e2e-modern.sh` | 真实 5.15+ 内核端到端脚本（2026-07-04 在 6.17 内核真机验证通过） |

### E2 — 3.10 ECS 端到端打通

| 子项 | 文件 | 说明 |
|------|------|------|
| E2.1 | `crates/ks-ebpf/scripts/ks_loader.c` | `--stream` 模式 + 帧格式 `[u32 LE length][u8[length] payload]` + 心跳帧（length=0，每 30s） |
| E2.2 | `crates/ks-engine/src/cloader_source.rs` | tokio::process::Command fork+exec ks_loader，read_frame 泛型函数，13 个单元测试 |
| E2.3 | `crates/ks-engine/src/tier_detect.rs` | Legacy/Ancient 的无 BTF 分支均优先 CLoaderSource（ancient_nobtf 需 3.10.0-1160 前缀、legacy_nobtf 需 4.19. 前缀守卫），aya 降级为 fallback |
| E2.4 | `scripts/e2e-ancient-ecs.sh` | 3.10 ECS 实例端到端脚本（ECS 3.10 stock 内核 13/13 探针加载验证通过） |
| —    | `docs/cloader-protocol.md` | 帧协议文档 |

### E3 — Phase E 文档 + 生产化

| 子项 | 文件 | 说明 |
|------|------|------|
| E3.1 | `ARCHITECTURE.md` / `ROADMAP.md` / `README.md` / `docs/phase-e-summary.md` / `docs/deployment.md` / `docs/performance-design.md` | 文档更新与新增 |
| E3.2 | `deploy/kernelsentinel.service` | systemd Type=notify + CapabilityBoundingSet + LimitMEMLOCK=infinity |
| E3.2 | `deploy/install.sh` / `deploy/uninstall.sh` | 部署/卸载脚本 |
| E3.2 | `crates/ks-cli/src/cmds/start.rs` | `--sd-notify` flag 调用 `sd_notify(0, "READY=1")` |
| ~~E3.3~~ | ~~`crates/ks-frontend/`~~ | ~~Vue 3 + Vite + ECharts + D3.js，Dashboard / Alerts / Chain 三页面~~ **已移除（申报书不涉及Web前端）** |
| ~~E3.3~~ | ~~`crates/ks-server/src/server.rs`~~ | ~~`tower_http::services::ServeDir` 挂载 `crates/ks-frontend/dist/` 到 `/`~~ **已移除（申报书不涉及Web前端）** |

### E4 — 检测能力扩展

| 子项 | 文件 | 探针 | event_type |
|------|------|------|------------|
| E4.1 | `crates/ks-ebpf/src/bpf/ks_probes_container.h` | kprobe `commit_creds` | 80 |
| E4.2 | `crates/ks-ebpf/src/bpf/ks_probes_lkm.h` | kprobe `do_init_module`（另 sys_exit 313 finit_module 失败双发射） | 81 |
| E4.3 | `crates/ks-ebpf/src/bpf/ks_probes_self_protect.h` | kprobe `security_bpf_prog_free` | 82 |
| E4.4 | — | 16 探针（5 tracepoint + 11 kprobe）/ 5 tier 编译通过，规则集扩展 + 集成测试 | — |

---

## 2. 关键技术决策

### 2.1 NOBTF 方案 — 3.10 stock 内核加载 eBPF

**背景**：CentOS 7 / Aliyun ECS 3.10.0-1160 stock 内核有完整 eBPF 支持（bpf syscall + helpers + JIT），但 `CONFIG_DEBUG_INFO_BTF` 未启用，`/sys/kernel/btf/vmlinux` 不存在。aya 默认走 BPF CO-RE 重定位，依赖 `.BTF.ext` 段，无 BTF 时加载失败返回 `EINVAL`。

**方案**：三层联动绕过 BTF 依赖：

1. **aya 本地 patch**（`Cargo.toml` `[patch.crates-io] aya = { path = "vendor/aya" }`）：当 `btf_fd=None` 时清零 `btf_key/value_type_id`，避免内核校验 type ID 失败。
2. **build.rs 自动剥离 `.BTF.ext`**（`crates/ks-engine/build.rs` 编译矩阵，仅 ancient_nobtf/legacy_nobtf 两 tier）：编译成功后 `llvm-objcopy --remove-section .BTF.ext --remove-section .rel.BTF.ext`，让产物加载阶段不带 CO-RE 重定位信息（保留 .BTF 段供 aya parse_btf_maps）。
3. **硬编码 offset**（`crates/ks-ebpf/src/bpf/common.h` `KS_NOBTF` 分支）：`BPF_CORE_READ(ptr, field)` 重定义为 `KS_NOREAD_##field(ptr)`，通过 `bpf_probe_read` + 实测 offset 读取字段。Offset 在 3.10.0-1160.119.1.el7.x86_64 上实测获取（ancient：inet_saddr=776 / inet_sport=784；legacy：inet_saddr=728 / inet_sport=736；另 dentry.d_name.name=40 等通用偏移，`scripts/extract-offsets.sh` 从 debuginfo RPM 用 pahole 提取）。注意：probe_read 系列 helper 的重定向条件为 `ANCIENT || (LEGACY && NOBTF)`（common.h:31-36）——带 BTF 的 ancient tier 同样重定向（3.10 内核无 probe_read_user/kernel 等新 helper）。

**为何如此**：BPF CO-RE 重定位是 libbpf/aya 加载阶段行为，运行时无法关闭；patch aya + 剥离段 + 硬编码 offset 三层联动才能完整绕过。单层方案（仅 patch 或仅剥离）会留下未解析的重定位记录导致加载失败。

**取舍**：硬编码 offset 在不同小版本内核上可能漂移，仅适用于固定内核版本（3.10.0-1160 系列）。BTF 路径仍是首选，NOBTF 仅在 stock 内核且无 kernel-plus 包时启用。

### 2.2 CLoaderSource 帧协议 — 为什么选 stdout 管道而非共享内存

**背景**：3.10 stock 内核下 aya 无法加载，需要 C loader（`ks_loader.c`）通过 libelf + bpf syscall 直接加载 .o 文件并把 perfbuf 事件回传给 Rust 用户态。

**方案**：`ks_loader --stream` 加载完成后进入 perfbuf 轮询循环，按帧格式向 stdout 写事件：`[u32 LE length][u8[length] payload]`。Rust 父进程通过 `tokio::process::Command` fork+exec 子进程，从 stdout 异步读帧。stderr 由后台 tokio task 预读到环形缓冲（保留末尾 512 字节用于诊断）。

**为何选 stdout 管道而非共享内存**：

| 方案 | 优点 | 缺点 |
|------|------|------|
| stdout 管道（已选） | 内核自动管理缓冲，无共享内存同步开销；子进程崩溃时父进程 `read` 立即收到 EOF；跨进程隔离强；tokio 原生支持 | 单向数据流；高吞吐时可能受 pipe buffer（默认 64KB）限制 |
| 共享内存 (mmap + ring) | 高吞吐无拷贝 | 需要手动管理同步（锁/原子变量）；子进程崩溃时共享内存状态不一致；C 与 Rust 双端结构体布局需严格对齐；调试困难 |
| Unix socket | 双向通信，可传 fd | 比 pipe 复杂，无显著优势 |
| 文件轮询 | 最简单 | 延迟高，磁盘 IO 开销大 |

事件量级（< 10K events/s）下 stdout 管道完全够用，且调试友好（可直接 `./ks_loader --stream xxx.o | xxd` 看帧）。心跳帧（length=0，每 30s 一次）让父进程能区分"无事件"与"子进程卡死"。

**取舍**：若未来需要 > 100K events/s 吞吐，再切换到共享内存 + 双端 ring buffer。

### 2.3 LinuxBpfMapReader 设计 — 为什么用 MapData::info() 而非 iter().count()

**背景**：`/api/v1/stats` 端点需要暴露 BPF map 真实统计。MockBpfMapReader 返回固定假数据，无法反映 map 实际占用。

**方案**：`LinuxBpfMapReader` 持有 `Arc<Mutex<aya::Ebpf>>` 共享 Ebpf 实例（与 EbpfLoader 共享同一实例），通过 `aya::maps::MapData::info()` 读取 6 个共享 map（`risk_scores` / `ip_whitelist` / `net_conn_history` / `freq_counters` / `infer_config` / `protected_comms`）的 `map_type` 与 `max_entries`。

**为何用 MapData::info() 而非 iter().count()**：

- `MapData::info()` 通过 `BPF_OBJ_GET_INFO_BY_FD` syscall 读取内核维护的元数据，O(1) 无锁，不遍历 map entries。
- `iter().count()` 需要按 map 名硬编码 K/V 类型构造 `aya::maps::HashMap::<&MapData, K, V>::try_from(md).iter()`，遍历所有 entry。对 LRU_HASH（如 `risk_scores` max_entries=4096）会引入数千次 `bpf_map_lookup_elem` syscall，阻塞 stats 端点。
- ARRAY / PERCPU_ARRAY 类型的 `max_entries` == 实际 entry 数（所有槽位始终存在），info() 直接给出准确值。
- HASH / LRU_HASH 的 `max_entries` 是容量上限，实际 entry 数需要 iter().count() — 当前实现返回容量，TODO 标注未来按需扩展。

**取舍**：当前仅返回统计信息（map_type + max_entries），不读 entries 内容。真实读取 entries 需要 K/V 类型硬编码（如 `risk_scores: (u32, u32)`），不阻塞 E1.3 集成测试和 E1.4 端到端脚本。

### 2.4 3 个新探针的 event_type 编号选择 — 为什么是 80-82

**背景**：E4 新增 3 个安全探针，需要分配 event_type 编号。现有编号已占用：

| 段 | 用途 |
|----|------|
| 1-3 | 进程 exec/exit/clone |
| 10-15 | 文件 open/read/write/delete/rename/chmod |
| 20-24 | 网络 connect/accept/send/recv/dns |
| 30-31 | 进程 ptrace/signal |
| 40-43 | 进程树事件 |
| 50-54 | 网络流事件 |
| 60-61 | 频率计数事件 |
| 70-72 | 智能过滤事件 |

**方案**：分配 80-82 给三个新探针：

- `EVENT_CONTAINER_ESCAPE = 80` — 容器逃逸（commit_creds）
- `EVENT_LKM_LOAD = 81` — 内核模块加载（do_init_module）
- `EVENT_EBPF_TAMPER = 82` — eBPF 自身防护（security_bpf_prog_free）

**为何选 80-82**：

- 避开所有已占用段（1-31 / 40-43 / 50-54 / 60-61 / 70-72），无冲突。
- 80-99 是预留的"安全事件段"，与 1-31 的"业务事件"语义分离，便于用户态聚合器按段路由（如安全事件优先级更高）。
- 留出 73-79 与 83-99 的空段，未来扩展（如 90-99 预留给合规审计事件）。
- 与 common.h 的 `EventType` enum（ks-core）兼容，前端按段着色（业务事件蓝色 / 安全事件红色）。

### 2.5 systemd CapabilityBoundingSet 设计 — 为什么需要 CAP_SYS_PTRACE / CAP_DAC_READ_SEARCH

**背景**：systemd 服务以 root 启动，但通过 CapabilityBoundingSet 限制实际能力，遵循最小权限原则。

**方案**（`deploy/kernelsentinel.service`）：

```
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
LimitMEMLOCK=infinity
```

| Capability | 用途 |
|------------|------|
| `CAP_BPF` | 创建 / 加载 / 管理 BPF program 与 map（5.8+ 内核） |
| `CAP_PERFMON` | perf_event_open 系统调用，perfbuf 路径需要（与 CAP_BPF 分离，5.8+ 引入） |
| `CAP_SYS_ADMIN` | 老内核（4.x / 3.10）下加载 BPF 程序的回退能力；mount namespace 操作 |
| `CAP_NET_ADMIN` | 网络探针 attach（tc / xdp），读取 socket 信息 |
| `CAP_SYS_PTRACE` | ptrace 探针 + 读取 /proc/<pid>/exe、/proc/<pid>/cmdline（其他进程的 cmdline 在严格模式下需要） |
| `CAP_DAC_READ_SEARCH` | 绕过文件权限检查读取任意路径（VFS 探针需要打开 /proc /sys /etc/shadow 等敏感路径做规则匹配） |

**为何需要 CAP_SYS_PTRACE / CAP_DAC_READ_SEARCH**：

- `CAP_SYS_PTRACE`：用户态聚合器在解码 ptrace 事件时需要读取目标进程 /proc 信息（exe 路径、cmdline）。Linux 4.10+ 默认 `kernel.yama.ptrace_scope=1` 限制 ptrace 仅限父子进程，需要此 capability 绕过。
- `CAP_DAC_READ_SEARCH`：VFS 探针捕获文件访问事件后，用户态规则引擎可能需要读取文件元数据做匹配（如 /etc/shadow 的哈希前缀做异常评分）。无此 capability 时 root 也可能因 SELinux / AppArmor 策略被拒（虽然 DAC 检查通过，但 MAC 仍可能拦截）。

**`LimitMEMLOCK=infinity`**：eBPF map 在内核中分配的内存受 `RLIMIT_MEMLOCK` 限制，默认仅 64KB，远远不够 `risk_scores` (4096 entries) + `net_conn_history` (8192 entries) + `freq_counters` + `process_tree` (65536 entries × 312B) + events ringbuf (16MB) 等 map 总和。设为 infinity 让内核按需分配。

**`Type=notify`**：ks-cli 通过 `--sd-notify` flag 在所有探针 attach 完成 + 规则加载完成 + 引擎初始化完成后调用 `sd_notify(0, "READY=1")`，systemd 收到通知后才标记服务为 active。这样 `systemctl start` 在真正就绪前不会返回成功，避免 health check 误判。

**安全取舍**：`NoNewPrivileges=false` / `ProtectSystem=false` / `ProtectHome=false` 看似削弱隔离，但 eBPF 程序需要访问整个系统（所有进程、所有文件、所有网络连接），过度隔离会让探针失效。真正的隔离通过 capability bounding + eBPF verifier 自身保证。

---

## 3. Phase E 状态总览

| 子阶段 | 状态 | 备注 |
|--------|------|------|
| E1.1 build.rs 自动剥离 .BTF.ext | ✅ 已完成 | 5 tier 编译矩阵在 `crates/ks-engine/build.rs`，nobtf 两 tier 编译成功后剥离 |
| E1.2 LinuxBpfMapReader 真实化 | ✅ 已完成 | 6 个共享 map 真实读取，/api/v1/stats 增 map_stats |
| E1.3 集成测试补全 | ✅ 已完成 | ransomware / privilege_escalation 全链路，integration_test.rs 12 个测试全过 |
| E1.4 e2e-modern.sh | ✅ 已完成 | 2026-07-04 在 6.17 内核真机验证通过；2026-08-13 5.15/6.1 重复验证 EXIT=0 |
| E2.1 ks_loader.c --stream | ✅ 已完成 | 帧格式输出 + 心跳帧（30s）+ `--load-only` 默认模式 |
| E2.2 CLoaderSource Rust | ✅ 已完成 | 13 个单元测试 |
| E2.3 tier_detect 路由 | ✅ 已完成 | Legacy/Ancient 无 BTF 双分支优先 CLoaderSource（含 3.10.0-1160 / 4.19. 前缀守卫） |
| E2.4 e2e-ancient-ecs.sh | ✅ 已完成 | 3.10 ECS stock 内核 13/13 探针加载验证通过；2026-08-13 完整 Rust 链路真机验证 |
| E3.1 文档更新 | ✅ 已完成 | 本文件 + ARCHITECTURE / ROADMAP / README / deployment / performance-design |
| E3.2 systemd + install.sh | ✅ 已完成 | Type=notify + CapabilityBoundingSet + --sd-notify |
| ~~E3.3 ks-frontend~~ | ~~✅ 已完成~~ | ~~Dashboard / Alerts / Chain + ServeDir~~ **已移除（申报书不涉及Web前端）** |
| E4.1 容器逃逸探针 | ✅ 已完成 | ks_probes_container.h, event_type=80 |
| E4.2 LKM 加载探针 | ✅ 已完成 | ks_probes_lkm.h, event_type=81（kprobe + sys_exit 313 双发射） |
| E4.3 eBPF 自身防护探针 | ✅ 已完成 | ks_probes_self_protect.h, event_type=82 |
| E4.4 规则集扩展 + 集成测试 | ✅ 已完成 | 16 探针（5 tracepoint + 11 kprobe）/ 5 tier 编译通过，9 套规则 23 条，e2e 14 测试 |

> E1.4 已实测：2026-07-04 6.17 真机通过（3902 事件 / 20 告警 / 0 丢包），2026-08-13 三机端到端回归通过。
> 性能与丢包率数据详见 [performance-design.md](performance-design.md)。

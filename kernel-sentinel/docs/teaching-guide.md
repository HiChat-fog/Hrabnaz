# 内核哨兵 — 教学应用指南

> ⚠️ 2026-08-31 修订：原稿中的 Web UI（ks-frontend 已按申报书约束移除）、`--mode observe/block` flag、
> `sudo make install`、`/api/v1/process-tree` 等路由不存在——以下实验步骤已改为实际可用的
> CLI（kernelsentinel status/watch/replay，含 start --serve 的 REST API + WebSocket）。
> 无 Web 界面：所有可视化走终端（comfy-table/sparkline/时间线）或 curl + python -m json.tool。

## 1. 教学定位

"内核哨兵"在方向五（智慧教学）中的定位：
**一个面向信息安全/计算机专业学生的 Linux 内核安全教学平台**。

不同于传统的 PPT 教学或虚拟机实验，学生可以直接观察到：
- 操作系统内核如何响应系统调用
- 恶意程序在内核层面留下了哪些痕迹
- eBPF 如何在生产环境中实现零侵入监控
- 自适应学习如何区分正常与异常行为

### 教学环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux 5.8+（推荐 Ubuntu 22.04 / Debian 12；3.10/4.19 老内核走 C loader 兼容路径） |
| 内核权限 | `sudo`（eBPF 加载需 root；或 systemd 部署的 CapabilityBoundingSet） |
| 依赖 | clang-18, llvm-18, libelf-dev, Rust stable（构建机）；目标机只需单二进制 |
| 安装 | `cd kernel-sentinel && cargo build --release && sudo bash deploy/install.sh`（或 `bash scripts/pack.sh` 后 `sudo ./install.sh`） |

---

## 2. 教学内容设计（6 个实验）

### 实验一：系统调用观测 (60 分钟)

**目标**: 理解 Linux 系统调用机制与 eBPF tracepoint 原理

**实验步骤**:

```bash
# 1. 启动内核哨兵（monitor 模式，只告警不杀——默认即为 monitor）
sudo kernelsentinel start --rules-dir rules/ --log-dir /tmp/ks-lab1 \
  --serve 8443 --auth-token "$(openssl rand -hex 16)" &
sleep 5

# 2. 实时事件流（终端内，每秒刷新）
kernelsentinel watch -s http://127.0.0.1:3000

# 3. 在另一个终端执行日常命令
ls -la /tmp
cat /etc/hostname
wget -q -O /dev/null https://example.com

# 4. 回放取证日志（查看完整事件流）
kernelsentinel replay --file /tmp/ks-lab1/events_*.jsonl | head -50
#    记录: event_type, syscall_nr, comm, filename

# 5. 对比 strace 输出
strace -e trace=execve,openat,connect ls /tmp 2>&1 | head -20
```

**预期输出**: watch 显示 execve→file_open→net 事件链；replay 的时间线分布展示各事件类型占比，syscall_nr 对应系统调用号（execve=59, openat=257, connect=42）。

**思考题**:
1. `execve` 和 `openat` 的系统调用号是多少？为什么 x86_64 和 ARM64 不同？
2. eBPF tracepoint 和 kprobe 有什么区别？哪个更稳定？
3. 用户态 `strace` 和内核态 eBPF 观测的性能差异有多大？

**延伸阅读**: [docs/adr.md](adr.md) ADR-001（eBPF vs Kernel Module 选型）

---

### 实验二：进程生命周期追踪 (60 分钟)

**目标**: 理解 Linux 进程管理与进程树拓扑

**实验步骤**:

```bash
# 1. 启动内核哨兵
sudo kernelsentinel start --rules-dir rules/ --log-dir /tmp/ks-lab2 --serve 8443 &

# 2. 创建进程链：bash → sleep → 子进程
bash -c 'sleep 10 & sleep 5 & wait'

# 3. 观察进程树事件（watch 输出含 TREE_FORK/TREE_EXEC/TREE_EXIT）
kernelsentinel watch --json | grep -E 'tree|40|41|42' | head -30
# 或直接查 BPF map 里的进程树拓扑（需 start --serve）
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/api/v1/maps/process_tree | python3 -m json.tool

# 4. 模拟孤儿进程
bash -c 'sleep 30 & disown' && exit

# 5. 查看进程树实时状态（status --watch 显示 map 条目数）
kernelsentinel status --watch --interval 2
```

**预期输出**: tree_events 里 fork/exec/exit 三类事件按时间排列；进程树 map 记录 pid/ppid/comm/exe_path；孤儿进程被 reparent 到 PID 1（ppid 变化）。
⚠️ 终端有颜色：`watch` 输出用 severity 色标（critical 红 / high 黄 / low 绿），管道重定向加 `--color never`。

**思考题**:
1. `fork()` 和 `clone()` 在内核层面有什么区别？
2. 僵尸进程是如何产生的？为什么需要 `wait()`？
3. 内核哨兵的进程树追踪探针挂载在哪些 tracepoint 上？

**延伸阅读**: [crates/ks-ebpf/src/bpf/ks_probes_process_tree.h](../crates/ks-ebpf/src/bpf/ks_probes_process_tree.h)

---

### 实验三：文件系统操作追踪 (60 分钟)

**目标**: 理解 Linux VFS 层与文件操作审计

**实验步骤**:

```bash
# 1. 启动内核哨兵
sudo kernelsentinel start --rules-dir rules/ --log-dir /tmp/ks-lab3 --serve 8443 &

# 2. 执行文件操作
echo "test data" > /tmp/lab3_test.txt
cp /tmp/lab3_test.txt /tmp/lab3_copy.txt
chmod 644 /tmp/lab3_test.txt
rm /tmp/lab3_copy.txt

# 3. 查看告警（REST API；响应为 JSON）
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8443/api/v1/alerts?limit=20" | python3 -m json.tool
#    关注: severity, rule_name(如有), process.comm, file.path

# 4. 敏感文件访问（触发敏感文件告警/异常评分）
sudo cat /etc/shadow

# 5. 回放日志确认事件类型
kernelsentinel replay --file /tmp/ks-lab3/events_*.jsonl | grep -A2 "事件类型分布"
```

**预期输出**: 文件操作事件按 event_type 分类（10=open, 12=write, 13=unlink）；`/etc/shadow` 访问触发敏感文件告警（内核推理 +40 风险分，event_type=10）。

**思考题**:
1. VFS 抽象层如何统一 ext4/xfs/tmpfs 等不同文件系统？
2. `O_DIRECT` 和缓存 IO 在 eBPF 事件层面有什么差异？
3. 内核哨兵如何判断文件操作是否敏感？（提示：查看 `common.h` 的 `infer_sensitive_file` 与 `detector.rs` 的 `anomaly_score`）

**延伸阅读**: [crates/ks-ebpf/src/bpf/ks_probes_syscall.h](../crates/ks-ebpf/src/bpf/ks_probes_syscall.h)（`trace_sys_enter`/`trace_sys_exit`）、[crates/ks-ebpf/src/bpf/ks_probes_vfs.h](../crates/ks-ebpf/src/bpf/ks_probes_vfs.h)

---

### 实验四：网络协议栈追踪 (60 分钟)

**目标**: 理解 Linux 网络栈与网络连接审计

**实验步骤**:

```bash
# 1. 启动内核哨兵
sudo kernelsentinel start --rules-dir rules/ --log-dir /tmp/ks-lab4 --serve 8443 &

# 2. 发起 TCP 连接
curl https://example.com -o /dev/null

# 3. 实时告警流（watch；观察网络事件的 dport/saddr 字段）
kernelsentinel watch -s http://127.0.0.1:3000

# 4. DNS 查询
dig +short example.com

# 5. 查看网络流状态机（BPF map，注意 REST 需鉴权）
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/api/v1/maps/net_flows | python3 -m json.tool

# 6. 模拟可疑外连（触发高危端口告警）
nc -zv 127.0.0.1 4444 2>&1 || true
#    预期：内核推理给恶意端口 4444 +50 风险分 → 规则/异常评分告警
```

**预期输出**: net_flows map 记录 TCP 流状态（SYN→ESTABLISHED→CLOSED）；dport 4444 触发高优先级告警。

**思考题**:
1. TCP 三次握手在 eBPF 事件时间线上如何体现？
2. 内核哨兵的网络流状态机如何检测 C2 心跳？（提示：查看 `ks_probes_netflow.h`）
3. DNS 隧道检测为什么依赖"60 秒内 >50 次 DNS 查询"的频率维度？（提示：看 baseline 的 dns 固定阈值）

**延伸阅读**: [crates/ks-ebpf/src/bpf/ks_probes_netflow.h](../crates/ks-ebpf/src/bpf/ks_probes_netflow.h)

---

### 实验五：攻击检测实战 (90 分钟)

**目标**: 理解终端威胁检测原理与 MITRE ATT&CK 框架

**实验步骤**:

```bash
# 1. 启动内核哨兵（默认 monitor 只告警不杀；如需内核实杀：KS_ENFORCE=1 且等干跑期过）
sudo kernelsentinel start --rules-dir rules/ --log-dir /tmp/ks-lab5 --serve 8443 &

# 2. 运行模拟攻击脚本（scenarios/ 共 6 个）
sudo bash scenarios/sim_reverse_shell.sh
sudo bash scenarios/sim_ransomware.sh
sudo bash scenarios/sim_privilege_esc.sh

# 3. 实时看告警（终端内，severity 上色 + MITRE 标注）
kernelsentinel watch -s http://127.0.0.1:3000

# 4. 查看告警详情（REST）
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8443/api/v1/alerts?limit=50" | python3 -m json.tool

# 5. 查看关联告警（跨事件关联引擎输出）
curl -s -H "Authorization: Bearer $TOKEN" "http://127.0.0.1:8443/api/v1/correlations?limit=50" | python3 -m json.tool

# 6. 查看规则匹配详情
cat rules/reverse_shell.yml
cat rules/ransomware.yml
```

**预期输出**: 每种攻击触发对应规则告警（critical/high 级别），correlation API 展示攻击链式关联（置信度 % + MITRE），start 终端内实时打印攻击链（confidence>0.5，如 `bash -i → 外连`）。

**思考题**:
1. MITRE ATT&CK 框架的战术/技术分层是什么？
2. 反弹 Shell 攻击在内核层面留下了哪些痕迹？
3. 勒索软件的批量文件加密如何被频率异常检测捕捉？
4. 内核态阻断（`KS_ENFORCE=1` + `bpf_send_signal`）和用户态阻断（`/api/v1/block/:pid`）有什么区别？

**延伸阅读**: [docs/adr.md](adr.md) ADR-011（eBPF 内核态即时阻断）、ADR-004（双模检测）、ADR-008（攻击链还原）

---

### 实验六：自定义规则编写与自适应检测 (60 分钟)

**目标**: 理解检测工程与 EWMA 自适应学习

**实验步骤**:

```bash
# 1. 学习 YAML 规则语法（9 套 23 条内置规则）
cat rules/data_exfil.yml

# 2. 编写自定义规则 — 放到 rules 目录，start 的 5s 热加载自动生效（无需重启）
cat > rules/custom_rule.yml << 'EOF'
- name: "自定义：检测 wget 下载可执行文件"
  description: "检测通过 wget 下载 .sh/.py/.elf 文件"
  severity: medium
  conditions:
    - field: comm
      operator: equals
      value: "wget"
    - field: args
      operator: regex
      value: "\\.(sh|py|elf)$"
  alert_message: "检测到 wget 下载可执行文件"
  mitre_tactic: "TA0011"
  mitre_technique: "T1105"
EOF
# 等待 5 秒热加载扫描周期

# 3. 触发自定义规则
wget -q -O /tmp/test.sh https://example.com/test.sh || true

# 4. 观察基线偏离数据（六维 z-score）
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/api/v1/baselines | python3 -m json.tool

# 5. 标记误报并观察阈值调整（ML 阈值 ×1.1，100 正常样本后衰减）
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  http://127.0.0.1:8443/api/v1/alerts/<alert_id>/feedback \
  -d '{"is_false_positive": true}'

# 6. 验证规则语法（拼错字段立即报错）
echo '- name: "bad"
  conditions:
    - field: commmmm
      operator: equals
      value: "x"' > /tmp/bad.yml
cp /tmp/bad.yml rules/bad_rule.yml   # 热加载失败 → 保留旧规则，日志有报错
```

**预期输出**: 自定义规则触发 medium 级告警；baseline API 返回各进程 z-score；误报反馈后 ML 阈值提升 10%（可在 /api/v1/alerts 观察 severity 变化）。

**思考题**:
1. 规则引擎的 `Field` 枚举如何保证类型安全？（提示：查看 `ks-core/src/rule.rs`）
2. EWMA 模型的 α=0.3 意味着什么？为什么不用更大的值？
3. 冷启动期间（<5 个窗口）系统如何检测异常？（提示：固定阈值 fallback）
4. 误报反馈后阈值提升 10%，为什么需要 100 个正常样本后才衰减回原值？

**延伸阅读**: [docs/adr.md](adr.md) ADR-006（YAML 规则 + Field 枚举）、ADR-012（EWMA 自适应检测）、[docs/ml-design.md](ml-design.md)

---

## 3. 教学资源

### 3.1 课件大纲

```
第1讲: eBPF 技术概述 (30页 PPT)
  - 什么是 eBPF，为什么需要它
  - eBPF vs 内核模块 vs ptrace
  - eBPF 在安全领域的应用

第2讲: Linux 内核观测技术 (40页 PPT)
  - tracepoint, kprobe, uprobe, XDP 对比
  - BPF maps 和 ring buffer / perf buffer
  - 从内核到用户态的数据通道（5 tier 兼容矩阵）

第3讲: 终端威胁检测原理 (35页 PPT)
  - 基于行为的检测 vs 基于签名的检测
  - MITRE ATT&CK 框架
  - 内核哨兵架构详解（四层检测防线：内核推理 + 规则 + 关联 + 基线/ML）

第4讲: 自适应检测与阻断 (30页 PPT)
  - EWMA 在线学习模型
  - 基线偏离 vs 规则匹配
  - 内核态阻断（enforce 门控）vs 用户态阻断

第5讲: 实战与扩展 (30页 PPT)
  - 编写自定义规则
  - 性能调优（真实瓶颈：取事件环节）
  - 未来方向讨论
```

### 3.2 实验报告模板

见 [docs/lab-report-template.md](lab-report-template.md)

---

## 4. 评估方式

### 4.1 平时成绩 (40%)
- 6 个实验报告 (每个 5%)
- 课堂参与和讨论 (10%)

### 4.2 期末项目 (60%)
- 选题1: 编写自定义 eBPF 探针
- 选题2: 设计新的检测规则集
- 选题3: 性能优化与对比分析
- 选题4: 攻击模拟与检测评估

---

## 5. 与现有课程的关系

| 课程 | 结合点 | 对应实验 |
|------|--------|---------|
| 操作系统 | 系统调用、进程管理、文件系统、内存管理 | 实验一、二、三 |
| Linux 系统管理 | 内核配置、性能调优、安全加固 | 实验三、四 |
| 网络原理 | TCP/IP 协议栈、Socket 编程 | 实验四 |
| 信息安全导论 | 威胁模型、攻击检测、MITRE ATT&CK | 实验五 |
| 软件工程 | Rust 系统编程、模块化设计 | 实验六 |
| 机器学习 | EWMA 模型、异常检测、自适应学习 | 实验六 |

---

## 6. 安全注意事项

1. **实验环境隔离**: 所有攻击模拟脚本仅在专用实验 VM 中运行，禁止在生产环境执行
2. **root 权限**: eBPF 需要 root，实验结束后及时关闭内核哨兵（kernelsentinel stop）
3. **数据隐私**: 内核哨兵会捕获所有进程的系统调用与**命令行参数**（argv 5×64B，无密码脱敏），实验环境不应包含敏感业务
4. **阻断风险**: `KS_ENFORCE=1`（enforce）模式会调用 `bpf_send_signal(SIGKILL)` 终止进程——实验默认用 monitor（`KS_ENFORCE` 未设置），另注意干跑期（默认 120s）内不杀
5. **规则误报**: 自定义规则字段名拼错会导致热加载失败（保留旧规则），日志有 Err——先看日志确认加载成功再触发
6. **服务鉴权**: `--serve` 时必须显式 `--auth-token`（未指定时 REST 实际放行所有请求，与打印文案不符）
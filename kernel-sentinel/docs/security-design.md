# 内核哨兵 — 安全设计文档

> 2026-08-31 依据当前代码重写。早期版本中的"自身防护（hide_self/memfd/pinned）"、
> `kernelsentinel verify`、`kernelsentinel export --encrypt`、WebSocket Token 认证等**均未实现**，已删除或标注。
> 配套：[deployment.md](deployment.md)（systemd capability）、[api-design.md](api-design.md)（服务端安全）、
> [blocking-design.md](blocking-design.md)（阻断安全考量）。

## 1. 设计原则

### 1.1 最小权限原则（现状）

- eBPF 探针仅记录元数据（文件名/参数/IP+端口），不记录文件内容与网络载荷。
- 部署形态：**单二进制以 root 运行**（申报书约束"仅需 root"），通过 systemd CapabilityBoundingSet +
  AmbientCapabilities 限制为最小能力集，而非用户态/root 分离（服务本身需要读全系统：
  加载 eBPF、attach kprobe、读任意进程 /proc）。

systemd 单元实际能力集（deploy/kernelsentinel.service）：

```
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
LimitMEMLOCK=infinity
LimitNOFILE=65536
```

| Capability | 用途 |
|---|---|
| CAP_BPF | 创建/加载/管理 BPF 程序与 map（5.8+） |
| CAP_PERFMON | perf_event_open（perfbuf 路径，与 CAP_BPF 分离，5.8+ 引入） |
| CAP_SYS_ADMIN | 老内核（4.x/3.10）加载 BPF 的回退能力；**仍保留在能力集中**（不支持仅 CAP_BPF 的老内核） |
| CAP_NET_ADMIN | 网络探针 attach、读取 socket 信息 |
| CAP_SYS_PTRACE | 读取其他进程 /proc/<pid>/exe、/proc/<pid>/cmdline（解码 ptrace 事件时） |
| CAP_DAC_READ_SEARCH | 绕过文件权限检查读取任意路径（VFS 探针做规则匹配时需要） |

> 注意：这不是"CAP_BPF+CAP_PERFMON 替代 CAP_SYS_ADMIN"；3.10/4.x 需要 CAP_SYS_ADMIN 作为回退，
> systemd 单元明确包含它。

### 1.2 数据最小化（现状）

| 项 | 实际实现 |
|---|---|
| 文件名 | 截断至 256 字节（exec_event/file_event filename[256]） |
| 命令行参数 | 内核侧 `syscall_ctxs.exec_args[320]` = argv[0..4] 各 64B 槽位（5×64B）；用户态按槽位独立 cstr 截断后以空格拼接 |
| 网络连接 | 仅记录 IP+端口+direction，不记录载荷内容 |
| 取证轮转 | **按大小轮转**（默认 100MB）+ gzip 归档 + **30 天**保留清理（不是按日/7 天） |

### 1.3 防篡改设计（取证哈希链，已实现）

```
Record N-1                    Record N                     Record N+1
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ data: {...}      │    │ data: {...}      │    │ data: {...}      │
│ hash: H(N-1)     │◄───│ prev_hash: H(N-1)│◄───│ prev_hash: H(N)  │
│ prev_hash: H(N-2)│    │ hash: H(N)       │    │ hash: H(N+1)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

- 每条 JSONL 记录内容经 BTreeMap 确定性序列化后算 SHA-256；记录带 `prev_hash` + `hash`，GENESIS 为 64 个 '0'。
- 修改任意一条记录会导致所有后续哈希失效。
- 链完整性校验：`kernelsentinel replay --file <events>.jsonl` 第一步即 `verify_chain()`，
  输出 `{total_records, is_valid, broken_at}`（三机真机 23,579 条记录验证链完整）。
- ⚠️ 早期设计中的"链尾哈希定期上报独立存储（防批量删除）"**未实现**——目前链尾哈希仅在进程退出与
  replay 时可见；如需防批量删除，需自行扩展（如定时将链尾哈希外发）。

### 1.4 自身防护（当前实现 vs 设计缺口）

**已实现**：

- **阻断豁免**：内核侧 `protected_pids`（引擎自身 pid + 祖先链 ≤8 跳 + pid 1）与 `protected_comms`
  （11 个默认 comm + KS_PROTECTED_COMMS）使自身进程从风险分阻断中豁免；comm 豁免还校验 exe_path
  不在 /tmp、/dev/shm、/var/tmp（防伪装 comm 绕豁免）。
- **eBPF 程序附加即加载即生效**：探针随引擎进程生命周期；进程退出时探针自动 detach（3.10 无 bpf_link，只 close fd）。

**早期设计未实现（勿当现状引用）**：

- ~~hide_self 探针隐藏自身进程~~：不存在。
- ~~memfd_create 加载 eBPF 无磁盘残留~~：实际是 ks_loader 静态二进制内嵌 + release_to_temp 落盘执行。
- ~~BPF 程序 pinned 防删除~~：无 pin 逻辑。
- ~~引擎进程异常退出时探针保持运行~~：探针随进程 detach。

### 1.5 资源限制（实测）

| 资源 | 实际 |
|---|---|
| events ringbuf | 16MB（modern tier）；另有 tree/freq/flow/filter_events 各 1MB；legacy/ancient 走 perf_event_array(256) |
| 聚合缓冲 | 用户态 VecDeque（default 10,000 条环形） |
| 取证日志 | 100MB/文件轮转 + gzip |
| CPU | 单核水平（真机 5.15 空载 ~833 events/s ≈ 0% CPU；open 洪水 1839 events/s ≈ 54% 单核） |
| 内存 | 三机真机 RSS 52-94MB；本地修复泄漏后 loadgen 下 3.9MB（2026-08 修复 ml_detector/baseline 表膨胀 OOM，历史峰值 1.4GB） |

---

## 2. 威胁模型

### 2.1 攻击类型与检测路径（按实际 16 探针重画）

| 攻击类型 | 检测方法 | 载体 |
|---|---|---|
| 反弹 Shell | `bash -i`、/dev/tcp、nc -e 等模式评分 + 规则 | detector 异常评分 / reverse_shell.yml + 关联规则 |
| 勒索软件 | 批量写+删模式、.encrypted/.locked 等后缀评分 | vfs_write、vfs_unlink + 规则/关联/基线六维 |
| 数据窃取 | 敏感文件访问 + 外连组合 | vfs_open/sys_exit、tcp_v4/v6_connect + 关联规则 |
| 提权 | chmod +s/4755、LD_PRELOAD、ptrace、sudo | sys_exit(101/62)、规则（mitre T1548/T1574.006） |
| 进程注入 | ptrace/kill 系统调用 | sys_exit（ptrace +35 分、kill +20 分） |
| 持久化 | cron/systemd 配置、authorized_keys 写入 | vfs_write（用户态规则路径匹配，探针无路径过滤） |
| Rootkit | 内核模块加载 | kprobe/do_init_module（81）+ sys_exit 313 finit_module（双发射） |
| DNS 隧道 | dport=53 事件 + 频次/大包 | kprobe/udp_sendmsg（24 类型）+ freq/baseline dns 维度 |
| C2 通信 | 恶意端口/高位端口外连、同连接重复、>100MB 外送 | tcp_v4/v6_connect、tcp_sendmsg（DATA_EXFIL 标志） |
| 端口扫描 | 连接目标分布 | netflow port_scan_map |
| 容器逃逸 | commit_creds | kprobe/commit_creds（80）；⚠️ ns_inum/cap_eff 字段仍为 0 占位 |

### 2.2 已知规避手段及应对

| 规避手段 | 应对 |
|---|---|
| 修改系统调用表 | kprobe 与 tracepoint 双层覆盖（raw_syscalls + 具体函数 kprobe） |
| 卸载 eBPF 程序 | 探测 `security_bpf_prog_free`（82）自身防护；无 pin 抗删除能力 |
| 伪造进程名 (comm) | protected_comms 豁免校验 exe_path（内核侧）；用户态规则可交叉 /proc |
| 分段执行命令 | 攻击链还原（300s 窗口）+ 跨事件关联 |
| 内核模块注入 | kprobe/do_init_module + sys_exit 313（finit_module）双通道 |
| 时间差攻击 | 长期行为基线（60s 窗口 × 20 快照，z-score）+ EWMA 趋势检测 |
| 高频低危淹没 | 内核智能过滤（风险分/异常标志优先放行，常规行为降频） |

---

## 3. 权限模型

### 3.1 部署模型（实际）

```
root (systemd, 能力受限) ──► 加载 eBPF ──► 消费 ringbuf ──► 检测 ──► 写取证日志
   └── CapabilityBoundingSet 6 项（见 §1.1）；LimitMEMLOCK=infinity
```

单二进制全权限运行，无 ks-engine/ks-server 用户分离（早期设计中的"三用户分离"未实现，且与申报书
"仅需 root"约束冲突）。真正的边界是内核 eBPF verifier + systemd 能力集。

### 3.2 文件位置

| 路径 | 说明 |
|---|---|
| `/usr/local/bin/kernelsentinel` | 安装后的二进制（deploy/install.sh） |
| `/etc/kernelsentinel/rules/` | 规则目录（systemd ExecStart `--rules-dir /etc/kernelsentinel/rules`） |
| `/var/log/kernelsentinel/` | 取证日志 + 审计日志 |
| `/tmp/ks-status.json` | 运行时状态文件（status/stop 用） |

> 无 setcap 方案——能力由 systemd AmbientCapabilities 注入（非 systemd 场景直接 sudo 运行）。

---

## 4. 数据安全

### 4.1 敏感数据最小化（已实现）

- 文件内容不记录（只记路径+操作类型+字节数）。
- 网络载荷不记录（只记 IP+端口+proto）。
- ⚠️ 命令行参数**未做密码/Token 正则脱敏**（早期设计的 `password=*`/`token=*` 脱敏未实现）——
  取证日志会完整记录 argv（5×64B 槽位）。如需脱敏，需在 forensic 写路径或解码层自行扩展。

### 4.2 日志加密

- **未实现**：`kernelsentinel export --encrypt` 命令不存在。目前靠文件系统权限 + 可选 dm-crypt 分区。
- 审计日志本身为 JSONL 明文。

### 4.3 传输安全（现状）

- Web API 默认仅监听 127.0.0.1（server.rs 硬编码）；远程访问需 SSH 隧道或反向代理。
- 可选 TLS/mTLS（`--tls-cert/--tls-key/--tls-client-ca`，rustls 0.23）。
- ⚠️ WebSocket `/ws/alerts` **免鉴权**（auth 白名单含 /ws 前缀）——早期文档的"WS 用 Token 认证"未实现；
  监听 127.0.0.1 + 防火墙是本机内 WS 的主要防线。
- REST 除白名单外均需 Bearer token（但注意 §api-design §3 的 token=None 放行坑）。

---

## 5. 已知安全缺口（诚实清单）

| # | 缺口 | 说明 |
|---|---|---|
| 1 | token=None 放行所有请求 | auth.rs 中未配置 token 时直接放行，与 CLI 文案矛盾；部署必须显式 --auth-token |
| 2 | WS 免鉴权无心跳 | /ws/alerts 在白名单内 |
| 3 | 审计 IP 可伪造 | 信任 x-forwarded-for |
| 4 | CORS 全放行 | CorsLayer::permissive() |
| 5 | 无自身隐身/pin | hide_self/memfd/pinned 均未实现 |
| 6 | 无链尾外报 | 哈希链防篡改在本地可验，防批量删除需自行扩展 |
| 7 | 容器逃逸字段占位 | commit_creds 事件源/目标 ns_inum、cap_eff 全 0 |
| 8 | 取证日志可能含敏感 argv | 无密码/token 脱敏 |
| 9 | 规则与权限无管理面 | 规则只能本地改文件 + 热加载；REST 无规则 CRUD |
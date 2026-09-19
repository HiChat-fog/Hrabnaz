# 内核哨兵 — 部署架构设计

> 本文档覆盖单机/分布式部署拓扑、systemd 部署、3.10 ECS 部署、Docker 容器化、配置管理、升级、监控集成与安全加固。
> Phase E 新增 systemd + install.sh 部署方式与 3.10 ECS sidecar 路径，详见 [phase-e-summary.md](phase-e-summary.md)。
> Phase F 新增 Docker 容器化部署（§2.6）、Prometheus + Grafana 监控（§6）、mTLS + 鉴权 + 审计 + 速率限制安全加固（§7）。
> 注：ks-frontend / nginx 前端构建与挂载已移除（申报书不涉及Web前端），原 §2.3 前端构建章节已删除，历史痕迹见 git log。

## 1. 部署拓扑

### 1.1 单机部署 (开发/演示)
```
┌─────────────────────────────────────────┐
│              Linux 主机                   │
│  ┌─────────────────────────────────────┐ │
│  │         kernelsentinel (单二进制)     │ │
│  │  ┌─────────┐  ┌─────────┐           │ │
│  │  │ CLI 管理 │  │ 引擎核心 │           │ │
│  │  │ start/   │  │ loader  │           │ │
│  │  │ stop/    │  │ detect  │           │ │
│  │  │ status   │  │ forensic│           │ │
│  │  └─────────┘  └─────────┘           │ │
│  └─────────────────────────────────────┘ │
│  ┌─────────────────────────────────────┐ │
│  │          Linux Kernel               │ │
│  │  ┌──────┐ ┌──────┐ ┌──────┐        │ │
│  │  │eBPF  │ │eBPF  │ │eBPF  │  ...   │ │
│  │  │probe1│ │probe2│ │probe3│        │ │
│  │  └──────┘ └──────┘ └──────┘        │ │
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### 1.2 分布式部署 (生产)
```
┌──────────┐  ┌──────────┐  ┌──────────┐
│  Agent 1 │  │  Agent 2 │  │  Agent N │
│ (node1)  │  │ (node2)  │  │ (nodeN)  │
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │              │              │
     │   syslog / fluentd / OTLP   │
     │              │              │
     └──────────────┼──────────────┘
                    │
             ┌──────▼──────┐
             │   SIEM 中心  │
             │ (Wazuh/ELK) │
             └─────────────┘
```

## 2. 安装方式

### 2.1 systemd 部署 (生产推荐，Phase E3.2)

Phase E 提供完整的 systemd 部署方案，包含 `deploy/install.sh` / `deploy/uninstall.sh` / `deploy/kernelsentinel.service`。

```bash
cd kernel-sentinel
cargo build --release
sudo ./deploy/install.sh
sudo systemctl start kernelsentinel
sudo systemctl status kernelsentinel
# 访问 http://127.0.0.1:8443/
```

`install.sh` 自动完成：
1. 编译 release 二进制并安装到 `/usr/local/bin/kernelsentinel`
2. 安装规则到 `/etc/kernelsentinel/rules/`
3. 安装 systemd unit 到 `/etc/systemd/system/kernelsentinel.service`
4. 创建日志目录 `/var/log/kernelsentinel/`
5. `systemctl daemon-reload && systemctl enable kernelsentinel`

systemd unit（`deploy/kernelsentinel.service`）关键配置：

```ini
[Service]
Type=notify
ExecStart=/usr/local/bin/kernelsentinel start --rules /etc/kernelsentinel/rules --log-dir /var/log/kernelsentinel --sd-notify
Restart=on-failure
User=root
Group=root

# eBPF 需要的能力
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_NET_ADMIN CAP_SYS_PTRACE CAP_DAC_READ_SEARCH

# 解除内存锁限制（eBPF map 需要）
LimitMEMLOCK=infinity
LimitNOFILE=65536

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=kernelsentinel
```

`Type=notify` 配合 ks-cli `--sd-notify` flag：ks-cli 在所有探针 attach 完成 + 规则加载完成 + 引擎初始化完成后调用 `sd_notify(0, "READY=1")`，systemd 收到通知后才标记服务为 active。这样 `systemctl start` 在真正就绪前不会返回成功，避免 health check 误判。

CapabilityBoundingSet 设计理由（为什么需要 `CAP_SYS_PTRACE` / `CAP_DAC_READ_SEARCH`）见 [phase-e-summary.md](phase-e-summary.md) 第 2.5 节。

卸载：

```bash
sudo ./deploy/uninstall.sh
```

日志查看：

```bash
journalctl -u kernelsentinel -f
curl http://127.0.0.1:8443/api/v1/health
```

### 2.2 3.10 ECS 部署 (Phase E2)

CentOS 7 / Aliyun ECS 3.10.0-1160 stock 内核无 BTF，aya 无法直接加载。KernelSentinel 提供 C loader sidecar 路径（`ks_loader --stream`），由 `tier_detect` 自动选择。

```bash
# 1. 在 ECS 上编译 ks_loader (需要 libelf-devel)
sudo yum install -y libelf-devel
gcc -std=c99 -O2 -o ks_loader crates/ks-ebpf/scripts/ks_loader.c -lelf

# 2. 编译 kernelsentinel (Rust 部分)
cargo build --release

# 3. 启动 — tier_detect 会自动检测 3.10 + 无 BTF，
#    优先走 CLoaderSource 路径 (fork+exec ks_loader --stream <obj>)，
#    aya 加载路径降级为 fallback。
sudo ./target/release/kernelsentinel start
```

帧协议（`ks_loader --stream` 输出格式）：

```
[u32 LE length][u8[length] payload]
length=0 表示心跳帧（每 30s 一次），Rust 端忽略。
日志/错误 → stderr；事件数据 → stdout。
```

详细协议设计与取舍见 [cloader-protocol.md](cloader-protocol.md) 与 [phase-e-summary.md](phase-e-summary.md) 第 2.2 节。

> 注：`ks_loader` 静态二进制由 `ks-engine/build.rs` 预编译并**内嵌进 Rust 二进制**（`include_bytes!`），
> 运行时优先用 `KS_LOADER_PATH` 指定的外部二进制，否则解压内嵌版本到临时目录执行。

### 2.3 交付包安装（`scripts/pack.sh` 产物）

```bash
# 本机打包
bash scripts/pack.sh        # 输出 dist/kernelsentinel-0.1.0-x86_64.tar.gz（musl 单二进制 + rules + systemd unit + install.sh，约 13MB）

# 目标机安装
tar xzf kernelsentinel-0.1.0-x86_64.tar.gz
sudo ./install.sh
# install.sh 自动完成:
# 1. 复制二进制到 /usr/local/bin/kernelsentinel
# 2. 安装规则到 /etc/kernelsentinel/rules/
# 3. 安装 systemd unit 到 /etc/systemd/system/kernelsentinel.service
# 4. 创建日志目录 /var/log/kernelsentinel/
# 5. systemctl daemon-reload && enable
```

> 项目是本地 git 仓库（不推 GitHub），预编译下载安装从未提供——统一用 pack.sh 产物 + install.sh。

### 2.4 源码编译

```bash
cd kernel-sentinel
cargo build --release          # 或 bash scripts/build-musl.sh 出静态单二进制
sudo ./target/release/kernelsentinel start --rules-dir rules/ --log-dir /var/log/ks
```

⚠️ 本项目**不使用 setcap 方式**分配 capability——systemd 部署由 `AmbientCapabilities` 注入
（§2.1），非 systemd 场景以 root 直接运行即可（eBPF 加载要求 root，见 HANDOFF §7 已知坑 1）。

### 2.5 Docker 容器化部署 (Phase F2)

Phase F2 提供完整的多阶段 Docker 镜像 + docker-compose 编排，适用于容器化生产环境。

**镜像构建**（多阶段：`rust:1.82-bookworm` builder + `debian:bookworm-slim` runtime）：

```bash
cd kernel-sentinel
docker build -t kernelsentinel:latest .
```

**docker-compose 启动**（推荐）：

```bash
# 1. (可选) 设置 API 鉴权 token — 放入 .env 文件
echo "KS_AUTH_TOKEN=$(openssl rand -hex 32)" > .env

# 2. 启动 ks-server
docker compose up -d

# 3. (可选) 启动监控栈
docker compose --profile metrics up -d
```

> 注：原"构建前端静态资源"步骤与 `nginx` 服务已移除（申报书不涉及Web前端），历史痕迹见 git log。

**服务说明**（`docker-compose.yml`）：

| 服务 | 镜像 | 端口 | 说明 |
|------|------|------|------|
| `ks-server` | kernelsentinel:latest | 8080 | eBPF 探针 + REST API + WebSocket（privileged 模式） |
| `prometheus` (可选) | prom/prometheus | 9090 | 指标采集（`--profile metrics` 启用） |

> 注：`nginx` 前端反代服务已移除（申报书不涉及Web前端），历史痕迹见 git log。

**关键 volume 挂载**：
- `/sys/fs/bpf:/sys/fs/bpf` — eBPF map 持久化（必需）
- `/proc:/proc` — 进程信息访问
- `/lib/modules:/lib/modules:ro` — 内核符号（只读）
- `./rules:/etc/kernelsentinel/rules:ro` — 规则目录（只读）

**entrypoint 前置检查**（`deploy/docker-entrypoint.sh`）：
1. 检查 `/sys/fs/bpf` 是否已挂载（type bpf）
2. 检查 CAP_BPF capability
3. `exec kernelsentinel start --serve 8080 --rules-dir /etc/kernelsentinel/rules`
4. trap SIGTERM 优雅退出

> 注：eBPF 加载需要 `privileged: true`（或等效的 `cap_add` 列表）。部分老内核（3.10）即使添加 capability 也需要 privileged。容器内无法端到端验证 eBPF 加载时，建议用 systemd 部署方式（2.1 节）。

## 3. 系统要求

### 3.1 内核版本
| 功能 | 最低内核 | 推荐内核 |
|------|----------|----------|
| 基础 eBPF (tracepoint/kprobe) | 5.4 | 5.15+ |
| BPF ring buffer | 5.8 | 5.15+ |
| BTF (无需 kernel headers) | 5.4+ (需编译时开启) | 5.15+ |
| XDP 网络探针 | 4.18 | 5.15+ |
| CAP_PERFMON 分离 | 5.8 | 5.15+ |

### 3.2 内核编译选项
```
CONFIG_DEBUG_INFO_BTF=y       # BTF 支持（推荐）
CONFIG_BPF=y                   # BPF 子系统
CONFIG_BPF_SYSCALL=y           # bpf() 系统调用
CONFIG_BPF_JIT=y               # BPF JIT 编译
CONFIG_HAVE_EBPF_JIT=y         # eBPF JIT 支持
CONFIG_BPF_EVENTS=y            # BPF 事件支持
CONFIG_KPROBE_EVENTS=y         # kprobe 支持
CONFIG_UPROBE_EVENTS=y         # uprobe 支持 (可选)
CONFIG_FTRACE_SYSCALLS=y       # syscall tracepoint
CONFIG_FUNCTION_TRACER=y       # 函数追踪
```

### 3.3 硬件要求
| 资源 | 最低 | 推荐 |
|------|------|------|
| CPU | 1 核 | 2+ 核 |
| 内存 | 256 MB 可用 | 512 MB+ 可用 |
| 磁盘 | 10 GB (日志) | 50 GB+ (日志) |
| 架构 | x86_64 | x86_64 / ARM64 |

## 4. 配置管理

### 4.1 配置来源（以环境变量 + CLI 为准）

⚠️ 旧文档的 `/etc/ks/config.yml` YAML 配置文件**未接入主程序**：`Config::load_from_file` 仅被测试使用，
`kernelsentinel start` 实际用 `Config::default()` + `KS_*` 环境变量覆盖 + CLI 参数直覆盖
（`--rules-dir` / `--log-dir` / `--serve`）。下方 YAML 结构对应 config.rs 的 5 个子配置，
字段名用于构造环境变量名（`KS_ENGINE_BUFFER_SIZE`、`KS_FORENSIC_LOG_DIR` 等 19 个），配置项本身请走环境变量：

```bash
export KS_ENGINE_BUFFER_SIZE=10000
export KS_DETECTION_ANOMALY_THRESHOLD=0.7
export KS_FORENSIC_LOG_DIR=/var/log/ks/
export KS_FORENSIC_MAX_LOG_SIZE_MB=100
export KS_FORENSIC_RETENTION_DAYS=30
export KS_NETWORK_SERVE_PORT=3000
export KS_NETWORK_BIND_ADDRESS=127.0.0.1
export KS_PERFORMANCE_MEMORY_LIMIT_MB=128
# enforce 阻断相关（loader.rs 直接读取，不在 config.rs）
export KS_ENFORCE=1                    # 开启 enforce（默认 monitor）
export KS_ENFORCE_WARMUP_SEC=120       # 干跑期
export KS_ENFORCE_KILL_THRESHOLD=70    # kill 阈值
export KS_PROTECTED_COMMS=nginx,redis  # 追加保护 comm
```

对应 config.rs 结构（字段名参考，非 YAML 文件）：

```yaml
# config.rs 5 个子配置（用于理解环境变量命名）
engine:      { buffer_size: 10000, ring_buffer_size_kb: 256, batch_size: 64 }   # ring/batch 无消费点
detection:   { rules_dir: /etc/ks/rules/, anomaly_threshold: 0.7, kernel_inference: true,
               block_enabled: false, block_ttl_secs: 300, block_severity_threshold: critical }
forensic:    { log_dir: /var/log/ks/, max_log_size_mb: 100, retention_days: 30, hash_chain: true }
network:     { serve_port: 3000, bind_address: 127.0.0.1, ws_enabled: true }
performance: { cpu_affinity: auto, max_cpu_percent: 5, memory_limit_mb: 128 }
```

⚠️ `ring_buffer_size_kb` / `batch_size` / `performance.*` 在引擎主循环中**无消费点**
（ringbuf 大小由 eBPF 编译期常量决定：events 16MB，其余 1MB）。

### 4.2 规则热更新

规则**没有独立的 reload 命令**（`kernelsentinel reload` 不存在）。规则热加载内置于 start 主循环：
每 5 秒扫描 `--rules-dir` 的 mtime，有变更则原子替换检测引擎（加载失败保留旧规则）。无需任何操作。
（server 的 `POST /api/v1/reload` 是 stub，返回 202 但无实际操作。）

## 5. 升级策略

### 5.1 升级方式

⚠️ 旧文档的"新 pin 路径/新旧探针并行 60s"与 `kernelsentinel rollback` 命令**均不存在**
（探针不 pin 到 /sys/fs/bpf，随进程 detach；无回滚子命令）。实际升级流程：

```
1. 构建/获取新版本二进制（pack.sh 交付包或 cargo build --release）
2. systemctl stop kernelsentinel       # 探针随进程卸载
3. 替换 /usr/local/bin/kernelsentinel
4. systemctl start kernelsentinel      # 恢复运行（哈希链从最后含 seq 的行续链）
5. 验证：kernelsentinel status / replay --file（链完整性）
```

版本不兼容回退同理：停服务 → 换回旧二进制 → 启动（取证日志向后兼容，旧版本可继续读）。

### 5.2 升级注意事项

- 升级期间取证日志文件如已轮转（100MB），哈希链会从新文件续链（recover_chain_state 读取最后一条含 seq 的记录）。
- 规则目录独立于二进制（/etc/kernelsentinel/rules/），升级二进制不影响规则。
- eBPF 5 tier 字节码内嵌进二进制，升级即新探针（无需单独部署 .o）。

## 6. 监控集成 (Phase F3)

### 6.1 Prometheus 指标

ks-server 通过 `/metrics` 端点暴露 6 个 Prometheus 指标（Content-Type: `text/plain; version=0.0.4`），由 `crates/ks-server/src/metrics.rs` 定义并注册到全局 Registry。

```
# 事件指标（Counter, labels: event_type）
ks_events_total{event_type="1"} 12345        # execve
ks_events_total{event_type="2"} 67890        # openat

# 告警指标（Counter, labels: severity）
ks_alerts_total{severity="critical"} 3
ks_alerts_total{severity="high"} 12
ks_alerts_total{severity="medium"} 47

# eBPF map 条目数（Gauge, labels: map_name）
ks_map_entries{map_name="risk_scores"} 29
ks_map_entries{map_name="freq_counters"} 76

# 事件处理延迟（Histogram, labels: event_type，单位：秒）
ks_event_processing_seconds_bucket{event_type="1",le="0.001"} 12300
ks_event_processing_seconds_sum{event_type="1"} 4.56
ks_event_processing_seconds_count{event_type="1"} 12345

# tier 激活状态（Gauge, labels: tier, 0=未激活 / 1=激活）
ks_tier_status{tier="modern"} 1
ks_tier_status{tier="legacy"} 0
ks_tier_status{tier="ancient"} 0

# ringbuf 丢失事件累计数（Counter, 无 label）
ks_ringbuf_lost_total 0
```

抓取配置（`deploy/prometheus.yml`）：

```yaml
global:
  scrape_interval: 15s
scrape_configs:
  - job_name: 'kernelsentinel'
    static_configs:
      - targets: ['ks-server:8080']
    metrics_path: /metrics
```

> `/metrics` 端点免鉴权（白名单路径），可被 Prometheus 直接抓取。生产环境建议通过网络层（mTLS / 防火墙）保护。

### 6.2 Grafana 可视化

预置 dashboard 位于 `deploy/grafana/kernelsentinel-dashboard.json`（8 个 panel）：

| Panel | 指标 | 说明 |
|-------|------|------|
| 事件速率 | `rate(ks_events_total[1m])` | 按事件类型的每秒事件数 |
| 告警速率 | `rate(ks_alerts_total[5m])` | 按严重级别的每分钟告警数 |
| map 大小 | `ks_map_entries` | 5 个共享 map 的实时条目数 |
| 处理延迟 P50/P99 | `histogram_quantile()` | 事件处理延迟分位数 |
| tier 状态 | `ks_tier_status` | 当前激活的 tier |
| ringbuf 丢失 | `rate(ks_ringbuf_lost_total[1m])` | 丢失事件速率（应接近 0） |
| Top 10 事件类型 | `topk(10, ks_events_total)` | 高频事件类型排行 |
| Top 10 告警规则 | `topk(10, ks_alerts_total)` | 高频告警规则排行 |

导入方式：Grafana → Dashboards → Import → 上传 `kernelsentinel-dashboard.json`。

### 6.3 健康检查
```bash
# 健康检查（免鉴权白名单）
curl http://127.0.0.1:8443/api/v1/health
# {"status":"ok","uptime_secs":0}

# 版本信息（需鉴权：/api/v1/version 不在白名单，注意与免鉴权的 /version 区分——后者无路由）
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8443/api/v1/version
# {"version":"0.1.0","component":"ks-server"}
```
> 端口注意：systemd 部署默认 8443；Docker/compose 映射 8080；CLI watch/baseline/correlation 默认请求 3000——按实际部署端口选择。

## 7. 安全加固 (Phase F4)

Phase F4 提供 4 层安全加固：mTLS 双向认证 + Bearer token 鉴权 + 审计日志 + 速率限制。所有加固均可通过 CLI flag 独立开关，默认关闭（本地调试友好）。

### 7.1 API 鉴权 (Bearer Token)

通过 `Authorization: Bearer <token>` header 校验，token 比对使用固定时间比较（防时序侧信道）。

**白名单路径**（免鉴权）：
- `/health`、`/api/v1/health` — k8s/systemd 探针
- `/version` — 版本信息
- `/metrics` — Prometheus 抓取
- `/ws/*` — WebSocket 升级（前缀匹配，覆盖 `/ws/alerts` 等子路径）

**启用方式**：

```bash
# 方式 1: CLI flag
kernelsentinel start --serve 8443 --auth-token "$(openssl rand -hex 32)"

# 方式 2: 环境变量（Docker / systemd）
export KS_AUTH_TOKEN=my-secret-token
kernelsentinel start --serve 8443

# 关闭鉴权（本地调试）
kernelsentinel start --serve 8443 --no-auth
```

**鉴权失败响应**：`401 + {"error":"missing or invalid token"}`

**⚠️ 安全注意**：若 `--auth-token` 与 `KS_AUTH_TOKEN` 都未设置，鉴权中间件会**放行所有请求**
（token=None 直接通过），与 CLI 打印的"ENABLED"文案相反——生产部署必须显式设置 token。

### 7.2 TLS / mTLS 双向认证

基于 `rustls 0.23` + `ring` crypto provider（纯 Rust，无 cmake/cc 依赖）。

**单向 TLS**（服务器出示证书）：

```bash
kernelsentinel start --serve 8443 \
  --tls-cert /etc/kernelsentinel/certs/server.crt \
  --tls-key  /etc/kernelsentinel/certs/server.key
```

**mTLS 双向认证**（客户端必须出示证书）：

```bash
kernelsentinel start --serve 8443 \
  --tls-cert /etc/kernelsentinel/certs/server.crt \
  --tls-key  /etc/kernelsentinel/certs/server.key \
  --tls-client-ca /etc/kernelsentinel/certs/client-ca.crt
```

**生成自签名证书（测试用）**：

```bash
mkdir -p /etc/kernelsentinel/certs && cd $_

# 1. 生成 CA
openssl genrsa -out ca.key 4096
openssl req -x509 -new -key ca.key -days 3650 -subj "/CN=KS-CA" -out ca.crt

# 2. 生成服务器证书
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=localhost" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out server.crt

# 3. 生成客户端证书（mTLS 用）
openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=ks-client" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out client.crt
```

**ALPN 协商**：HTTP/2 优先，回退 HTTP/1.1。

### 7.3 审计日志

记录所有 REST API 调用，JSON Lines 格式，**同步逐行追加写**（AuditWriter，每行 flush）。

```bash
kernelsentinel start --serve 8443 --audit-log /var/log/kernelsentinel/audit.log
```

**日志字段**（每行一个 JSON 对象）：

| 字段 | 说明 |
|------|------|
| `timestamp` | RFC3339 时间戳 |
| `client_ip` | 客户端 IP |
| `token_id` | token SHA-256 前 8 位（用于关联调用方，不泄露原 token） |
| `method` | HTTP 方法 |
| `path` | 请求路径 |
| `status` | HTTP 状态码 |
| `latency_ms` | 处理延迟（毫秒） |

### 7.4 速率限制

基于 `tower-governor`，按客户端 IP 限流，默认 100 req/min/IP。

```bash
kernelsentinel start --serve 8443 --rate-limit 100
```

超限响应：`429 Too Many Requests` + `X-RateLimit-Reset` header。

### 7.5 中间件执行顺序

axum 中间件采用 LIFO（后入先出）顺序，实际执行顺序：

```
请求 → rate_limit (最外层) → auth → audit → 业务路由
```

- **rate_limit** 最先执行：在鉴权前拦截洪水请求，避免无谓的 token 校验开销
- **auth** 在 audit 前：审计日志记录已通过鉴权的调用
- **audit** 最内层：记录最终到达业务路由的请求

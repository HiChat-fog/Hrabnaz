# ks-server API 设计

> **状态**：已实现（2026-08-31 依据 `crates/ks-server/src/` 源码重写）
>
> 本文档描述 ks-server 的**实际** REST API、WebSocket 协议与安全机制（19 条路由，从 routes.rs 实测）。
> ⚠️ 早期设计稿中的 JWT 认证、SQLite/PostgreSQL 持久化、规则 CRUD、事件查询等**未实现**，
> 作为"未来工作"保留在 §9，实施前勿当现状引用。

---

## 1. 架构与运行方式

ks-server 有两种启动方式，代码完全相同，只是入口不同：

| 方式 | 入口 | 端口 | 说明 |
|------|------|------|------|
| 内嵌（推荐） | `kernelsentinel start --serve <port>` | 用户指定 | 与检测引擎同进程，共享 ServerState（可挂 map_reader / tier / BlockManager / AdaptiveDetector） |
| 独立二进制 | `ks-server-bin` | `KS_SERVER_PORT` env（默认 **8443**） | 无引擎，独立运行，默认 insecure |

- 绑定地址**硬编码 127.0.0.1**（server.rs），远程访问需 SSH 隧道或反向代理。
- 中间件执行顺序（axum `Router::layer()` 后入先出）：**rate_limit → auth → audit → 业务路由**。

技术选型（实际）：

| 组件 | 选择 | 说明 |
|------|------|------|
| Web 框架 | axum 0.7 + tokio | 异步、tower 生态 |
| WebSocket | axum::extract::ws | 服务器单向推送 |
| 认证 | Bearer 静态 token + 路径白名单 | 无 JWT、无角色、无登录端点 |
| TLS/mTLS | rustls 0.23 + ring provider | axum-server `tls-rustls-no-provider` |
| 速率限制 | tower-governor 0.4 + governor 0.6 | GCRA，每 IP 每分钟 limit 次 |
| 审计 | 自研 AuditWriter | JSONL 逐行追加 |
| 指标 | prometheus 0.13 | 全局 Registry + TextEncoder |

---

## 2. REST API — 实际端点（19 个 route，routes.rs 实测）

### 2.1 告警管理

| 方法/路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /api/v1/alerts?limit=100` | ✅ | 告警列表（**内存环形存储**，MAX_ALERTS=10000 FIFO），按时间倒序 take limit |
| `GET /api/v1/alerts/:id` | ✅ | 告警详情（Uuid）；404 未找到 |
| `POST /api/v1/alerts/:id/ack` | ✅ | 状态 → Investigating；404 |
| `POST /api/v1/alerts/:id/resolve` | ✅ | 状态 → Resolved；404 |
| `POST /api/v1/alerts/:id/feedback` | ✅ | body `{is_false_positive: bool, comment?}`：更新 feedback、状态 → FalsePositive，并调 `ml_detector.false_feedback(pid, fp)`；404 |

### 2.2 系统状态

| 方法/路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /api/v1/stats` | ✅ | `{total, by_severity{high,medium,low}, by_status{new,investigating,resolved}, map_stats[]}`；high 合并 Critical+High；有 map_reader 时含真实 BPF map 占用 |
| `GET /api/v1/health` | 免 | `{status:"ok", uptime_secs}`；⚠️ uptime_secs 硬编码 0 |
| `GET /api/v1/tier` | ✅ | 纯文本 `tier: {label}`（如 modern / ancient_nobtf） |
| `POST /api/v1/reload` | ✅ | ⚠️ **stub**——返回 202 ACCEPTED 但无实际操作 |
| `GET /api/v1/version` | ✅ | `{version: CARGO_PKG_VERSION, component:"ks-server"}` |

### 2.3 检测数据

| 方法/路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /api/v1/baselines` | ✅ | 六维行为基线列表 `Vec<BehaviorBaseline>`（start.rs 每 50 事件同步进 state） |
| `GET /api/v1/correlations?limit=100` | ✅ | 关联告警列表（MAX_CORR_ALERTS=1000 环形） |

### 2.4 用户态阻断

| 方法/路径 | 鉴权 | 说明 |
|---|---|---|
| `POST /api/v1/block/:pid?ttl=&reason=&trigger=` | ✅ | 用户态 BlockManager 阻断；`reason` 默认 5（Manual）、`trigger` 默认 "rest_api"；`block_enabled=false` 时 403 FORBIDDEN |
| `DELETE /api/v1/block/:pid` | ✅ | 解除阻断；404 未阻断 |
| `GET /api/v1/blocked` | ✅ | `Vec<BlockedPid>` 阻断列表 |

> 注意：这些端点操作的是**用户态纯内存表**（BlockManager），**不写内核 block_decisions map**——
> 内核态 SIGKILL 阻断由 `KS_ENFORCE=1` 独立驱动，两者是两条平行通道（见 blocking-design.md）。

### 2.5 BPF Map 查询

| 方法/路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /api/v1/maps` | ✅ | `{maps: [...]}` map 列表；无 map_reader 时 503 |
| `GET /api/v1/maps/:name` | ✅ | 白名单 **6** 个：`process_tree`/`net_flows`/`freq_counters`/`filter_stats`/`risk_scores`/`block_decisions`；返回 `{map, entry_count, entries}`；不支持的名字 400；无 reader 503 |

### 2.6 WebSocket 与指标

| 方法/路径 | 鉴权 | 说明 |
|---|---|---|
| `GET /ws/alerts` | 免（白名单 /ws 前缀） | WebSocket：每条新告警服务器推送 JSON（完整 Alert 对象），无心跳、无订阅消息、断开即退出 |
| `GET /metrics` | 免 | Prometheus 文本（见 §7） |

> 严格说 2.6 的 /ws 与 /metrics 不算 REST；REST+WS+metrics 共 19 条 `.route()`。

---

## 3. 认证（auth.rs）

**实现**：Bearer 静态 token + 路径白名单 + 固定时间比较（constant_time_eq，长度异或+逐字节）。

- 配置：CLI `--auth-token <TOKEN>` 或环境变量 `KS_AUTH_TOKEN`（start 的 SecurityArgs）。
- 白名单（免鉴权，query 剥离后精确匹配）：`/health`、`/api/v1/health`、`/version`、`/metrics`；另 `/ws` **前缀**放行（覆盖 /ws/alerts）。
- 缺失/错误 token → `401 {"error":"missing or invalid token"}`；要求 `Bearer ` 前缀。

**⚠️ 安全假象（重要坑）**：当既没给 `--auth-token` 也没设 `KS_AUTH_TOKEN` 时，auth 中间件中 `token=None` 会**直接放行所有请求**（auth.rs 源码 `None => return next.run(req).await`），
而 CLI 打印的文案却声称"ENABLED (no token — 401 for all authed endpoints)"——**行为与文案相反**。
生产部署必须显式配置 `--auth-token`，否则鉴权形同虚设。

**与早期设计稿的差异**：无 JWT（jsonwebtoken）、无 `/api/v1/auth/*` 端点、无 Admin/Analyst/Viewer 角色矩阵、无 refresh token 撤销表——全部未实现。

---

## 4. TLS / mTLS（tls.rs）

- 配置：CLI `--tls-cert <path>` / `--tls-key <path>` / `--tls-client-ca <path>`（start 的 SecurityArgs）；cert+key 必须同时提供才启用 TLS。
- `--tls-client-ca` 存在即 mTLS：`WebPkiClientVerifier` 要求客户端证书由该 CA 签发。
- 证书加载：`rustls_pemfile` 解析（certs 可多个；私钥 PKCS8/PKCS1/SEC1，必须恰好 1 个）。
- ALPN：`h2` + `http/1.1`。
- 运行机制：`axum_server::tls_rustls::bind_rustls`（TLS 分支）或 `TcpListener + axum::serve with ConnectInfo`（明文分支，供限流取 IP）。
- 自签名证书生成命令见 [deployment.md](deployment.md)。

---

## 5. 速率限制（rate_limit.rs）

- 组件：tower-governor `GovernorLayer<PeerIpKeyExtractor, StateInformationMiddleware>`。
- 算法：GCRA 令牌桶，`per_second(60)` 周期 + `burst_size = limit`——即**每 IP 每分钟 limit 次请求**（默认 `DEFAULT_RATE_LIMIT_PER_MIN = 100`）。
- `--rate-limit 0` 表示不加限流层（server.rs 按 0 跳过 layer）。
- 响应带 X-RateLimit 头；超限 429。
- ⚠️ 依赖 `ConnectInfo` 取 IP：缺失（如某些代理场景）时返回 **500**。
- 示例：`kernelsentinel start --serve 8443 --rate-limit 200`。

**与早期设计稿的差异**：无分端点分类限流（GET 100/分、POST 30/分、登录 10/分、WS 5/分），全端点统一每 IP 每分钟。

---

## 6. 审计日志（audit.rs）

- 配置：CLI `--audit-log <path>`（默认 `/var/log/kernelsentinel/audit.log`）；`--no-audit` 关闭（SecurityArgs）。
- 内容：每请求一行 JSONL——`{timestamp(RFC3339), client_ip(x-forwarded-for 优先，否则 "unknown"), token_id(SHA-256(token) 前 4 字节 hex，无 token "none"), method, path(含 query), status, latency_ms}`。
- 实现：逐行 flush 追加写；目录不存在自动创建；打开失败降级为 None（warn 后关闭审计）。
- ⚠️ `x-forwarded-for` 直接信任，客户端可伪造审计 IP。

---

## 7. Prometheus 指标（metrics.rs，6 个）

| 指标 | 类型 | 标签 |
|---|---|---|
| `ks_events_total` | Counter | event_type |
| `ks_alerts_total` | Counter | severity |
| `ks_map_entries` | Gauge | map_name |
| `ks_event_processing_seconds` | Histogram | event_type |
| `ks_tier_status` | Gauge | tier（0/1） |
| `ks_ringbuf_lost_total` | Counter | — |

- `/metrics` 端点免鉴权，Content-Type `text/plain; version=0.0.4`。
- 告警计数由 `state.push_alert` 驱动；`record_event`/`record_ringbuf_lost` 提供钩子（当前仅测试直接调用）。

---

## 8. 状态管理（state.rs）

`ServerState` 内存态：

| 字段 | 说明 |
|---|---|
| `alerts: RwLock<Vec<Alert>>` | 告警环形（MAX_ALERTS=10000，FIFO remove(0)） |
| `tx: broadcast<Alert>` | WebSocket 广播频道（CHANNEL_CAP=256） |
| `tier_label` | 静态字符串（"unknown (standalone)" 或 start.rs 传入） |
| `map_reader: Option<Arc<dyn BpfMapReader>>` | 共享 BPF map 读取器（start.rs 传入） |
| `baseline_snapshots` | 六维基线（start.rs 每 50 事件同步） |
| `correlation_alerts` | 关联告警环形（MAX_CORR_ALERTS=1000） |
| `ml_detector: Arc<Mutex<AdaptiveDetector>>` | 反馈端点驱动误报学习 |
| `block_manager: Arc<Mutex<BlockManager>>` | 用户态阻断表 |

---

## 9. 未来工作（原设计稿，未实现）

以下为早期设计内容，**尚未实现**，仅作扩展参考：

- **数据库持久化**：SQLite（开发）/ PostgreSQL（生产）+ sqlx + 迁移（users/alerts/attack_chains/events_archive/forensic_checkpoints/refresh_tokens 6 表）；当前告警全部在内存，重启即清空。
- **JWT 认证体系**：登录/刷新/登出/me 端点、15 分钟 access token、角色权限矩阵、refresh token 撤销表。
- **规则 CRUD API**：`/api/v1/rules*`、`validate`——当前规则只从本地 YAML 加载 + start 内 5s 热加载，无 HTTP 管理面。
- **事件查询 API**：`/api/v1/events` 列表/详情/search/histogram——当前事件不落库，只经取证日志（JSONL）落盘，回放走 `kernelsentinel replay`。
- **攻击链 API**：`/api/v1/chains*`——当前攻击链只在 start 主循环打印（confidence>0.5）。
- **取证 API**：`/api/v1/forensic/*`——当前链校验用 `kernelsentinel replay --file`。
- **配置 API**：`/api/v1/config`——当前配置走环境变量 + CLI（YAML 文件未接入主程序）。
- **WebSocket 增强**：订阅/退订消息、`last_event_id` 断点补发、30s 心跳、status 定时推送、probe_change 消息类型。
- **事件归档冷热分离、多租户**：原"Phase 4"规划，与当前路线图（分布式/SIEM 对接）叠加评估。

---

## 10. 已知坑清单

1. `token=None` 时放行所有请求（见 §3）——部署必须显式 token。
2. `/api/v1/health` 的 `uptime_secs` 硬编码 0。
3. `/api/v1/reload` 是 stub，返回 202 但无操作。
4. 白名单含 `/health`（无此路由）与 `/version`（免鉴权），但 `/api/v1/version` 需要鉴权——不一致。
5. WS 免鉴权、无心跳；挂掉的客户端靠断开自清理。
6. rate limiter 在缺失 ConnectInfo 时 500。
7. CORS 全放行（`CorsLayer::permissive()`）。
8. 审计 client_ip 信任 `x-forwarded-for`。
9. `ks-server-bin` 默认 8443，而 CLI 的 watch/baseline/correlation 默认请求 3000——端口不一致，需 `-s` 显式指定。
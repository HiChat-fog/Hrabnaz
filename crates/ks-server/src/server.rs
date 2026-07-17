//! D5: 服务器启动函数
//!
//! run_server: 创建 ServerState，绑定 127.0.0.1:port，启动 axum
//! new_shared_state: 供 start.rs --serve 使用，返回 SharedState 供注入告警
//!
//! F4 安全加固：ServerConfig 集成 auth/tls/audit/rate_limit 配置，
//! run_server_with_config 按顺序应用中间件 layer：
//!   rate_limit (最外) -> auth -> audit -> 业务路由 (最内)
//! 中间件执行顺序：请求进入时从外到内（rate_limit 先检查配额，再鉴权，再审计），
//! 响应返回时从内到外（audit 拿到响应状态后写日志）。

use crate::{
    audit::{audit_middleware, AuditConfig, AuditWriter},
    auth::{auth_middleware, AuthToken},
    rate_limit,
    routes::router,
    state::ServerState,
    tls::{self, TlsConfig},
};
use anyhow::Result;
use axum::middleware::from_fn_with_state;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

/// F4 服务器安全配置 — 由 CLI flags 构建，注入到 `run_server_with_config`。
///
/// 字段说明：
/// - `auth`: API 鉴权配置（`enabled=false` 表示 `--no-auth` 模式）
/// - `tls`: 可选 TLS 配置（`None` = HTTP，`Some` = HTTPS）
/// - `audit`: 审计日志配置
/// - `rate_limit_per_min`: 速率限制（每分钟请求数/IP，0 = 关闭）
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    pub auth: AuthToken,
    pub tls: Option<TlsConfig>,
    pub audit: AuditConfig,
    /// 每分钟每 IP 请求上限；0 表示关闭速率限制。
    pub rate_limit_per_min: u32,
}

impl ServerConfig {
    /// 默认配置：鉴权关闭（向后兼容旧测试 / 旧 e2e）、无 TLS、审计关闭、速率限制 100/min。
    ///
    /// 注：生产部署应通过 CLI flags 显式启用鉴权 / TLS / 审计。
    pub fn insecure_default() -> Self {
        Self {
            auth: AuthToken::disabled(),
            tls: None,
            audit: AuditConfig::disabled(),
            rate_limit_per_min: rate_limit::DEFAULT_RATE_LIMIT_PER_MIN,
        }
    }
}

/// 旧入口（保留兼容）— 等价于 `run_server_with_config(state, port, ServerConfig::insecure_default())`。
pub async fn run_server(port: u16) -> Result<()> {
    let state: Arc<ServerState> = Arc::new(ServerState::new());
    serve(state, port, ServerConfig::insecure_default()).await
}

/// 旧入口（保留兼容）— tier 标签注入，安全配置为 insecure_default。
pub async fn run_server_with_tier(port: u16, tier: &'static str) -> Result<()> {
    let state: Arc<ServerState> = Arc::new(ServerState::with_tier(tier));
    serve(state, port, ServerConfig::insecure_default()).await
}

/// 旧入口（保留兼容）— 由调用方提供 ServerState，安全配置为 insecure_default。
///
/// 注：start.rs 调用此函数启动数据服务，向后兼容不破坏。
pub async fn run_server_with_state(state: Arc<ServerState>, port: u16) -> Result<()> {
    serve(state, port, ServerConfig::insecure_default()).await
}

/// F4 入口 — 由 CLI flags 构建的 ServerConfig 决定启用哪些安全特性。
pub async fn run_server_with_config(
    state: Arc<ServerState>,
    port: u16,
    config: ServerConfig,
) -> Result<()> {
    serve(state, port, config).await
}

/// 内部统一启动函数 — 根据 ServerConfig 组装中间件链。
///
/// 中间件 layer 顺序（请求进入方向：从外到内）：
///   1. CorsLayer（最外，处理 CORS preflight）
///   2. GovernorLayer（速率限制，超限 429）
///   3. auth_middleware（鉴权，401）
///   4. audit_middleware（审计日志，最后写日志，能拿到最终状态码）
///   5. routes::router（业务路由）
///
/// 注：axum::Router::layer() 是后入先出（LIFO）— 越后 layer 越在内层（先执行）。
/// 因此本函数中调用顺序与上面"外→内"列表相反。
async fn serve(state: Arc<ServerState>, port: u16, config: ServerConfig) -> Result<()> {
    // 构建审计 writer（若启用）
    let audit_writer: Option<AuditWriter> = if config.audit.enabled {
        match AuditWriter::open(&config.audit.log_path).await {
            Ok(w) => {
                log::info!("audit log: {}", config.audit.log_path.display());
                Some(w)
            }
            Err(e) => {
                log::warn!(
                    "audit log open 失败 ({}): {} — 审计将关闭",
                    config.audit.log_path.display(),
                    e
                );
                None
            }
        }
    } else {
        None
    };

    // 构建基础路由（业务路由 + WebSocket + /metrics）
    let app = router(state)
        // 4. audit（最内层中间件）— 必须在 auth 之后才能拿到 401 状态码
        .layer(from_fn_with_state(audit_writer, audit_middleware))
        // 3. auth — 鉴权失败返回 401，应在 audit 之前（让 audit 记录 401）
        .layer(from_fn_with_state(config.auth.clone(), auth_middleware));

    // 2. rate limit — 仅在 limit > 0 时启用
    let app = if config.rate_limit_per_min > 0 {
        app.layer(rate_limit::build_rate_limiter(config.rate_limit_per_min))
    } else {
        app
    };

    // 1. CORS（最外）
    let app = app.layer(CorsLayer::permissive());

    let addr = format!("127.0.0.1:{}", port);
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("bind 地址解析失败 {}: {}", addr, e))?;

    // TLS vs HTTP
    match &config.tls {
        Some(tls_cfg) => {
            log::info!(
                "TLS 配置: cert={}, key={}, mTLS={}",
                tls_cfg.server_cert.display(),
                tls_cfg.server_key.display(),
                tls_cfg.is_mtls()
            );
            tls::check_files_exist(tls_cfg)?;
            let rustls_config = tls::load_tls_config(tls_cfg).await?;
            // 注：用 into_make_service_with_connect_info 让 rate_limit 的 PeerIpKeyExtractor 能拿到客户端 IP
            tls::serve_tls(app, &addr, rustls_config, tls_cfg.is_mtls()).await?;
        }
        None => {
            log::info!("ks-server listening on http://{}", addr);
            println!("ks-server listening on http://{}", addr);
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            // 注：into_make_service_with_connect_info 注入 ConnectInfo<SocketAddr>，
            // 供 rate_limit 模块的 PeerIpKeyExtractor 提取客户端 IP
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }
    let _ = socket_addr; // 已在 log/println 中使用
    Ok(())
}

//! 服务器启动函数。
//!
//! run_server创建ServerState,绑定127.0.0.1:port,启动axum。new_shared_state供start.rs --serve使用,返回SharedState供注入告警。
//!
//! ServerConfig集成auth/tls/audit/rate_limit配置,run_server_with_config按顺序应用中间件layer:rate_limit(最外)、auth、audit、业务路由(最内)。请求进入时从外到内(rate_limit先检查配额,再鉴权,再审计),响应返回时从内到外(audit拿到响应状态后写日志)。

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

/// 服务器安全配置,由CLI flags构建,注入到run_server_with_config。
///
/// 字段说明:auth是API鉴权配置(enabled=false表示--no-auth模式);tls是可选TLS配置(None为HTTP,Some为HTTPS);audit是审计日志配置;rate_limit_per_min是速率限制(每分钟请求数/IP,0为关闭)。
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    pub auth: AuthToken,
    pub tls: Option<TlsConfig>,
    pub audit: AuditConfig,
    /// 每分钟每IP请求上限,0表示关闭速率限制。
    pub rate_limit_per_min: u32,
}

impl ServerConfig {
    /// 默认配置:鉴权关闭(向后兼容旧测试和旧e2e)、无TLS、审计关闭、速率限制100/min。
    ///
    /// 注:生产部署应通过CLI flags显式启用鉴权、TLS、审计。
    pub fn insecure_default() -> Self {
        Self {
            auth: AuthToken::disabled(),
            tls: None,
            audit: AuditConfig::disabled(),
            rate_limit_per_min: rate_limit::DEFAULT_RATE_LIMIT_PER_MIN,
        }
    }
}

/// 旧入口(保留兼容),等价于run_server_with_config(state, port, ServerConfig::insecure_default())。
pub async fn run_server(port: u16) -> Result<()> {
    let state: Arc<ServerState> = Arc::new(ServerState::new());
    serve(state, port, ServerConfig::insecure_default()).await
}

/// 旧入口(保留兼容),tier标签注入,安全配置为insecure_default。
pub async fn run_server_with_tier(port: u16, tier: &'static str) -> Result<()> {
    let state: Arc<ServerState> = Arc::new(ServerState::with_tier(tier));
    serve(state, port, ServerConfig::insecure_default()).await
}

/// 旧入口(保留兼容),由调用方提供ServerState,安全配置为insecure_default。
///
/// 注:start.rs调用此函数启动数据服务,向后兼容不破坏。
pub async fn run_server_with_state(state: Arc<ServerState>, port: u16) -> Result<()> {
    serve(state, port, ServerConfig::insecure_default()).await
}

/// 入口,由CLI flags构建的ServerConfig决定启用哪些安全特性。
pub async fn run_server_with_config(
    state: Arc<ServerState>,
    port: u16,
    config: ServerConfig,
) -> Result<()> {
    serve(state, port, config).await
}

/// 内部统一启动函数,根据ServerConfig组装中间件链。
///
/// 中间件layer顺序(请求进入方向从外到内):CorsLayer(最外,处理CORS preflight)、GovernorLayer(速率限制,超限429)、auth_middleware(鉴权,401)、audit_middleware(审计日志,最后写日志,能拿到最终状态码)、routes::router(业务路由)。
///
/// 注:axum::Router::layer()是后入先出(LIFO),越后layer越在内层(先执行),所以本函数中调用顺序跟上面外到内列表相反。
async fn serve(state: Arc<ServerState>, port: u16, config: ServerConfig) -> Result<()> {
    // 构建审计writer(若启用)
    let audit_writer: Option<AuditWriter> = if config.audit.enabled {
        match AuditWriter::open(&config.audit.log_path).await {
            Ok(w) => {
                log::info!("audit log: {}", config.audit.log_path.display());
                Some(w)
            }
            Err(e) => {
                log::warn!(
                    "audit log open 失败 ({}): {} - 审计将关闭",
                    config.audit.log_path.display(),
                    e
                );
                None
            }
        }
    } else {
        None
    };

    // 构建基础路由(业务路由 + WebSocket + /metrics)
    let app = router(state)
        // audit(最内层中间件),必须在auth之后才能拿到401状态码
        .layer(from_fn_with_state(audit_writer, audit_middleware))
        // auth,鉴权失败返回401,应在audit之前(让audit记录401)
        .layer(from_fn_with_state(config.auth.clone(), auth_middleware));

    // rate limit,仅在limit > 0时启用
    let app = if config.rate_limit_per_min > 0 {
        app.layer(rate_limit::build_rate_limiter(config.rate_limit_per_min))
    } else {
        app
    };

    // CORS(最外)
    let app = app.layer(CorsLayer::permissive());

    let addr = format!("127.0.0.1:{}", port);
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("bind地址解析失败{}: {}", addr, e))?;

    // TLS还是HTTP
    match &config.tls {
        Some(tls_cfg) => {
            log::info!(
                "TLS配置: cert={}, key={}, mTLS={}",
                tls_cfg.server_cert.display(),
                tls_cfg.server_key.display(),
                tls_cfg.is_mtls()
            );
            tls::check_files_exist(tls_cfg)?;
            let rustls_config = tls::load_tls_config(tls_cfg).await?;
            // 注:用into_make_service_with_connect_info让rate_limit的PeerIpKeyExtractor能拿到客户端IP
            tls::serve_tls(app, &addr, rustls_config, tls_cfg.is_mtls()).await?;
        }
        None => {
            log::info!("ks-server listening on http://{}", addr);
            println!("ks-server listening on http://{}", addr);
            let listener = tokio::net::TcpListener::bind(&addr).await?;
            // 注:into_make_service_with_connect_info注入ConnectInfo<SocketAddr>,
            // 供rate_limit模块的PeerIpKeyExtractor提取客户端IP
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }
    let _ = socket_addr; // 已在log/println中使用
    Ok(())
}

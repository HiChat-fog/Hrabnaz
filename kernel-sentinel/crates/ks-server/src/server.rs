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
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    pub auth: AuthToken,
    pub tls: Option<TlsConfig>,
    pub audit: AuditConfig,

    pub rate_limit_per_min: u32,
}

impl ServerConfig {

    pub fn insecure_default() -> Self {
        Self {
            auth: AuthToken::disabled(),
            tls: None,
            audit: AuditConfig::disabled(),
            rate_limit_per_min: rate_limit::DEFAULT_RATE_LIMIT_PER_MIN,
        }
    }
}

pub async fn run_server(port: u16) -> Result<()> {
    let state: Arc<ServerState> = Arc::new(ServerState::new());
    serve(state, port, ServerConfig::insecure_default()).await
}

pub async fn run_server_with_tier(port: u16, tier: &'static str) -> Result<()> {
    let state: Arc<ServerState> = Arc::new(ServerState::with_tier(tier));
    serve(state, port, ServerConfig::insecure_default()).await
}

pub async fn run_server_with_state(state: Arc<ServerState>, port: u16) -> Result<()> {
    serve(state, port, ServerConfig::insecure_default()).await
}

pub async fn run_server_with_config(
    state: Arc<ServerState>,
    port: u16,
    config: ServerConfig,
) -> Result<()> {
    serve(state, port, config).await
}

/// 先绑定端口再交给 serve，供调用方（start --serve）在 spawn 前确认 bind 成功，
/// 避免端口被占时后台静默 warn、用户误以为数据服务正常
pub async fn bind_listener(port: u16) -> Result<tokio::net::TcpListener> {
    let addr = format!("127.0.0.1:{}", port);
    tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| anyhow::anyhow!("绑定 {} 失败: {} (端口被占用或权限不足?)", addr, e))
}

/// 用已绑定的 listener 启动（明文 HTTP 路径）
pub async fn run_server_with_listener(
    state: Arc<ServerState>,
    listener: tokio::net::TcpListener,
    config: ServerConfig,
) -> Result<()> {
    let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    serve_on(Some(listener), port, state, config).await
}

pub fn cors_layer() -> CorsLayer {
    // 旧实现 CorsLayer::permissive() 允许任意网页跨域调用全部 API（含阻断 PID 的写操作）。
    // 默认不再放开任何 origin（curl/服务端调用不受 CORS 影响）；部署了浏览器端时
    // 用 KS_CORS_ORIGINS 显式列出可信 origin（逗号分隔）
    match std::env::var("KS_CORS_ORIGINS") {
        Ok(v) if !v.trim().is_empty() => {
            let origins: Vec<_> = v
                .split(',')
                .filter_map(|s| s.trim().parse().ok())
                .collect();
            CorsLayer::new()
                .allow_origin(origins)
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::DELETE,
                ])
                .allow_headers(Any)
        }
        _ => CorsLayer::new(),
    }
}

async fn serve(state: Arc<ServerState>, port: u16, config: ServerConfig) -> Result<()> {
    // 只有明文路径预绑端口（start --serve 要 bind 失败即中止）。
    // TLS 路径由 axum_server::bind_rustls 自行绑定：若这里预绑，
    // listener 存活期间 bind_rustls 绑同一端口会 EADDRINUSE，TLS 启动必失败
    let listener = if config.tls.is_none() {
        Some(bind_listener(port).await?)
    } else {
        None
    };
    serve_on(listener, port, state, config).await
}

async fn serve_on(
    listener: Option<tokio::net::TcpListener>,
    port: u16,
    state: Arc<ServerState>,
    config: ServerConfig,
) -> Result<()> {

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

    // 把生效的鉴权配置同步给 WS handler（REST 鉴权走下面的 auth_middleware）
    state.set_auth(config.auth.clone());

    let app = router(state)

        .layer(from_fn_with_state(audit_writer, audit_middleware))

        .layer(from_fn_with_state(config.auth.clone(), auth_middleware));

    let app = if config.rate_limit_per_min > 0 {
        app.layer(rate_limit::build_rate_limiter(config.rate_limit_per_min))
    } else {
        app
    };

    let app = app.layer(cors_layer());

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

            tls::serve_tls(
                app,
                &format!("127.0.0.1:{}", port),
                rustls_config,
                tls_cfg.is_mtls(),
            )
            .await?;
        }
        None => {
            let listener = listener.expect("明文路径必须携带预绑定的 listener");
            let addr = listener
                .local_addr()
                .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], port)));
            log::info!("ks-server listening on http://{}", addr);
            println!("ks-server listening on http://{}", addr);

            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }
    Ok(())
}

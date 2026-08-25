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

async fn serve(state: Arc<ServerState>, port: u16, config: ServerConfig) -> Result<()> {

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

    let app = router(state)

        .layer(from_fn_with_state(audit_writer, audit_middleware))

        .layer(from_fn_with_state(config.auth.clone(), auth_middleware));

    let app = if config.rate_limit_per_min > 0 {
        app.layer(rate_limit::build_rate_limiter(config.rate_limit_per_min))
    } else {
        app
    };

    let app = app.layer(CorsLayer::permissive());

    let addr = format!("127.0.0.1:{}", port);
    let socket_addr: SocketAddr = addr
        .parse()
        .map_err(|e| anyhow::anyhow!("bind地址解析失败{}: {}", addr, e))?;

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

            tls::serve_tls(app, &addr, rustls_config, tls_cfg.is_mtls()).await?;
        }
        None => {
            log::info!("ks-server listening on http://{}", addr);
            println!("ks-server listening on http://{}", addr);
            let listener = tokio::net::TcpListener::bind(&addr).await?;

            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await?;
        }
    }
    let _ = socket_addr;
    Ok(())
}

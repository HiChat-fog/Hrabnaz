use anyhow::{anyhow, Result};

#[tokio::main]
async fn main() -> Result<()> {

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    tracing_log::LogTracer::init().ok();

    let port: u16 = std::env::var("KS_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8443);

    // 独立二进制入口不再默认裸奔：旧实现走 insecure_default()（无鉴权/无审计/无 TLS）。
    // 想保持旧行为必须显式 KS_SERVER_ALLOW_INSECURE=1
    let auth_token = std::env::var("KS_AUTH_TOKEN").ok();
    if auth_token.is_none() && std::env::var("KS_SERVER_ALLOW_INSECURE").as_deref() != Ok("1") {
        return Err(anyhow!(
            "拒绝以不安全配置启动：未设置 KS_AUTH_TOKEN。\
             请设置 KS_AUTH_TOKEN=<token> 启用鉴权，\
             或显式设置 KS_SERVER_ALLOW_INSECURE=1 确认无鉴权模式（仅限本机调试）"
        ));
    }

    let config = ks_server::ServerConfig {
        auth: match auth_token {
            Some(t) => ks_server::AuthToken::new(t),
            None => ks_server::AuthToken::disabled(),
        },
        tls: None,
        audit: ks_server::AuditConfig::disabled(),
        rate_limit_per_min: ks_server::rate_limit::DEFAULT_RATE_LIMIT_PER_MIN,
    };

    let state = std::sync::Arc::new(ks_server::ServerState::new());
    ks_server::run_server_with_config(state, port, config).await
}

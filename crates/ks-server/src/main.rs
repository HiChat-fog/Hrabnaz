use anyhow::Result;

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
    ks_server::run_server(port).await
}

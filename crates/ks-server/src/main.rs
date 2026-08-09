//! ks-server入口,二进制main。
//!
//! 可观测性:用tracing-subscriber(json + env-filter)初始化,并通过tracing-log桥接让现有log::info!等调用继续工作(输出为JSON结构化日志)。RUST_LOG环境变量控制过滤级别(默认info),输出格式JSON(一行一条),便于SIEM、Loki采集。

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // tracing-subscriber JSON输出加EnvFilter(默认info级别)。
    // 必须在env_logger::init()之前调用,否则env_logger会安装自己的log后端。
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // tracing-log桥接,让log crate的log::info!/warn!/error!宏
    // 转发到tracing,从而以JSON结构化格式输出(保留现有代码兼容)。
    // 失败时仅记录警告,不影响服务启动。
    tracing_log::LogTracer::init().ok();

    let port: u16 = std::env::var("KS_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8443);
    ks_server::run_server(port).await
}

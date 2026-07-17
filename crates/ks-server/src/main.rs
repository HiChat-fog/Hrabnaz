//! ks-server 入口 — 二进制 main。
//!
//! F3 可观测性：用 tracing-subscriber (json + env-filter) 初始化，
//! 并通过 tracing-log 桥接让现有 `log::info!` 等调用继续工作（输出为 JSON 结构化日志）。
//!
//! - `RUST_LOG` 环境变量控制过滤级别（默认 info）。
//! - 输出格式：JSON（一行一条），便于 SIEM / Loki 采集。

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // F3: tracing-subscriber JSON 输出 + EnvFilter（默认 info 级别）。
    // 必须在 env_logger::init() 之前调用，否则 env_logger 会安装自己的 log 后端。
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // F3: tracing-log 桥接 — 让 log crate 的 log::info!/warn!/error! 宏
    // 转发到 tracing，从而以 JSON 结构化格式输出（保留现有代码兼容）。
    // 失败时仅记录警告，不影响服务启动。
    tracing_log::LogTracer::init().ok();

    let port: u16 = std::env::var("KS_SERVER_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8443);
    ks_server::run_server(port).await
}

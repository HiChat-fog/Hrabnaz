use anyhow::Result;
use std::sync::Arc;

use crate::cmds::{build_server_config, SecurityArgs};

/// F4: ks-cli `serve` 子命令入口 — 启动 standalone 数据服务模式。
///
/// 与 `start --serve <port>` 不同，此命令不加载 eBPF 探针，
/// 仅启动 ks-server REST API + WebSocket。安全配置由 `SecurityArgs` 提供：
/// - `--no-auth` / `--auth-token` / `KS_AUTH_TOKEN` 控制 API 鉴权
/// - `--tls-cert` + `--tls-key` 启用 TLS；`--tls-client-ca` 启用 mTLS
/// - `--rate-limit` 控制速率限制（默认 100/min/IP）
/// - `--audit-log` 控制审计日志路径
pub async fn run(port: u16, security: &SecurityArgs) -> Result<()> {
    println!("╔══════════════════════════════════════════╗");
    println!("║  内核哨兵 — 数据服务模式 (standalone)       ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("REST API:   http://127.0.0.1:{}/api/v1/", port);
    println!("WebSocket:  ws://127.0.0.1:{}/ws/alerts", port);
    println!();
    println!("提示: 此模式不启动 eBPF 探针。");
    println!(
        "      如需实时检测 + 数据服务，请用: kernelsentinel start --serve {}",
        port
    );
    println!();

    // F4: 用 SecurityArgs 构建 ServerConfig（auth/tls/audit/rate_limit）
    let server_config = build_server_config(security);
    let state = Arc::new(ks_server::ServerState::new());
    ks_server::run_server_with_config(state, port, server_config).await
}

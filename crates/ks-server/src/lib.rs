//! ks-server,REST API加WebSocket数据服务。
//!
//! 提供SIEM/SOAR消费接口:REST API支持告警查询、确认、解决、统计、健康检查;WebSocket支持实时告警推送(/ws/alerts);绑定127.0.0.1,公安内网部署。
//!
//! 安全加固:API鉴权(auth)加TLS双向认证(tls)加审计日志(audit)加速率限制(rate_limit)。默认启用鉴权,CLI --no-auth关闭(本地调试)。

pub mod metrics;
pub mod routes;
pub mod server;
pub mod state;
pub mod ws;

// F4 安全加固模块
pub mod audit;
pub mod auth;
pub mod rate_limit;
pub mod tls;

pub use audit::{AuditConfig, AuditWriter};
pub use auth::AuthToken;
pub use server::run_server;
pub use server::run_server_with_config;
pub use server::run_server_with_state;
pub use server::run_server_with_tier;
pub use server::ServerConfig;
pub use state::ServerState;
pub use state::SharedState;
pub use tls::TlsConfig;

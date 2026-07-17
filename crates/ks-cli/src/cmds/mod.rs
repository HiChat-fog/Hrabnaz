pub mod baseline;
pub mod correlation;
pub mod replay;
pub mod serve;
pub mod start;
pub mod status;
pub mod stop;
pub mod watch;

use clap::Args;

/// F4 安全加固共享 CLI 参数 — 同时挂到 `Start --serve` 与 `Serve` 子命令。
///
/// 默认行为：
/// - `--no-auth` 不开启 → 鉴权启用（但仅在指定 `--auth-token` / `KS_AUTH_TOKEN` 时生效）
/// - `--tls-cert` / `--tls-key` 均指定 → 启用 TLS；`--tls-client-ca` 同时指定则启用 mTLS
/// - `--rate-limit` 默认 100/min
/// - `--audit-log` 默认 `/var/log/kernelsentinel/audit.log`
#[derive(Args, Debug, Clone, Default)]
pub struct SecurityArgs {
    /// 禁用 API 鉴权（仅本地调试，生产环境不应使用）
    #[arg(long, default_value_t = false)]
    pub no_auth: bool,

    /// API 鉴权 Bearer token；未指定时从环境变量 KS_AUTH_TOKEN 读取
    #[arg(long)]
    pub auth_token: Option<String>,

    /// TLS 服务器证书 PEM 文件路径（同时指定 --tls-key 时启用 TLS）
    #[arg(long)]
    pub tls_cert: Option<String>,

    /// TLS 服务器私钥 PEM 文件路径
    #[arg(long)]
    pub tls_key: Option<String>,

    /// 客户端 CA 证书 PEM（指定后启用 mTLS 双向认证）
    #[arg(long)]
    pub tls_client_ca: Option<String>,

    /// 每分钟每 IP 请求上限（默认 100，0 表示关闭）
    #[arg(long, default_value_t = 100)]
    pub rate_limit: u32,

    /// 审计日志文件路径（默认 /var/log/kernelsentinel/audit.log）
    #[arg(long, default_value = "/var/log/kernelsentinel/audit.log")]
    pub audit_log: String,
}

/// 从 SecurityArgs 构建 ks_server::ServerConfig。
///
/// 优先级：
/// - `auth_token` 字段 > `KS_AUTH_TOKEN` 环境变量
/// - `--no-auth` 时强制关闭鉴权（即便提供了 token）
/// - `--tls-cert` + `--tls-key` 同时提供时启用 TLS；`--tls-client-ca` 同时提供则启用 mTLS
pub fn build_server_config(args: &SecurityArgs) -> ks_server::ServerConfig {
    // 1. 鉴权配置
    let auth = if args.no_auth {
        ks_server::AuthToken::disabled()
    } else {
        // 优先 CLI flag，其次环境变量
        let token = args
            .auth_token
            .clone()
            .or_else(|| std::env::var("KS_AUTH_TOKEN").ok());
        match token {
            Some(t) => ks_server::AuthToken::new(t),
            None => {
                // enabled=true 但 token=None — 兼容模式：仅启用审计路径，不实际校验 token
                ks_server::AuthToken {
                    token: None,
                    enabled: true,
                }
            }
        }
    };

    // 2. TLS 配置
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Some(ks_server::TlsConfig::new(
            cert.clone(),
            key.clone(),
            args.tls_client_ca.clone().map(std::path::PathBuf::from),
        )),
        _ => None,
    };

    // 3. 审计配置 — 启用条件：路径非空
    let audit = if args.audit_log.is_empty() {
        ks_server::AuditConfig::disabled()
    } else {
        ks_server::AuditConfig::new(&args.audit_log)
    };

    // 4. 速率限制
    ks_server::ServerConfig {
        auth,
        tls,
        audit,
        rate_limit_per_min: args.rate_limit,
    }
}

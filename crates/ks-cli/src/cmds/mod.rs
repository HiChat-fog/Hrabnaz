pub mod ui;
pub mod baseline;
pub mod correlation;
pub mod replay;
pub mod serve;
pub mod singleton;
pub mod start;
pub mod status;
pub mod stop;
pub mod watch;

use clap::Args;

/// 安全加固共享CLI参数,同时挂到Start --serve与Serve子命令。
///
/// 默认行为:--no-auth不开启则鉴权启用(但仅在指定--auth-token或KS_AUTH_TOKEN时生效);--tls-cert与--tls-key均指定时启用TLS,--tls-client-ca同时指定则启用mTLS;--rate-limit默认100/min;--audit-log默认/var/log/kernelsentinel/audit.log。
#[derive(Args, Debug, Clone, Default)]
pub struct SecurityArgs {
    /// 禁用API鉴权(仅本地调试,生产环境不应使用)
    #[arg(long, default_value_t = false)]
    pub no_auth: bool,

    /// API鉴权Bearer token,未指定时从环境变量KS_AUTH_TOKEN读取
    #[arg(long)]
    pub auth_token: Option<String>,

    /// TLS服务器证书PEM文件路径(同时指定--tls-key时启用TLS)
    #[arg(long)]
    pub tls_cert: Option<String>,

    /// TLS服务器私钥PEM文件路径
    #[arg(long)]
    pub tls_key: Option<String>,

    /// 客户端CA证书PEM(指定后启用mTLS双向认证)
    #[arg(long)]
    pub tls_client_ca: Option<String>,

    /// 每分钟每IP请求上限(默认100,0表示关闭)
    #[arg(long, default_value_t = 100)]
    pub rate_limit: u32,

    /// 审计日志文件路径(默认/var/log/kernelsentinel/audit.log)
    #[arg(long, default_value = "/var/log/kernelsentinel/audit.log")]
    pub audit_log: String,
}

/// 从SecurityArgs构建ks_server::ServerConfig。
///
/// 优先级:auth_token字段优先于KS_AUTH_TOKEN环境变量;--no-auth时强制关闭鉴权(即便提供了token);--tls-cert加--tls-key同时提供时启用TLS,--tls-client-ca同时提供则启用mTLS。
pub fn build_server_config(args: &SecurityArgs) -> ks_server::ServerConfig {
    // 鉴权配置
    let auth = if args.no_auth {
        ks_server::AuthToken::disabled()
    } else {
        // 优先CLI flag,其次环境变量
        let token = args
            .auth_token
            .clone()
            .or_else(|| std::env::var("KS_AUTH_TOKEN").ok());
        match token {
            Some(t) => ks_server::AuthToken::new(t),
            None => {
                // enabled为true但token为None,兼容模式:仅启用审计路径,不实际校验token
                ks_server::AuthToken {
                    token: None,
                    enabled: true,
                }
            }
        }
    };

    // TLS配置
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Some(ks_server::TlsConfig::new(
            cert.clone(),
            key.clone(),
            args.tls_client_ca.clone().map(std::path::PathBuf::from),
        )),
        _ => None,
    };

    // 审计配置,启用条件为路径非空
    let audit = if args.audit_log.is_empty() {
        ks_server::AuditConfig::disabled()
    } else {
        ks_server::AuditConfig::new(&args.audit_log)
    };

    // 速率限制
    ks_server::ServerConfig {
        auth,
        tls,
        audit,
        rate_limit_per_min: args.rate_limit,
    }
}

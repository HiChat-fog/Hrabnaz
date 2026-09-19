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

/// 运行时状态文件路径（start 写 / status 读 / stop 读后 kill）。
/// root 时放 /run/kernelsentinel/（root-only 目录，防本地用户伪造/symlink 后诱导 stop 杀任意进程），
/// 非 root 回退 /tmp。三处共用此 helper，避免路径漂移
pub fn status_file_path() -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        let is_root = unsafe { libc::geteuid() } == 0;
        if is_root {
            let run_dir = std::path::Path::new("/run/kernelsentinel");
            if std::fs::create_dir_all(run_dir).is_ok() {
                // 目录收紧为 0700，普通用户不可读写
                let _ = std::fs::set_permissions(run_dir, {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::Permissions::from_mode(0o700)
                });
                return run_dir.join("ks-status.json");
            }
        }
        std::path::PathBuf::from("/tmp/ks-status.json")
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::path::PathBuf::from("./ks-status.json")
    }
}

#[derive(Args, Debug, Clone, Default)]
pub struct SecurityArgs {
    #[arg(long, default_value_t = false)]
    pub no_auth: bool,

    #[arg(long)]
    pub auth_token: Option<String>,

    #[arg(long)]
    pub tls_cert: Option<String>,

    #[arg(long)]
    pub tls_key: Option<String>,

    #[arg(long)]
    pub tls_client_ca: Option<String>,

    #[arg(long, default_value_t = 100)]
    pub rate_limit: u32,

    #[arg(long, default_value = "/var/log/kernelsentinel/audit.log")]
    pub audit_log: String,
}

pub fn build_server_config(args: &SecurityArgs) -> ks_server::ServerConfig {
    let auth = if args.no_auth {
        ks_server::AuthToken::disabled()
    } else {
        let token = args
            .auth_token
            .clone()
            .or_else(|| std::env::var("KS_AUTH_TOKEN").ok());
        match token {
            Some(t) => ks_server::AuthToken::new(t),
            None => {
                ks_server::AuthToken {
                    token: None,
                    enabled: true,
                }
            }
        }
    };

    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Some(ks_server::TlsConfig::new(
            cert.clone(),
            key.clone(),
            args.tls_client_ca.clone().map(std::path::PathBuf::from),
        )),
        _ => None,
    };

    let audit = if args.audit_log.is_empty() {
        ks_server::AuditConfig::disabled()
    } else {
        ks_server::AuditConfig::new(&args.audit_log)
    };

    ks_server::ServerConfig {
        auth,
        tls,
        audit,
        rate_limit_per_min: args.rate_limit,
    }
}

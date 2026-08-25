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

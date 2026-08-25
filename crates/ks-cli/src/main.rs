mod cmds;

use clap::{Parser, Subcommand};
use colored::control;

#[derive(Parser)]
#[command(name = "kernelsentinel")]
#[command(about = "内核哨兵 - eBPF 内核级威胁检测")]
#[command(version)]
struct Cli {
    #[arg(short, long, default_value = "warn")]
    log_level: String,
    #[arg(long, default_value = "auto", value_parser = ["auto", "always", "never"], global = true)]
    color: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Start {
        #[arg(short, long, default_value = "rules/")]
        rules_dir: String,
        #[arg(short, long, default_value = "/var/log/ks")]
        log_dir: String,
        #[arg(long)]
        serve: Option<u16>,
        #[arg(long, default_value_t = false)]
        sd_notify: bool,
        #[command(flatten)]
        security: cmds::SecurityArgs,
    },
    Stop,
    Status {
        #[arg(long, default_value_t = false)]
        watch: bool,
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
    Replay {
        #[arg(short, long)]
        file: String,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    Serve {
        #[arg(short, long, default_value = "8443")]
        port: u16,
    },
    Baseline {
        #[command(flatten)]
        args: cmds::baseline::BaselineArgs,
    },
    Correlation {
        #[command(flatten)]
        args: cmds::correlation::CorrelationArgs,
    },
    Watch {
        #[command(flatten)]
        args: cmds::watch::WatchArgs,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&cli.log_level))
        .init();

    match cli.color.as_str() {
        "always" => control::set_override(true),
        "never" => control::set_override(false),
        _ => control::unset_override(),
    }

    #[cfg(target_os = "linux")]
    {
        let rl = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl) } != 0 {
            log::warn!(
                "setrlimit(RLIMIT_MEMLOCK, ∞) 失败: {} - eBPF map创建可能EPERM(systemd下由LimitMEMLOCK=infinity覆盖)",
                std::io::Error::last_os_error()
            );
        }
    }

    match cli.command {
        Commands::Start {
            rules_dir,
            log_dir,
            serve,
            sd_notify,
            security,
        } => {
            cmds::ui::banner(&format!("内核哨兵 v{} 启动中", env!("CARGO_PKG_VERSION")));
            println!("  规则目录: {}", rules_dir);
            println!("  日志目录: {}", log_dir);
            if let Some(port) = serve {
                println!("  REST API (可选demo): http://localhost:{}/api/v1/", port);
                print_security_status(&security);
            }
            if sd_notify {
                println!("  sd-notify: 启用 (Type=notify)");
            }
            println!();

            cmds::start::run(&rules_dir, &log_dir, serve, sd_notify, &security).await?;
        }
        Commands::Stop => {
            cmds::stop::run().await?;
        }
        Commands::Status { watch, interval } => cmds::status::run(watch, interval).await?,
        Commands::Replay { file, json } => {
            cmds::replay::run(&file, json).await?;
        }
        Commands::Serve { port } => {
            cmds::serve::run(port).await?;
        }
        Commands::Baseline { args } => {
            cmds::baseline::run(&args).await?;
        }
        Commands::Correlation { args } => {
            cmds::correlation::run(&args).await?;
        }
        Commands::Watch { args } => {
            cmds::watch::run(&args).await?;
        }
    }
    Ok(())
}

fn print_security_status(args: &cmds::SecurityArgs) {
    let auth_status = if args.no_auth {
        "DISABLED (--no-auth)"
    } else if args.auth_token.is_some() || std::env::var("KS_AUTH_TOKEN").is_ok() {
        "ENABLED"
    } else {
        "ENABLED (no token — 401 for all authed endpoints)"
    };
    println!("      鉴权: {}", auth_status);
    match (&args.tls_cert, &args.tls_key) {
        (Some(c), Some(k)) => {
            println!("      TLS:  启用 (cert={}, key={})", c, k);
            if let Some(ca) = &args.tls_client_ca {
                println!("      mTLS: 启用 (client_ca={})", ca);
            }
        }
        (Some(c), None) => println!(
            "      TLS:  仅指定 --tls-cert={} 但未指定 --tls-key，TLS 不启用",
            c
        ),
        (None, Some(k)) => println!(
            "      TLS:  仅指定 --tls-key={} 但未指定 --tls-cert，TLS 不启用",
            k
        ),
        (None, None) => println!("      TLS:  未启用 (HTTP)"),
    }
    println!("      限流: {} req/min/IP", args.rate_limit);
    println!("      审计: {}", args.audit_log);
}

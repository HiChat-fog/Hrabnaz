mod cmds;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "kernelsentinel")]
#[command(about = "内核哨兵 - eBPF 内核级威胁检测")]
#[command(version)]
struct Cli {
    #[arg(short, long, default_value = "warn")]
    log_level: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// 启动探针开始监控
    Start {
        #[arg(short, long, default_value = "rules/")]
        rules_dir: String,
        #[arg(short, long, default_value = "/var/log/ks")]
        log_dir: String,
        #[arg(long)]
        serve: Option<u16>,
        /// 启动后向systemd发送READY=1通知（Type=notify服务使用）
        #[arg(long, default_value_t = false)]
        sd_notify: bool,
        /// F4安全加固参数（仅--serve启用数据服务时生效）
        #[command(flatten)]
        security: cmds::SecurityArgs,
    },
    /// 卸载探针
    Stop,
    /// 查看状态（--watch进入动态监控模式，定期刷新探针状态与事件计数）
    Status {
        /// 动态监控模式：定期清屏重绘
        #[arg(long, default_value_t = false)]
        watch: bool,
        /// 刷新间隔秒数（仅--watch生效）
        #[arg(long, default_value_t = 2)]
        interval: u64,
    },
    /// 回放取证日志
    Replay {
        #[arg(short, long)]
        file: String,
    },
    /// CLI-first声明（不启动Web服务；申报书要求serve≠启动Web服务）
    Serve {
        /// 仅用于提示`start --serve <port>`可选demo端口
        #[arg(short, long, default_value = "8443")]
        port: u16,
    },
    /// 查看进程行为基线（z-score六维基线）
    Baseline {
        #[command(flatten)]
        args: cmds::baseline::BaselineArgs,
    },
    /// 查看跨事件关联告警
    Correlation {
        #[command(flatten)]
        args: cmds::correlation::CorrelationArgs,
    },
    /// 实时监控告警流
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

    // BPF map创建需memlock；非systemd运行（如SSH手动`start`）默认memlock 64KB会在CentOS 7 3.10上致bpf() EPERM。
    // systemd unit已设LimitMEMLOCK=infinity，此处兜底手动运行。
    #[cfg(target_os = "linux")]
    {
        let rl = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl) } != 0 {
            log::warn!(
                "setrlimit(RLIMIT_MEMLOCK, ∞) 失败: {} — eBPF map 创建可能 EPERM（systemd 下由 LimitMEMLOCK=infinity 覆盖）",
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
            println!("内核哨兵启动中...");
            println!("规则目录: {}", rules_dir);
            println!("日志目录: {}", log_dir);
            if let Some(port) = serve {
                println!("REST API (可选 demo): http://localhost:{}/api/v1/", port);
                print_security_status(&security);
            }
            if sd_notify {
                println!("sd-notify: 启用 (Type=notify)");
            }
            println!();
            println!("========================================");
            println!(" 内核哨兵 v{}", env!("CARGO_PKG_VERSION"));
            println!(" eBPF 探针已启动，正在监控系统调用...");
            println!(" 按 Ctrl+C 停止");
            println!("========================================");

            cmds::start::run(&rules_dir, &log_dir, serve, sd_notify, &security).await?;
        }
        Commands::Stop => {
            println!("正在卸载探针...");
            cmds::stop::run().await?;
            println!("探针已卸载");
        }
        Commands::Status { watch, interval } => cmds::status::run(watch, interval).await?,
        Commands::Replay { file } => {
            println!("回放 {}", file);
            cmds::replay::run(&file).await?;
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

/// 打印当前安全配置概要（不泄露token）。
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

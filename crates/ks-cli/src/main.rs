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
        #[arg(long, default_value_t = false)]
        sd_notify: bool,
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
            sd_notify,
        } => {
            cmds::ui::banner(&format!("内核哨兵 v{} 启动中", env!("CARGO_PKG_VERSION")));
            println!("  规则目录: {}", rules_dir);
            println!("  日志目录: {}", log_dir);
            if sd_notify {
                println!("  sd-notify: 启用 (Type=notify)");
            }
            println!();

            cmds::start::run(&rules_dir, &log_dir, sd_notify).await?;
        }
        Commands::Stop => {
            cmds::stop::run().await?;
        }
        Commands::Status { watch, interval } => cmds::status::run(watch, interval).await?,
        Commands::Replay { file, json } => {
            cmds::replay::run(&file, json).await?;
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

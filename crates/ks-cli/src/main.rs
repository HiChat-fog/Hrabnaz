mod cmds;

use clap::{Parser, Subcommand};
use colored::control;
use std::path::Path;

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
    /// 手动下发阻断裁决（写引擎 pin 的 block_decisions map，--ttl 0 = 永久）
    Block {
        pid: u32,
        /// TTL 秒数，0 = 永久
        #[arg(long, default_value_t = 600)]
        ttl: u64,
        /// 机器可读输出（单行 JSON 对象）
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// 解除手动/自动的阻断裁决
    Unblock {
        pid: u32,
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// 列出生效中的阻断裁决
    Blocked {
        #[arg(long, default_value_t = false)]
        json: bool,
    },
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
    /// 引擎心跳 watchdog：消费循环停摆时 SIGTERM 交由 systemd 拉起
    Watchdog {
        #[command(flatten)]
        args: cmds::watchdog::WatchdogArgs,
    },
    /// 生成规则集完整性基线指纹（配合 KS_RULES_DIGEST 部署守卫使用）
    RulesDigest {
        #[arg(short, long, default_value = "rules/")]
        rules_dir: String,
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
    if let Err(e) = ks_core::sys::set_memlock_unlimited() {
        log::warn!(
            "setrlimit(RLIMIT_MEMLOCK, ∞) 失败: {} - eBPF map创建可能EPERM(systemd下由LimitMEMLOCK=infinity覆盖)",
            e
        );
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
        Commands::Block { pid, ttl, json } => {
            cmds::block::run_block(pid, ttl, json).await?;
        }
        Commands::Unblock { pid, json } => {
            cmds::block::run_unblock(pid, json).await?;
        }
        Commands::Blocked { json } => {
            cmds::block::run_blocked(json).await?;
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
        Commands::Watchdog { args } => {
            cmds::watchdog::run(&args).await?;
        }
        Commands::RulesDigest { rules_dir } => {
            let integrity = ks_engine::rules_integrity::digest_rules_dir(Path::new(&rules_dir))?;
            println!("KS_RULES_DIGEST={}", integrity.combined_digest);
            for (name, hash) in &integrity.files {
                println!("  {}  {}", hash, name);
            }
            println!();
            println!(
                "部署守卫: 把 KS_RULES_DIGEST 写入服务环境（或 unit Environment=），\
                 引擎启动/热加载时自动比对；不一致产生审计告警，KS_RULES_DIGEST_STRICT=1 时拒绝启动"
            );
        }
    }
    Ok(())
}

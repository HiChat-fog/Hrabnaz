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
    },
    /// 卸载探针
    Stop,
    /// 查看状态
    Status,
    /// 回放取证日志
    Replay {
        #[arg(short, long)]
        file: String,
    },
    /// 启动 Web Dashboard
    Serve {
        #[arg(short, long, default_value = "3000")]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&cli.log_level)).init();

    match cli.command {
        Commands::Start { rules_dir, log_dir, serve } => {
            println!("内核哨兵启动中...");
            println!("规则目录: {}", rules_dir);
            println!("日志目录: {}", log_dir);
            if let Some(port) = serve {
                println!("Dashboard: http://localhost:{}", port);
            }
            println!();
            println!("========================================");
            println!(" 内核哨兵 v{}", env!("CARGO_PKG_VERSION"));
            println!(" eBPF 探针已启动，正在监控系统调用...");
            println!(" 按 Ctrl+C 停止");
            println!("========================================");

            if let Some(port) = serve {
                tokio::spawn(async move {
                    println!("[注意] Web Dashboard (端口 {}) 尚未实现", port);
                    let _ = cmds::serve::run(port).await;
                });
                cmds::start::run(&rules_dir, &log_dir).await?;
            } else {
                cmds::start::run(&rules_dir, &log_dir).await?;
            }
        }
        Commands::Stop => {
            println!("正在卸载探针...");
            cmds::stop::run().await?;
            println!("探针已卸载");
        }
        Commands::Status => cmds::status::run().await?,
        Commands::Replay { file } => {
            println!("回放 {}", file);
            cmds::replay::run(&file).await?;
        }
        Commands::Serve { port } => {
            println!("Dashboard: http://localhost:{}", port);
            cmds::serve::run(port).await?;
        }
    }
    Ok(())
}
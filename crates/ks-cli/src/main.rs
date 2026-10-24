mod cmds;

use clap::{Parser, Subcommand, ValueEnum};
use colored::control;
use colored::Colorize;
use std::path::Path;

#[derive(Parser)]
#[command(name = "kernelsentinel")]
#[command(about = "内核哨兵 - eBPF 内核级威胁检测")]
#[command(version)]
#[command(after_help = "常用示例:
  kernelsentinel start
  kernelsentinel watch --severity high --comm sshd
  kernelsentinel status --json")]
struct Cli {
    /// 日志级别: error|warn|info|debug|trace
    #[arg(short, long, default_value = "warn", value_parser = ["error", "warn", "info", "debug", "trace"])]
    log_level: String,
    /// 颜色输出: auto|always|never
    #[arg(long, default_value = "auto", value_parser = ["auto", "always", "never"], global = true)]
    color: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
    Fish,
    Powershell,
    Elvish,
}

#[derive(Subcommand)]
enum Commands {
    /// 启动探针消费与检测（需要 root）
    Start {
        /// 规则目录
        #[arg(short, long, default_value = "rules/")]
        rules_dir: String,
        /// 取证日志目录
        #[arg(short, long, default_value = "/var/log/ks")]
        log_dir: String,
        /// 启用 systemd Type=notify 就绪通知
        #[arg(long, default_value_t = false)]
        sd_notify: bool,
    },
    /// 停止当前运行的实例
    Stop,
    /// 手动下发阻断裁决（写引擎 pin 的 block_decisions map，--ttl 0 = 永久）
    Block {
        /// 目标进程 PID
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
        /// 目标进程 PID
        pid: u32,
        /// 机器可读输出（单行 JSON 对象）
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// 列出生效中的阻断裁决
    Blocked {
        /// 机器可读输出（单行 JSON 对象）
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// 显示系统状态（运行实例、探针、取证、规则集）
    Status {
        /// 每 N 秒刷新一次，Ctrl+C 退出
        #[arg(long, default_value_t = false)]
        watch: bool,
        /// 刷新间隔（秒，≥1）
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..))]
        interval: u64,
        /// 输出稳定 JSON；配合 --watch 时为 JSONL 快照
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// 回放取证日志并校验哈希链
    Replay {
        /// 取证日志文件（events_*.jsonl 或 .jsonl.gz）
        #[arg(short, long)]
        file: String,
        /// 机器可读输出（单行 JSON 对象）
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// 基线诊断
    Baseline {
        #[command(flatten)]
        args: cmds::baseline::BaselineArgs,
    },
    /// 关联规则诊断
    Correlation {
        #[command(flatten)]
        args: cmds::correlation::CorrelationArgs,
    },
    /// 实时告警流（默认 follow）
    #[command(
        long_about = "启动时回显最近历史告警，然后持续 tail 当前取证日志；轮转/截断自动跟随。\n\
                      --json 输出 JSONL（follow 时不回显历史）；--no-follow 读取当前已有告警后退出。",
        after_help = "过滤（同一 flag 多次为 OR，不同 flag 之间为 AND）:
  --rule <GLOB>       规则名，如 'SSH*'
  --comm <GLOB>       进程名，如 'sshd'
  --severity <LEVEL>  最低级别 low|medium|high|critical
  --pid <PID>         进程 PID
  --file <SUBSTR>     文件路径包含

示例:
  kernelsentinel watch --severity high --comm sshd
  kernelsentinel watch --rule '*勒索*' --json
  kernelsentinel watch --no-follow --max 50"
    )]
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
        /// 规则目录
        #[arg(short, long, default_value = "rules/")]
        rules_dir: String,
    },
    /// 生成 shell 补全脚本
    Completion {
        /// 目标 shell
        #[arg(value_enum)]
        shell: CompletionShell,
    },
}

/// Rust 默认忽略 SIGPIPE，向已关闭的管道继续写会 panic（`watch | head` 这类
/// 正常脚本用法会留下 101 和一段 backtrace）。除需要收尾清理的 start 外，
/// 把 broken pipe 视作正常的读取方退出：安静退出 0。
fn install_broken_pipe_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let broken_pipe = payload
            .downcast_ref::<String>()
            .is_some_and(|msg| msg.contains("Broken pipe"))
            || payload
                .downcast_ref::<&str>()
                .is_some_and(|msg| msg.contains("Broken pipe"));
        if broken_pipe {
            std::process::exit(0);
        }
        default_hook(info);
    }));
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if !matches!(&cli.command, Commands::Start { .. }) {
        install_broken_pipe_hook();
    }
    let debug = matches!(cli.log_level.as_str(), "debug" | "trace");
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&cli.log_level))
        .init();

    match cli.color.as_str() {
        "always" => control::set_override(true),
        "never" => control::set_override(false),
        _ => control::unset_override(),
    }

    // 只有 start 会创建 eBPF map；其余子命令不该因为非 root 而向 stderr
    // 输出一条与本次操作无关的 memlock 警告。
    #[cfg(target_os = "linux")]
    if matches!(&cli.command, Commands::Start { .. }) {
        if let Err(e) = ks_core::sys::set_memlock_unlimited() {
            log::warn!(
                "setrlimit(RLIMIT_MEMLOCK, ∞) 失败: {} - eBPF map创建可能EPERM(systemd下由LimitMEMLOCK=infinity覆盖)",
                e
            );
        }
    }

    if let Err(e) = run(cli).await {
        // 用法错误由 clap 处理（exit 2）；这里只处理运行期错误
        eprintln!("{} {e}", "error:".red().bold());
        if debug {
            eprintln!("{e:#}");
        }
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
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
        Commands::Status {
            watch,
            interval,
            json,
        } => cmds::status::run(watch, interval, json).await?,
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
        Commands::Completion { shell } => print_completion(shell),
    }
    Ok(())
}

fn print_completion(shell: CompletionShell) {
    let script = match shell {
        CompletionShell::Bash => {
            r#"_kernelsentinel() {
  local cur prev cmd
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  cmd="${COMP_WORDS[1]}"
  local commands="start stop block unblock blocked status replay baseline correlation watch watchdog rules-digest completion help"
  if [ "$COMP_CWORD" -eq 1 ]; then
    COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
    return 0
  fi
  case "$prev" in
    --file|-f|--log-dir|-l|--rules-dir|-r) COMPREPLY=( $(compgen -f -- "$cur") ); return 0;;
  esac
  case "$cmd" in
    start) COMPREPLY=( $(compgen -W "--rules-dir --log-dir --sd-notify --color --help" -- "$cur") );;
    block) COMPREPLY=( $(compgen -W "--ttl --json --color --help" -- "$cur") );;
    unblock|blocked) COMPREPLY=( $(compgen -W "--json --color --help" -- "$cur") );;
    status) COMPREPLY=( $(compgen -W "--watch --interval --json --color --help" -- "$cur") );;
    replay) COMPREPLY=( $(compgen -W "--file --json --color --help" -- "$cur") );;
    watch) COMPREPLY=( $(compgen -W "--log-dir --interval --max --json --follow --no-follow --rule --comm --severity --pid --file --color --help" -- "$cur") );;
    rules-digest) COMPREPLY=( $(compgen -W "--rules-dir --color --help" -- "$cur") );;
    completion) COMPREPLY=( $(compgen -W "bash zsh fish powershell elvish" -- "$cur") );;
  esac
}
complete -F _kernelsentinel kernelsentinel
"#
        }
        CompletionShell::Zsh => {
            r#"#compdef kernelsentinel
_arguments '1:command:(start stop block unblock blocked status replay baseline correlation watch watchdog rules-digest completion help)' '*::arg:->args'
case $words[2] in
  watch) _arguments '--rule[rule glob]' '--comm[comm glob]' '--severity[min severity]' '--pid[pid]' '--file[file substring]' '--json[JSONL]' '--follow[follow]' '--no-follow[read and exit]' '--max[max alerts]' '--interval[seconds]' '--log-dir[directory]' ;;
  status) _arguments '--json[JSON]' '--watch[refresh]' '--interval[seconds]' ;;
  completion) _values shell bash zsh fish powershell elvish ;;
esac
"#
        }
        CompletionShell::Fish => {
            r#"complete -c kernelsentinel -f
complete -c kernelsentinel -n '__fish_use_subcommand' -a 'start stop block unblock blocked status replay baseline correlation watch watchdog rules-digest completion help'
complete -c kernelsentinel -n '__fish_seen_subcommand_from watch' -l rule -l comm -l severity -l pid -l file -l json -l follow -l no-follow -l max -l interval -l log-dir
complete -c kernelsentinel -n '__fish_seen_subcommand_from status' -l json -l watch -l interval
complete -c kernelsentinel -n '__fish_seen_subcommand_from replay' -l file -l json
complete -c kernelsentinel -n '__fish_seen_subcommand_from completion' -a 'bash zsh fish powershell elvish'
"#
        }
        CompletionShell::Powershell => {
            r#"Register-ArgumentCompleter -Native -CommandName kernelsentinel -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $commands = 'start','stop','block','unblock','blocked','status','replay','baseline','correlation','watch','watchdog','rules-digest','completion','help'
  $commands | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
"#
        }
        CompletionShell::Elvish => {
            r#"set edit:completion:arg-completer[kernelsentinel] = {|@words|
  put start stop block unblock blocked status replay baseline correlation watch watchdog rules-digest completion help
}
"#
        }
    };
    print!("{script}");
}

//! `kernelsentinel watch`子命令,实时监控告警流。
//!
//! 通过HTTP轮询/api/v1/alerts?limit=20(每秒一次)打印新告警。不使用WebSocket客户端以避免额外依赖,轮询间隔1s对告警展示足够。

use anyhow::Result;
use ks_core::alert::Alert;
use std::collections::HashSet;
use std::time::Duration;

use super::ui::{banner, severity_badge};
use colored::Colorize;

#[derive(clap::Args, Debug)]
pub struct WatchArgs {
    /// ks-server地址
    #[arg(short, long, default_value = "http://127.0.0.1:3000")]
    pub server: String,
    /// 轮询间隔(秒,默认1)
    #[arg(short, long, default_value_t = 1)]
    pub interval: u64,
    /// 最多显示N条后退出(0表示持续)
    #[arg(long, default_value_t = 0)]
    pub max: usize,
    /// 输出 JSONL(每行一条告警),管道/jq/SIEM 消费用
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub async fn run(args: &WatchArgs) -> Result<()> {
    let url = format!(
        "{}/api/v1/alerts?limit=20",
        args.server.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()?;

    let json_mode = args.json;
    if !json_mode {
        banner(&format!("实时告警监控 — 每 {}s 轮询", args.interval));
        println!("  数据源: {}", url.dimmed());
        println!("  按 Ctrl+C 停止");
        println!();
    }

    let mut seen: HashSet<uuid::Uuid> = HashSet::new();
    let mut count: usize = 0;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if !json_mode {
                    println!();
                    println!("停止监控 (共显示 {} 条新告警)", count);
                }
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(args.interval)) => {
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        let alerts: Vec<Alert> = match resp.json().await {
                            Ok(a) => a,
                            Err(e) => {
                                eprintln!("  [warn] JSON 解析失败: {}", e);
                                continue;
                            }
                        };
                        for a in &alerts {
                            if seen.insert(a.id) {
                                count += 1;
                                if json_mode {
                                    // JSONL:每行一条告警,喂 jq/SIEM/其他系统
                                    if let Ok(s) = serde_json::to_string(a) {
                                        println!("{s}");
                                    }
                                } else {
                                    let mitre = a.mitre.as_ref()
                                        .map(|m| format!(" | MITRE {}/{}", m.tactic, m.technique))
                                        .unwrap_or_default();
                                    let ts = chrono::Local::now().format("%H:%M:%S");
                                    println!(
                                        "  {} {} {} — PID {}{}",
                                        ts.to_string().dimmed(),
                                        severity_badge(&a.severity),
                                        a.title.bold(),
                                        a.process.pid,
                                        mitre.dimmed()
                                    );
                                }
                                if args.max > 0 && count >= args.max {
                                    if !json_mode {
                                        println!();
                                        println!("已达 --max {} 上限，停止监控", args.max);
                                    }
                                    return Ok(());
                                }
                            }
                        }
                    }
                    Ok(resp) => {
                        eprintln!("  [warn] HTTP {}", resp.status());
                    }
                    Err(e) => {
                        eprintln!("  [warn] 连接失败: {} (ks-server 未启动?)", e);
                    }
                }
            }
        }
    }
    Ok(())
}

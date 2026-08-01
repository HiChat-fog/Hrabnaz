//! `kernelsentinel baseline`子命令,查看各进程的z-score行为基线快照。
//!
//! 通过HTTP GET /api/v1/baselines拉取ServerState中的基线快照(由start.rs在周期触发时推送),以表格形式展示各进程的六维基线(均值和标准差)。

use anyhow::Result;
use ks_engine::baseline::BehaviorBaseline;

#[derive(clap::Args, Debug)]
pub struct BaselineArgs {
    /// ks-server地址(默认本机3000)
    #[arg(short, long, default_value = "http://127.0.0.1:3000")]
    pub server: String,
    /// 输出JSON而非表格
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub async fn run(args: &BaselineArgs) -> Result<()> {
    let url = format!("{}/api/v1/baselines", args.server.trim_end_matches('/'));
    let resp = reqwest::get(&url).await?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {} 失败: HTTP {}", url, resp.status());
    }
    let baselines: Vec<BehaviorBaseline> = resp.json().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&baselines)?);
        return Ok(());
    }

    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║  z-score 行为基线快照 — {:<6} 条", baselines.len());
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    if baselines.is_empty() {
        println!("  (无基线数据 — 需启动 `kernelsentinel start --serve <port>` 并产生事件)");
        return Ok(());
    }

    println!(
        "  {:<8} {:<16} {:<8} {:<10} {:<24}",
        "PID", "COMM", "样本数", "已建立", "syscall μ/σ"
    );
    println!(
        "  {} {} {} {} {}",
        "─".repeat(8),
        "─".repeat(16),
        "─".repeat(8),
        "─".repeat(10),
        "─".repeat(24)
    );

    for b in &baselines {
        let established = if b.established_at_ns > 0 {
            "✓"
        } else {
            "训练中"
        };
        let high_freq = if b.is_inherently_high_freq {
            " [高频]"
        } else {
            ""
        };
        println!(
            "  {:<8} {:<16} {:<8} {:<10} {:.1}/{:.2}{}",
            b.pid,
            b.comm,
            b.sample_count,
            established,
            b.syscall_baseline.mean,
            b.syscall_baseline.stddev,
            high_freq
        );
    }

    println!();
    println!("提示: 六维基线 = syscall / file_ops / net_ops / dns_ops / ptrace / signal");
    println!("      z>2σ 低风险偏离 / z>3σ 中等 / z>5σ 严重（详见 /api/v1/baselines JSON）");
    Ok(())
}

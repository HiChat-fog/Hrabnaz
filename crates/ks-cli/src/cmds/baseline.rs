use anyhow::Result;
use ks_engine::baseline::BehaviorBaseline;
use colored::Colorize;
use super::ui::{banner, new_table};

#[derive(clap::Args, Debug)]
pub struct BaselineArgs {
    #[arg(short, long, default_value = "http://127.0.0.1:3000")]
    pub server: String,
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

    banner(&format!("z-score 行为基线快照 — {} 条", baselines.len()));
    println!();

    if baselines.is_empty() {
        println!("  (无基线数据 — 需启动 `kernelsentinel start --serve <port>` 并产生事件)");
        return Ok(());
    }

    let mut t = new_table();
    t.set_header(vec!["PID", "COMM", "样本数", "已建立", "syscall μ/σ", "标记"]);
    for b in &baselines {
        let established = if b.established_at_ns > 0 {
            "✓".to_string().green()
        } else {
            "训练中".to_string().yellow()
        };
        let high_freq = if b.is_inherently_high_freq {
            "高频".to_string()
        } else {
            "".to_string()
        };
        t.add_row(vec![
            b.pid.to_string(),
            b.comm.clone(),
            b.sample_count.to_string(),
            established.to_string(),
            format!("{:.1}/{:.2}", b.syscall_baseline.mean, b.syscall_baseline.stddev),
            high_freq,
        ]);
    }
    println!("{t}");

    println!();
    println!("提示: 六维基线 = syscall / file_ops / net_ops / dns_ops / ptrace / signal");
    println!("      z>2σ 低风险偏离 / z>3σ 中等 / z>5σ 严重（详见 /api/v1/baselines JSON）");
    Ok(())
}

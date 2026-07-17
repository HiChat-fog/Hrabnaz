//! G1.3: `kernelsentinel correlation` 子命令 — 查看最近的跨事件关联告警。
//!
//! 通过 HTTP GET /api/v1/correlations 拉取 ServerState 中的关联告警存储
//! （由 start.rs 在 correlation_engine 产生告警时推送）。
//!
//! 申报书承诺的 8 个 CLI 子命令之一。

use anyhow::Result;
use ks_engine::correlation::CorrelationAlert;

#[derive(clap::Args, Debug)]
pub struct CorrelationArgs {
    /// ks-server 地址
    #[arg(short, long, default_value = "http://127.0.0.1:3000")]
    pub server: String,
    /// 拉取条数（默认 50）
    #[arg(short, long, default_value_t = 50)]
    pub limit: usize,
    /// 输出 JSON
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

pub async fn run(args: &CorrelationArgs) -> Result<()> {
    let url = format!(
        "{}/api/v1/correlations?limit={}",
        args.server.trim_end_matches('/'),
        args.limit
    );
    let resp = reqwest::get(&url).await?;
    if !resp.status().is_success() {
        anyhow::bail!("GET {} 失败: HTTP {}", url, resp.status());
    }
    let alerts: Vec<CorrelationAlert> = resp.json().await?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&alerts)?);
        return Ok(());
    }

    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║  跨事件关联告警 — {:<6} 条", alerts.len());
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    if alerts.is_empty() {
        println!("  (无关联告警 — 需启动监控并触发多步攻击场景)");
        println!("  示例: 读 /etc/shadow 后外连 4444 → 数据窃取 Window 关联");
        return Ok(());
    }

    for (i, a) in alerts.iter().enumerate() {
        let mitre = a
            .mitre
            .as_ref()
            .map(|m| format!("{}/{}", m.tactic, m.technique))
            .unwrap_or_else(|| "-".to_string());
        let evt_count = a.events.len();
        println!(
            "  [{:>3}] [{}] {} — 置信度 {:.0}% ({} 事件)",
            i + 1,
            a.severity,
            a.rule_name,
            a.confidence * 100.0,
            evt_count
        );
        println!("        描述: {}", a.description);
        println!("        MITRE: {}", mitre);
    }

    println!();
    println!("提示: 关联引擎三模式 = Window（时间窗配对）/ Sequence（步骤序列）/ ProcessTree（父子进程）");
    Ok(())
}

use anyhow::Result;
use ks_core::event::DecodedEvent;
use ks_engine::correlation::{CorrelationAlert, CorrelationEngine};
use ks_engine::process_tree::ProcessTreeManager;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use super::ui::{banner, severity_colored};
use colored::Colorize;

/// 关联告警收集上限：每条告警携带事件克隆（~KB 级），2 万条 ≈ 数十 MB，
/// 防误报洪峰把离线回放吃爆内存
const MAX_ALERTS: usize = 20_000;

#[derive(clap::Args, Debug)]
pub struct CorrelationArgs {
    /// 取证日志目录（events_*.jsonl 所在处）
    #[arg(short = 'L', long, default_value = "/var/log/ks")]
    pub log_dir: String,
    /// 最多输出 N 条关联告警
    #[arg(short, long, default_value_t = 50)]
    pub limit: usize,
    /// 机器可读输出（单行 JSON 对象）
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// 把 forensic JSONL 的事件记录还原回 DecodedEvent（字段与 log_event 落盘一一对应）
fn record_to_event(v: &serde_json::Value) -> Option<DecodedEvent> {
    let mut cb = [0u8; 16];
    let comm = v.get("comm").and_then(|x| x.as_str()).unwrap_or("?");
    let len = comm.len().min(16);
    cb[..len].copy_from_slice(&comm.as_bytes()[..len]);

    let get_u64 = |k: &str| v.get(k).and_then(|x| x.as_u64());
    let get_opt = |k: &str| {
        v.get(k)
            .filter(|x| !x.is_null())
            .and_then(|x| x.as_u64())
            .map(|x| x as u32)
    };

    Some(DecodedEvent {
        seq: get_u64("seq").unwrap_or(0),
        header: ks_core::event::EventHeader {
            event_type: get_u64("event_type").unwrap_or(0) as u32,
            _pad1: 0,
            timestamp_ns: get_u64("timestamp_ns").unwrap_or(0),
            pid: get_u64("pid").unwrap_or(0) as u32,
            tid: get_u64("tid").unwrap_or(0) as u32,
            uid: get_u64("uid").unwrap_or(0) as u32,
            ppid: get_u64("ppid").unwrap_or(0) as u32,
            comm: cb,
            syscall_nr: get_u64("syscall_nr").unwrap_or(0) as i32,
            _pad2: 0,
            retval: v.get("retval").and_then(|x| x.as_i64()).unwrap_or(0),
        },
        comm: comm.to_string(),
        filename: v
            .get("filename")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        args: v
            .get("args")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        saddr: v
            .get("saddr")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        daddr: v
            .get("daddr")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        sport: get_opt("sport").map(|x| x as u16),
        dport: get_opt("dport").map(|x| x as u16),
        proto: v
            .get("proto")
            .and_then(|x| x.as_str())
            .map(|s| s.to_string()),
        target_pid: get_opt("target_pid"),
        signal: v.get("signal").and_then(|x| x.as_i64()).map(|x| x as i32),
        file_bytes: v.get("file_bytes").and_then(|x| x.as_u64()),
        module_name: None,
        prog_name: None,
        source_ns_inum: None,
        target_ns_inum: None,
        cap_eff: None,
        action: None,
    })
}

fn latest_events_jsonl(dir: &str) -> Result<Option<std::path::PathBuf>> {
    let mut candidates: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(anyhow::Error::from)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("events_") && n.ends_with(".jsonl"))
        })
        .collect();
    candidates.sort();
    Ok(candidates.pop())
}

pub async fn run(args: &CorrelationArgs) -> Result<()> {
    let latest = latest_events_jsonl(&args.log_dir)?;
    let path = latest.unwrap_or_else(|| Path::new(&args.log_dir).join("events_<date>.jsonl"));
    if !path.exists() {
        anyhow::bail!(
            "{} 下没有 events_*.jsonl — 先运行 kernelsentinel start 产生日志",
            args.log_dir
        );
    }

    // 与 start 主循环同构：事件按序喂给关联引擎 + 进程树管理器，离线重算跨事件关联
    let mut corr_engine = CorrelationEngine::new(300);
    let mut pt_mgr = ProcessTreeManager::new();
    let mut alerts: VecDeque<CorrelationAlert> = VecDeque::new();
    let mut truncated = false;
    let mut event_count: u64 = 0;

    let file = File::open(&path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.is_empty() || line.contains("\"type\":\"alert\"") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let Some(event) = record_to_event(&v) else {
            continue;
        };
        event_count += 1;
        pt_mgr.update_from_event(&event);
        let ca_list = corr_engine.detect_correlations_with_tree(&event, Some(&pt_mgr));
        for ca in ca_list {
            if alerts.len() >= MAX_ALERTS {
                truncated = true;
                break;
            }
            alerts.push_back(ca);
        }
        if truncated {
            break;
        }
    }

    let total = alerts.len();
    let alerts: Vec<CorrelationAlert> = alerts
        .into_iter()
        .rev()
        .take(args.limit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();

    if args.json {
        println!("{}", serde_json::to_string_pretty(&alerts)?);
        return Ok(());
    }

    banner(&format!(
        "跨事件关联告警（离线重放） — 最近 {} / 共 {} 条",
        alerts.len(),
        total
    ));
    println!(
        "  数据源: {} ({} 事件)",
        path.display().to_string().dimmed(),
        event_count
    );
    if truncated {
        println!(
            "  {} 关联告警超过 {} 条，仅保留最早 {} 条",
            "[WARN]".yellow(),
            MAX_ALERTS,
            MAX_ALERTS
        );
    }
    println!();

    if alerts.is_empty() {
        println!("  (无关联告警 — 日志里没有触发多步攻击场景)");
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
            "  {} {} {} — 置信度 {:.0}% ({} 事件)",
            format!("#{:<3}", i + 1).dimmed(),
            severity_colored(&format!("[{}]", a.severity), &a.severity),
            a.rule_name.bold(),
            a.confidence * 100.0,
            evt_count
        );
        println!("        {} {}", "描述:".dimmed(), a.description);
        println!("        {} {}", "MITRE:".dimmed(), mitre);
    }

    println!();
    println!("提示: 关联引擎三模式 = Window（时间窗配对）/ Sequence（步骤序列）/ ProcessTree（父子进程）");
    Ok(())
}

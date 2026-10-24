use anyhow::Result;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

use colored::Colorize;
use super::ui::{banner, new_table};

/// 与引擎侧 BaselineManager 对齐的离线近似参数：
/// 引擎按 60s 窗口计数、连续 5 个非平凡窗口(min_samples)后判定基线建立
const WINDOW_SECS: u64 = 60;
const MIN_SAMPLES: u64 = 5;
/// 60s 窗口均值超过该值视为天然高频进程（引擎按 comm 白名单判定，离线无法还原名单）
const HIGH_FREQ_MEAN: f64 = 100.0;

#[derive(clap::Args, Debug)]
pub struct BaselineArgs {
    /// 取证日志目录（events_*.jsonl 所在处）
    #[arg(short, long, default_value = "/var/log/ks")]
    pub log_dir: String,
    /// 机器可读输出（单行 JSON 对象）
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

#[derive(Default)]
struct PidAgg {
    comm: String,
    sample_count: u64,
    first_ts: u64,
    /// 每 60s 窗口的 syscall 计数（窗口号 → 计数）
    buckets: BTreeMap<u64, u64>,
}

pub async fn run(args: &BaselineArgs) -> Result<()> {
    let latest = latest_events_jsonl(&args.log_dir)?;
    let path = latest.unwrap_or_else(|| {
        Path::new(&args.log_dir).join("events_<date>.jsonl")
    });
    if !path.exists() {
        anyhow::bail!("{} 下没有 events_*.jsonl — 先运行 kernelsentinel start 产生日志", args.log_dir);
    }

    let mut aggs: BTreeMap<u32, PidAgg> = BTreeMap::new();
    let file = File::open(&path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.is_empty() || line.contains("\"type\":\"alert\"") {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let Some(pid) = v.get("pid").and_then(|x| x.as_u64()) else {
            continue;
        };
        let ts = v.get("timestamp_ns").and_then(|x| x.as_u64()).unwrap_or(0);
        let comm = v
            .get("comm")
            .and_then(|x| x.as_str())
            .unwrap_or("?")
            .to_string();
        let agg = aggs.entry(pid as u32).or_default();
        agg.comm = comm;
        agg.sample_count += 1;
        if agg.first_ts == 0 || ts < agg.first_ts {
            agg.first_ts = ts;
        }
        let window = ts / 1_000_000_000 / WINDOW_SECS;
        *agg.buckets.entry(window).or_insert(0) += 1;
    }

    let mut rows: Vec<(u32, String, u64, bool, f64, f64, bool)> = Vec::new();
    for (pid, agg) in &aggs {
        // 只统计非平凡窗口（count>1），与引擎 established 判定一致
        let completed: Vec<f64> = agg
            .buckets
            .values()
            .filter(|c| **c > 1)
            .map(|c| *c as f64)
            .collect();
        let established = completed.len() as u64 >= MIN_SAMPLES;
        let (mean, stddev) = if completed.is_empty() {
            (0.0, 0.0)
        } else {
            let m = completed.iter().sum::<f64>() / completed.len() as f64;
            let var = completed.iter().map(|c| (c - m).powi(2)).sum::<f64>()
                / completed.len() as f64;
            (m, var.sqrt())
        };
        let high_freq = mean > HIGH_FREQ_MEAN;
        rows.push((
            *pid,
            agg.comm.clone(),
            agg.sample_count,
            established,
            mean,
            stddev,
            high_freq,
        ));
    }
    rows.sort_by_key(|(_, _, samples, _, _, _, _)| std::cmp::Reverse(*samples));

    if args.json {
        let arr: Vec<serde_json::Value> = rows
            .iter()
            .map(|(pid, comm, samples, est, mean, std, hf)| {
                serde_json::json!({
                    "pid": pid,
                    "comm": comm,
                    "sample_count": samples,
                    "established": est,
                    "syscall_per_60s": { "mean": (mean * 100.0).round() / 100.0, "stddev": (std * 100.0).round() / 100.0 },
                    "is_inherently_high_freq": hf,
                    "source": path.display().to_string(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }

    banner(&format!(
        "z-score 行为基线（离线统计） — {} 个进程",
        rows.len()
    ));
    println!("  数据源: {}", path.display().to_string().dimmed());
    println!();

    if rows.is_empty() {
        println!("  (日志里没有事件记录 — 先启动 kernelsentinel start 并产生事件)");
        return Ok(());
    }

    let mut t = new_table();
    t.set_header(vec!["PID", "COMM", "样本数", "已建立", "syscall 次/60s μ/σ", "标记"]);
    for (pid, comm, samples, established, mean, stddev, high_freq) in &rows {
        let established = if *established {
            "✓".to_string().green()
        } else {
            "训练中".to_string().yellow()
        };
        let high_freq = if *high_freq {
            "高频".to_string()
        } else {
            "".to_string()
        };
        t.add_row(vec![
            pid.to_string(),
            comm.clone(),
            samples.to_string(),
            established.to_string(),
            format!("{:.1}/{:.2}", mean, stddev),
            high_freq,
        ]);
    }
    println!("{t}");

    println!();
    println!(
        "提示: 离线统计按 {}s 窗口重算 syscall 频率, 基线建立 = ≥{} 个非平凡窗口 (引擎同款判定)",
        WINDOW_SECS, MIN_SAMPLES
    );
    println!("      z>2σ 低风险偏离 / z>3σ 中等 / z>5σ 严重");
    Ok(())
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

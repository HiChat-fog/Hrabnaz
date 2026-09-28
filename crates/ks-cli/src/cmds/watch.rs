use anyhow::Result;
use ks_core::alert::Alert;
use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;

use super::ui::{banner, severity_badge};
use colored::Colorize;

/// seen 集合上限：只增不减的 HashSet 在长跑 watch 里会缓慢膨胀
const SEEN_CAP: usize = 10000;
/// 启动时回显日志中已有的最近 N 条告警（对齐旧版轮询 limit=20 的首屏行为）
const SEED_LIMIT: usize = 20;

#[derive(clap::Args, Debug)]
pub struct WatchArgs {
    /// 取证日志目录（start --log-dir 的值，events_*.jsonl 所在处）
    #[arg(short, long, default_value = "/var/log/ks")]
    pub log_dir: String,
    #[arg(short, long, default_value_t = 1)]
    pub interval: u64,
    #[arg(long, default_value_t = 0)]
    pub max: usize,
    #[arg(long, default_value_t = false)]
    pub json: bool,
}

/// 目录里最新的 events_*.jsonl（文件名带日期，排序即时间序，轮转/换日自动跟上）
fn latest_log(dir: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("events_") && n.ends_with(".jsonl"))
        })
        .collect();
    candidates.sort();
    candidates.pop()
}

fn print_alert(a: &Alert) {
    let mitre = a
        .mitre
        .as_ref()
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

/// 从一行 JSON 解析告警：子串预筛避免全量 JSON parse，剥离 forensic 附加字段后再反序列化
fn parse_alert_line(line: &str) -> Option<Alert> {
    if !line.contains("\"type\":\"alert\"") {
        return None;
    }
    let mut v: serde_json::Value = serde_json::from_str(line).ok()?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("type");
        obj.remove("prev_hash");
        obj.remove("hash");
    }
    serde_json::from_value(v).ok()
}

/// 自 offset 起读完整行，返回 (消费的字节数, 完整行列表)。
/// 半截行（正在写入）不消费，留待下次 tail。
fn read_new_lines(file: &mut File, offset: u64) -> Result<(u64, Vec<String>)> {
    file.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(file);
    let mut consumed = 0u64;
    let mut lines = Vec::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        if buf.last() != Some(&b'\n') {
            break;
        }
        consumed += n as u64;
        buf.pop();
        lines.push(String::from_utf8_lossy(&buf).into_owned());
    }
    Ok((consumed, lines))
}

pub async fn run(args: &WatchArgs) -> Result<()> {
    let json_mode = args.json;
    if !json_mode {
        banner(&format!(
            "实时告警监控 — 每 {}s 轮询取证日志",
            args.interval
        ));
        println!("  日志目录: {}", args.log_dir.dimmed());
        println!("  按 Ctrl+C 停止");
        println!();
    }

    let mut seen: HashSet<uuid::Uuid> = HashSet::new();
    let mut seen_order: VecDeque<uuid::Uuid> = VecDeque::new();
    let mut count: usize = 0;
    let mut tracked: Option<(PathBuf, u64)> = None;

    // 启动时流式扫描日志：只保留最近 N 条告警用于回显 + 全量 id 进 seen（防 tail 重复），
    // 不整文件驻留内存（长跑日志可达百 MB 级）
    if let Some(path) = latest_log(&args.log_dir) {
        let mut total = 0usize;
        let mut recent: VecDeque<Alert> = VecDeque::new();
        let mut end_offset = 0u64;
        if let Ok(mut file) = File::open(&path) {
            let mut reader = BufReader::new(&mut file);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        end_offset += n as u64;
                        if let Some(a) = parse_alert_line(line.trim_end_matches(['\n', '\r'])) {
                            total += 1;
                            if seen.insert(a.id) {
                                seen_order.push_back(a.id);
                                if seen_order.len() > SEEN_CAP {
                                    if let Some(old) = seen_order.pop_front() {
                                        seen.remove(&old);
                                    }
                                }
                            }
                            if recent.len() == SEED_LIMIT {
                                recent.pop_front();
                            }
                            recent.push_back(a);
                        }
                    }
                }
            }
        }
        tracked = Some((path.clone(), end_offset));
        if total > 0 && !json_mode {
            println!("  已有 {} 条历史告警，回显最近 {} 条:", total, recent.len());
            for a in &recent {
                print_alert(a);
            }
            println!();
        }
    } else if !json_mode {
        println!(
            "  ({} 下暂无 events_*.jsonl — start 产生日志后自动跟上)",
            args.log_dir
        );
    }

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
                // 轮转/换日：最新文件变化则切过去从头读
                if let Some(latest) = latest_log(&args.log_dir) {
                    let need_reset = match &tracked {
                        Some((p, _)) => *p != latest,
                        None => true,
                    };
                    if need_reset {
                        tracked = Some((latest, 0));
                    }
                }
                let Some((path, offset)) = tracked.as_mut() else {
                    continue;
                };
                let Ok(mut file) = File::open(&*path) else {
                    continue;
                };
                let (consumed, lines) = match read_new_lines(&mut file, *offset) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                *offset += consumed;
                for line in &lines {
                    let Some(a) = parse_alert_line(line) else {
                        continue;
                    };
                    if !seen.insert(a.id) {
                        continue;
                    }
                    seen_order.push_back(a.id);
                    if seen_order.len() > SEEN_CAP {
                        if let Some(old) = seen_order.pop_front() {
                            seen.remove(&old);
                        }
                    }
                    count += 1;
                    if json_mode {
                        if let Ok(s) = serde_json::to_string(&a) {
                            println!("{s}");
                        }
                    } else {
                        print_alert(&a);
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
    }
    Ok(())
}

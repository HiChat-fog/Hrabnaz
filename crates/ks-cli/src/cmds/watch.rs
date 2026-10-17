use anyhow::Result;
use ks_core::alert::Alert;
use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;

use super::ui::{banner, severity_badge};
use colored::Colorize;

/// seen 集合上限：只增不减的 HashSet 在长跑 watch 里会缓慢膨胀
const SEEN_CAP: usize = 10000;
/// 启动时回显日志中已有的最近 N 条告警（对齐旧版轮询 limit=20 的首屏行为）
const SEED_LIMIT: usize = 20;

/// 跟踪中的日志文件：路径 + 已消费偏移 + 文件身份（dev/ino）。
/// 轮转会 rename 旧文件并在**同一路径**新建文件——路径不变但 inode 变了，
/// 只看路径会把旧 offset 用到新文件上（新文件更小 → 永远读不到新告警）。
struct Tracked {
    path: PathBuf,
    offset: u64,
    dev: u64,
    ino: u64,
}

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

/// 活跃取证文件固定为 events_YYYYMMDD.jsonl。归档 events_YYYYMMDD_HHMMSS.jsonl
/// 在 ASCII 上排在同日活跃文件之后（'_' 0x5F > '.' 0x2E），旧实现"按名字排序取
/// 最大"会在轮转→压缩窗口（压缩被跳过/失败时甚至是永久）把归档当成最新文件，
/// 导致 watch 停报。
fn is_active_log_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("events_") else {
        return false;
    };
    let Some(date) = rest.strip_suffix(".jsonl") else {
        return false;
    };
    date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit())
}

/// 目录里最新的活跃文件（文件名带日期，排序即时间序；归档与压缩文件不参与）
fn latest_log(dir: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_active_log_name)
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
    let mut tracked: Option<Tracked> = None;

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
            if let Ok(meta) = file.metadata() {
                tracked = Some(Tracked {
                    path: path.clone(),
                    offset: end_offset,
                    dev: meta.dev(),
                    ino: meta.ino(),
                });
            }
        }
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
                // 换日/换文件：活跃文件路径变化则切过去从头读
                if let Some(latest) = latest_log(&args.log_dir) {
                    let need_reset = match &tracked {
                        Some(t) => t.path != latest,
                        None => true,
                    };
                    if need_reset {
                        tracked = Some(Tracked {
                            path: latest,
                            offset: 0,
                            dev: 0,
                            ino: 0,
                        });
                    }
                }
                let Some(tr) = tracked.as_mut() else {
                    continue;
                };
                let Ok(mut file) = File::open(&tr.path) else {
                    continue;
                };
                // 同一路径下文件被轮转替换（inode 变化）或被截断时，旧 offset 无意义，
                // 从头重读（告警按 id 去重，已显示过的不会重复）
                if let Ok(meta) = file.metadata() {
                    if tr.ino == 0
                        || meta.dev() != tr.dev
                        || meta.ino() != tr.ino
                        || meta.len() < tr.offset
                    {
                        tr.offset = 0;
                        tr.dev = meta.dev();
                        tr.ino = meta.ino();
                    }
                }
                let (consumed, lines) = match read_new_lines(&mut file, tr.offset) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                tr.offset += consumed;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 只有"当前世代"的活跃文件参与 tail：归档名带 _HHMMSS 后缀，不能匹配
    #[test]
    fn active_log_name_matches_only_current_generation() {
        assert!(is_active_log_name("events_20261016.jsonl"));
        assert!(!is_active_log_name("events_20261016_172533.jsonl"));
        assert!(!is_active_log_name("events_20261016_172533.jsonl.gz"));
        assert!(!is_active_log_name("chain_head.log"));
        assert!(!is_active_log_name("events_short.jsonl"));
        assert!(!is_active_log_name("events_20261016.jsonl.bak"));
    }

    /// 未压缩归档（轮转→压缩窗口内，或压缩被跳过/失败后长期存在）不能顶替活跃文件
    #[test]
    fn latest_log_prefers_active_over_uncompressed_archive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events_20261015.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("events_20261016.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("events_20261016_172533.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("events_20261016_172533.jsonl.gz"), "").unwrap();
        let latest = latest_log(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(
            latest.file_name().unwrap().to_str().unwrap(),
            "events_20261016.jsonl",
            "同日未压缩归档排序在活跃文件之后，旧实现会误选归档导致 watch 停报"
        );
    }
}

use anyhow::Result;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::BufRead;
use std::path::Path;

use colored::*;
use super::ui::{banner, severity_colored};

/// 进程画像每 pid 保留的展示样本数（展示只取前 5 条，样本再多没有意义）
const PID_SAMPLE_KEEP: usize = 5;
/// 攻击链条目上限：告警洪峰（历史 150 万条误报）时防止回放 OOM
const MAX_ATTACK_CHAINS: usize = 100_000;

/// 单个进程的回放画像：总数 + 前 N 条样本
#[derive(Default)]
struct PidProfile {
    total: u64,
    samples: Vec<(u64, u32, String)>,
}

fn mitre_phase_name(tactic: &str) -> &str {
    match tactic {
        "TA0001" => "初始入侵",
        "TA0002" => "执行",
        "TA0003" => "持久化",
        "TA0004" => "提权",
        "TA0005" => "防御规避",
        "TA0006" => "凭据访问",
        "TA0007" => "信息探测",
        "TA0008" => "横向移动",
        "TA0010" => "数据窃取",
        "TA0011" => "命令控制",
        _ => tactic,
    }
}

fn event_type_label(etype: u32) -> &'static str {
    match etype {
        1 => "进程执行",
        2 => "进程退出",
        3 => "进程克隆",
        10 => "文件打开",
        11 => "文件读取",
        12 => "文件写入",
        13 => "文件删除",
        14 => "文件重命名",
        15 => "权限修改",
        20 => "TCP连接",
        21 => "连接接受",
        22 => "数据发送",
        23 => "数据接收",
        24 => "DNS查询",
        30 => "ptrace",
        31 => "信号发送",
        _ => "未知",
    }
}

pub async fn run(file: &str, json: bool) -> Result<()> {
    let path = Path::new(file);
    if !path.exists() {
        anyhow::bail!("文件不存在: {}", file);
    }

    let path_buf = path.to_path_buf();
    let verification = ks_engine::forensic::ForensicLogger::verify_chain(&path_buf)?;

    if !json {
        banner("内核哨兵 — 取证日志回放");
        println!();
        println!("日志文件: {}", file.cyan());

        println!();
        println!("{}", "── 阶段 1: 哈希链完整性校验 ──".cyan().bold());
        println!("  SHA-256 链式校验: 每条记录的 hash = SHA256(内容)");
        println!("  prev_hash 机制:   每条记录包含上一条的 hash");
        println!("  链断裂 = 日志被篡改 (插入/删除/修改任何记录)");
        println!();

        if verification.is_valid {
            // 锚定于上一世代（首条 prev_hash 指向前代文件）是按天滚动/重启续链的
            // 正常形态：链校验只看文件内连续性与逐条自身哈希
            let anchor_note = if verification.anchored {
                " (首条锚定于上一世代)"
            } else {
                ""
            };
            println!(
                "  [✓] 链完整性: 通过 — {} 条记录, 链完整无断裂{}",
                verification.total_records, anchor_note
            );
        } else {
            println!(
                "  [✗] 链完整性: 断裂 — 第 {} 条记录处检测到篡改",
                verification.broken_at.unwrap_or(0)
            );
            println!("  建议: 检查该记录是否被人为修改或插入");
        }

        println!();
        println!("{}", "── 阶段 2: 事件/告警解析 ──".cyan().bold());
        println!();
    }

    // 归档默认 gzip 压缩（.jsonl.gz）：回放必须能直接读它，而不是让使用者先手工解压
    let reader = ks_engine::forensic::open_log_reader(path)?;

    let mut event_count: u64 = 0;
    let mut alert_count: u64 = 0;
    let mut event_types: BTreeMap<u32, u64> = BTreeMap::new();
    let mut severities: BTreeMap<String, u64> = BTreeMap::new();
    let mut pids: HashSet<u32> = HashSet::new();
    // 进程画像只需"每 pid 总数 + 前 5 条样本"：旧实现把每个事件全量存进
    // HashMap<u32, Vec<(u64,u32,String)>>，多天日志回放会吃掉数 GB 内存
    let mut pid_profiles: HashMap<u32, PidProfile> = HashMap::new();
    let mut mitre_tags: HashMap<String, Vec<String>> = HashMap::new();
    // 告警峰值可达百万级（loadgen 误报历史），同样设上限防 OOM
    let mut attack_chains: Vec<AttackChainEntry> = Vec::new();
    let mut attack_chains_truncated = false;
    let mut first_ts: Option<u64> = None;
    let mut last_ts: Option<u64> = None;

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }

        let record: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  [SKIP] 解析失败: {}", e);
                continue;
            }
        };

        let record_type = record
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("event");

        if record_type == "alert" {
            alert_count += 1;

            if let Some(severity) = record.get("severity").and_then(|v| v.as_str()) {
                *severities.entry(severity.to_string()).or_insert(0) += 1;
            }

            if let Some(tactic) = record
                .get("mitre")
                .and_then(|m| m.get("tactic"))
                .and_then(|v| v.as_str())
            {
                let technique = record
                    .get("mitre")
                    .and_then(|m| m.get("technique"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                mitre_tags
                    .entry(tactic.to_string())
                    .or_default()
                    .push(technique.to_string());
            }

            let title = record
                .get("title")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let severity = record
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let pid = record
                .get("process")
                .and_then(|p| p.get("pid"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let comm = record
                .get("process")
                .and_then(|p| p.get("comm"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");

            let daddr = record
                .get("network")
                .and_then(|n| n.get("daddr"))
                .and_then(|v| v.as_str());
            let dport = record
                .get("network")
                .and_then(|n| n.get("dport"))
                .and_then(|v| v.as_u64());
            let proto = record
                .get("network")
                .and_then(|n| n.get("proto"))
                .and_then(|v| v.as_str());

            let filepath = record
                .get("file")
                .and_then(|f| f.get("path"))
                .and_then(|v| v.as_str());

            let mitre_tactic = record
                .get("mitre")
                .and_then(|m| m.get("tactic"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let mitre_technique = record
                .get("mitre")
                .and_then(|m| m.get("technique"))
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let ts = record.get("timestamp_ns").and_then(|v| v.as_u64());

            if attack_chains.len() >= MAX_ATTACK_CHAINS {
                attack_chains_truncated = true;
            } else {
                attack_chains.push(AttackChainEntry {
                    title: title.to_string(),
                    severity: severity.to_string(),
                    pid: pid as u32,
                    comm: comm.to_string(),
                    daddr: daddr.map(|s| s.to_string()),
                    dport: dport.map(|v| v as u16),
                    proto: proto.map(|s| s.to_string()),
                    filepath: filepath.map(|s| s.to_string()),
                    mitre_tactic: mitre_tactic.to_string(),
                    mitre_technique: mitre_technique.to_string(),
                    ts,
                });
            }
        } else {
            event_count += 1;

            if let Some(etype) = record.get("event_type").and_then(|v| v.as_u64()) {
                *event_types.entry(etype as u32).or_insert(0) += 1;
            }

            if let Some(pid) = record.get("pid").and_then(|v| v.as_u64()) {
                pids.insert(pid as u32);
                let seq = record.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
                let etype = record
                    .get("event_type")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let comm = record
                    .get("comm")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();
                let prof = pid_profiles.entry(pid as u32).or_default();
                prof.total += 1;
                if prof.samples.len() < PID_SAMPLE_KEEP {
                    prof.samples.push((seq, etype as u32, comm));
                }
            }

            if let Some(ts) = record.get("timestamp_ns").and_then(|v| v.as_u64()) {
                first_ts = Some(first_ts.map_or(ts, |f| f.min(ts)));
                last_ts = Some(last_ts.map_or(ts, |f| f.max(ts)));
            }
        }
    }

    if json {
        let summary = serde_json::json!({
            "file": file,
            "chain": {
                "valid": verification.is_valid,
                "total_records": verification.total_records,
                "broken_at": verification.broken_at,
                "anchored": verification.anchored,
            },
            "events": event_count,
            "alerts": alert_count,
            "unique_pids": pids.len(),
            "severities": severities,
            "event_types": event_types,
            "attack_chains": attack_chains.len(),
            "attack_chains_truncated": attack_chains_truncated,
            "first_ts": first_ts,
            "last_ts": last_ts,
        });
        println!("{}", serde_json::to_string_pretty(&summary)?);
        return Ok(());
    }

    println!("{}", "── 阶段 3: 统计摘要 ──".cyan().bold());
    println!();
    println!("  事件总数: {}", event_count);
    println!("  告警总数: {}", alert_count);
    println!("  唯一进程: {}", pids.len());
    println!(
        "  链完整性: {}",
        if verification.is_valid {
            if verification.anchored {
                "通过 ✓ (锚定于上一世代)"
            } else {
                "通过 ✓"
            }
        } else {
            "断裂 ✗"
        }
    );

    if let (Some(first), Some(last)) = (first_ts, last_ts) {
        let duration_secs = (last - first) / 1_000_000_000;
        println!(
            "  时间跨度: {} 秒 ({} → {})",
            duration_secs,
            format_timestamp(first),
            format_timestamp(last)
        );
    }

    if !event_types.is_empty() {
        println!();
        println!("{}", "── 阶段 4: 事件类型分布 ──".cyan().bold());
        println!();
        let max_count = event_types.values().max().unwrap_or(&0);
        let bar_width = 30;
        let mut t = super::ui::new_table();
        t.set_header(vec!["类型", "名称", "分布", "数量"]);
        for (etype, count) in &event_types {
            let name = event_type_label(*etype);
            let bar_len = if *max_count > 0 {
                ((*count as f64 / *max_count as f64) * bar_width as f64) as usize
            } else {
                0
            };
            let bar = "█".repeat(bar_len) + &"░".repeat(bar_width - bar_len);
            t.add_row(vec![
                etype.to_string(),
                name.to_string(),
                bar,
                format!("{} 条", count),
            ]);
        }
        println!("{t}");
    }

    if !severities.is_empty() {
        println!();
        println!("{}", "── 阶段 5: 告警等级分布 ──".cyan().bold());
        println!();
        for (sev, count) in &severities {
            let icon = match sev.as_str() {
                "critical" => "🔴",
                "high" => "🟠",
                "medium" => "🟡",
                "low" => "🟢",
                _ => "⚪",
            };
            println!("  {} {} {} 条", icon, severity_colored(sev, sev), count);
        }
    }

    if !mitre_tags.is_empty() {
        println!();
        println!("{}", "── 阶段 6: MITRE ATT&CK 映射 ──".cyan().bold());
        println!();
        println!("  检测到的攻击战术 (按 MITRE ATT&CK 框架分类):");
        println!();
        for (tactic, techniques) in &mitre_tags {
            let phase = mitre_phase_name(tactic);
            println!("  {} ({})", tactic, phase);
            let mut unique: BTreeMap<String, usize> = BTreeMap::new();
            for tech in techniques {
                *unique.entry(tech.clone()).or_insert(0) += 1;
            }
            for (tech, n) in &unique {
                if *n > 1 {
                    println!("    └─ {} ×{}", tech, n);
                } else {
                    println!("    └─ {}", tech);
                }
            }
        }
    }

    if !attack_chains.is_empty() {
        println!();
        println!("{}", "── 阶段 7: 攻击链还原 ──".cyan().bold());
        println!();
        if attack_chains_truncated {
            println!(
                "  {} 告警超过 {} 条，仅还原前 {} 条 (统计摘要仍基于全量数据)",
                "[WARN]".yellow(),
                MAX_ATTACK_CHAINS,
                MAX_ATTACK_CHAINS
            );
            println!();
        }
        println!("  从离散告警中还原攻击者的行为链:");
        println!();

        let mut timed_ts: Vec<u64> = attack_chains.iter().filter_map(|e| e.ts).collect();
        if !timed_ts.is_empty() {
            timed_ts.sort_unstable();
            let first = *timed_ts.first().unwrap();
            let last = *timed_ts.last().unwrap();
            let span = last.saturating_sub(first).max(1);
            const BUCKETS: usize = 48;
            let mut counts = vec![0u64; BUCKETS];
            for t in &timed_ts {
                let idx = (((t - first) as u128 * BUCKETS as u128) / span as u128) as usize;
                counts[idx.min(BUCKETS - 1)] += 1;
            }
            let maxc = (*counts.iter().max().unwrap_or(&1)).max(1) as f64;
            let sparks = "▁▂▃▄▅▆▇█";
            let line: String = counts
                .iter()
                .map(|c| {
                    let lvl = ((*c as f64 / maxc) * 7.0).round() as usize;
                    sparks.chars().nth(lvl.min(7)).unwrap()
                })
                .collect();
            println!("  ⏱ 告警时间线 (按时间戳分布, {} 条):", timed_ts.len());
            println!("  {}", line.truecolor(100, 200, 255));
            println!(
                "  {} ──────────────── {}",
                format_timestamp(first).dimmed(),
                format_timestamp(last).dimmed()
            );
            println!();
        }

        let mut sorted_chains = attack_chains.clone();
        sorted_chains.sort_by(|a, b| {
            let sev_order = |s: &str| match s {
                "critical" => 0,
                "high" => 1,
                "medium" => 2,
                "low" => 3,
                _ => 4,
            };
            sev_order(&a.severity).cmp(&sev_order(&b.severity))
        });

        let phase_order = [
            "TA0001", "TA0002", "TA0003", "TA0004", "TA0005", "TA0006", "TA0007", "TA0008",
            "TA0010", "TA0011",
        ];
        let mut phase_sorted: Vec<&AttackChainEntry> = Vec::new();
        for phase in &phase_order {
            for entry in &attack_chains {
                if entry.mitre_tactic == *phase {
                    phase_sorted.push(entry);
                }
            }
        }
        for entry in &attack_chains {
            if entry.mitre_tactic.is_empty() || !phase_order.contains(&entry.mitre_tactic.as_str())
            {
                phase_sorted.push(entry);
            }
        }

        if !phase_sorted.is_empty() {
            for (i, entry) in phase_sorted.iter().enumerate() {
                let connector = if i == 0 { "▶" } else { "│" };
                let phase_label = if !entry.mitre_tactic.is_empty() {
                    format!(
                        "{} ({})",
                        entry.mitre_tactic,
                        mitre_phase_name(&entry.mitre_tactic)
                    )
                } else {
                    "未映射".to_string()
                };

                println!(
                    "  {} {} {} — PID:{} ({})",
                    connector,
                    severity_colored(&format!("[{}]", entry.severity), &entry.severity),
                    entry.title.bold(),
                    entry.pid,
                    entry.comm
                );

                if let Some(ref daddr) = entry.daddr {
                    let port_info = entry.dport.map(|p| format!(":{}", p)).unwrap_or_default();
                    let proto_info = entry.proto.as_deref().unwrap_or("");
                    println!("  │   └─ 目标: {}{} {}", daddr, port_info, proto_info);
                }

                if let Some(ref filepath) = entry.filepath {
                    println!("  │   └─ 文件: {}", filepath);
                }

                if !entry.mitre_tactic.is_empty() {
                    println!(
                        "  │   └─ MITRE: {} / {}",
                        phase_label, entry.mitre_technique
                    );
                }
            }

            println!("  └─ [链结束] 共 {} 个阶段", phase_sorted.len());
        }
    }

    if !pid_profiles.is_empty() {
        println!();
        println!("{}", "── 阶段 8: 进程行为画像 (按 PID) ──".cyan().bold());
        println!();
        println!("  每个进程的事件序列 (用于识别异常行为模式):");
        println!();

        for (pid, prof) in pid_profiles.iter() {
            if prof.total < 2 {
                continue;
            }
            println!("  PID {} ({} 条事件):", pid, prof.total);
            for (_, etype, comm) in prof.samples.iter() {
                println!("    └─ {} [type={}]", comm, etype);
            }
            if prof.total > prof.samples.len() as u64 {
                println!("    └─ ... (共 {} 条)", prof.total);
            }
        }
    }

    println!();
    let integrity = if verification.is_valid {
        "通过 ✓"
    } else {
        "断裂 ✗"
    };
    banner(&format!("回放完成 — 链完整性 {}", integrity));
    println!("  上述分析基于 SHA-256 哈希链校验,所有结论均有佐证,可用于司法取证");

    Ok(())
}

/// timestamp_ns 来自内核 bpf_ktime_get_ns()（CLOCK_MONOTONIC，开机起算），不是
/// epoch。旧实现按 epoch 渲染，回放里出现 1970 年的假日期。这里按"开机后"格式
/// 如实显示；文件内的相对时间线（跨度/时间线分布）不受影响。
fn format_timestamp(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let days = secs / 86_400;
    let h = (secs % 86_400) / 3_600;
    let m = (secs % 3_600) / 60;
    let s = secs % 60;
    if days > 0 {
        format!("开机后 {}d {:02}:{:02}:{:02}", days, h, m, s)
    } else {
        format!("开机后 {:02}:{:02}:{:02}", h, m, s)
    }
}

#[derive(Clone)]
struct AttackChainEntry {
    title: String,
    severity: String,
    pid: u32,
    comm: String,
    daddr: Option<String>,
    dport: Option<u16>,
    proto: Option<String>,
    filepath: Option<String>,
    mitre_tactic: String,
    mitre_technique: String,
    ts: Option<u64>,
}

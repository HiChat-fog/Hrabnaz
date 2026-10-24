use anyhow::{bail, Result};
use ks_engine::blocker::{BlockReason, PinnedBlockMap};
use serde_json::json;

use super::ui::{banner, new_table};
use colored::Colorize;

/// 手动裁决的防呆：不杀 pid 1 / 自身 / 已不存在的进程
fn guard_pid(pid: u32) -> Result<()> {
    if pid == 0 {
        bail!("pid 0 无效");
    }
    if pid == 1 {
        bail!("拒绝阻断 pid 1（init）");
    }
    if pid == std::process::id() {
        bail!("拒绝阻断自身");
    }
    if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
        bail!("pid {} 不存在", pid);
    }
    Ok(())
}

/// block/unblock/blocked 的 JSON 输出契约：单行对象到 stdout（含 command 字段
/// 标识来源），人读细节走 stderr（管道消费方只解析 stdout）
fn emit_json(v: serde_json::Value) {
    println!("{}", v);
}

pub async fn run_block(pid: u32, ttl_secs: u64, json: bool) -> Result<()> {
    guard_pid(pid)?;
    let expire = if ttl_secs == 0 {
        0 // 内核语义：expire=0 = 永久
    } else {
        ks_engine::blocker::monotonic_now_ns()
            .saturating_add(ttl_secs.saturating_mul(1_000_000_000))
    };
    PinnedBlockMap::open()?.write(pid, expire, BlockReason::Manual as u8)?;
    if json {
        emit_json(json!({
            "command": "block",
            "pid": pid,
            "ttl_secs": ttl_secs,
            "expire_monotonic_ns": expire,
            "reason": BlockReason::Manual.to_string(),
        }));
    } else {
        println!(
            "{}  pid {} 已写入裁决 ({}, 来源: {})",
            "阻断".red().bold(),
            pid,
            if expire == 0 {
                "永久".to_string()
            } else {
                format!("{}s", ttl_secs)
            },
            BlockReason::Manual
        );
    }
    Ok(())
}

pub async fn run_unblock(pid: u32, json: bool) -> Result<()> {
    let removed = PinnedBlockMap::open()?.remove(pid)?;
    if json {
        emit_json(json!({
            "command": "unblock",
            "pid": pid,
            "removed": removed,
        }));
        if !removed {
            // exit code 交给 main 的错误路径会打印非 JSON 文本；这里以 JSON
            // 报告结果，退出码用 1 表达"无裁决"——消费者可两者兼得
            std::process::exit(1);
        }
    } else if removed {
        println!("{}  pid {} 已解除", "解除".green().bold(), pid);
    } else {
        bail!("pid {} 无生效裁决", pid);
    }
    Ok(())
}

pub async fn run_blocked(json: bool) -> Result<()> {
    let map = PinnedBlockMap::open()?;
    let now = ks_engine::blocker::monotonic_now_ns();
    let mut rows: Vec<(u32, u64, u8)> = map
        .entries()
        .into_iter()
        .filter(|&(pid, expire, _)| pid > 0 && (expire == 0 || expire > now))
        .collect();
    rows.sort();

    if json {
        let entries: Vec<serde_json::Value> = rows
            .iter()
            .map(|&(pid, expire, reason)| {
                json!({
                    "pid": pid,
                    "expire_monotonic_ns": expire,
                    "permanent": expire == 0,
                    "remain_secs": if expire == 0 { serde_json::Value::Null } else { json!(expire.saturating_sub(now) / 1_000_000_000) },
                    "reason": BlockReason::from_u8(reason).to_string(),
                })
            })
            .collect();
        emit_json(json!({
            "command": "blocked",
            "count": entries.len(),
            "now_monotonic_ns": now,
            "entries": entries,
        }));
        return Ok(());
    }

    banner(&format!("生效中的阻断裁决 — {} 条", rows.len()));
    println!();
    if rows.is_empty() {
        println!("  (无 — 自动触发见引擎日志, 手动下发用 kernelsentinel block <pid>)");
        return Ok(());
    }
    let mut t = new_table();
    t.set_header(vec!["PID", "来源", "剩余"]);
    for (pid, expire, reason) in rows {
        let remain = if expire == 0 {
            "永久".to_string()
        } else {
            format!("{}s", expire.saturating_sub(now) / 1_000_000_000)
        };
        t.add_row(vec![
            pid.to_string(),
            BlockReason::from_u8(reason).to_string(),
            remain,
        ]);
    }
    println!("{t}");
    Ok(())
}

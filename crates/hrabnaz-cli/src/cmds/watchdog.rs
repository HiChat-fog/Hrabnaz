use anyhow::{bail, Result};
use std::path::PathBuf;

use super::ui::{banner, step};
use colored::Colorize;

/// 心跳年龄超过该秒数视为消费循环停摆（H-1.6）。
/// 引擎 10s 写一次心跳，默认阈值 60s = 连续 6 个周期无刷新
const DEFAULT_STALE_SECS: u64 = 60;

/// 判停后的动作：SIGTERM 让引擎走优雅退出（卸探针/flush 取证链），
/// systemd Restart=on-failure 自动拉起新实例——kill 引擎后 ≤1min 自动恢复消费
#[derive(clap::Args, Debug)]
pub struct WatchdogArgs {
    /// 心跳年龄超过该秒数判定停摆
    #[arg(long, default_value_t = DEFAULT_STALE_SECS)]
    pub stale_secs: u64,
    /// 只检查并报告，不执行 SIGTERM（试运行/巡检用）
    #[arg(long, default_value_t = false)]
    pub dry_run: bool,
}

struct Heartbeat {
    pid: u32,
    ts_epoch_ms: u64,
    consumed: u64,
}

fn read_heartbeat() -> Option<Heartbeat> {
    let path: PathBuf = super::heartbeat_file_path();
    let content = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&content).ok()?;
    Some(Heartbeat {
        pid: v.get("pid")?.as_u64()? as u32,
        ts_epoch_ms: v.get("ts_epoch_ms")?.as_u64()?,
        consumed: v.get("consumed").and_then(|c| c.as_u64()).unwrap_or(0),
    })
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 校验心跳里 pid 的 /proc 身份确为 hrabnaz（防状态文件残留/复用后误杀），
/// 复用 stop.rs 的同款判定
#[cfg(target_os = "linux")]
fn verify_ks_process(pid: u32) -> bool {
    super::stop::verify_ks_process(pid)
}

pub async fn run(args: &WatchdogArgs) -> Result<()> {
    banner(&format!(
        "引擎 watchdog — 心跳停摆阈值 {}s",
        args.stale_secs
    ));
    step(1, 2, "读取引擎心跳");

    let hb_path = super::heartbeat_file_path();
    let Some(hb) = read_heartbeat() else {
        // 优雅停止会删除心跳文件：此时引擎本就没在跑，静默退出 0——
        // 否则每分钟 timer 会对"已正常停服"周期性报 failed 刷 journal。
        // 只有"文件存在但解析失败"才算异常（文件损坏/被篡改）
        if !hb_path.exists() {
            println!("  引擎未运行（无心跳文件）— 无需动作");
            return Ok(());
        }
        bail!(
            "心跳文件 {} 存在但无法解析 — 文件损坏或被篡改",
            hb_path.display()
        );
    };

    let now = now_epoch_ms();
    if hb.ts_epoch_ms > now + 60_000 {
        bail!(
            "心跳时间戳来自未来 ({}ms)，时钟异常，拒绝判定",
            hb.ts_epoch_ms
        );
    }
    let age_secs = now.saturating_sub(hb.ts_epoch_ms) / 1000;
    let alive = std::path::Path::new(&format!("/proc/{}", hb.pid)).exists();

    println!(
        "      引擎 PID {} — 心跳 {}s 前 (已消费 {} 事件, 进程{})",
        hb.pid,
        age_secs,
        hb.consumed,
        if alive { "存活" } else { "已退出" }
    );

    step(2, 2, "判定");
    if age_secs <= args.stale_secs {
        println!("  {} 心跳正常，无需动作", "✓".green().bold());
        return Ok(());
    }

    println!(
        "  {} 心跳停摆 {}s (阈值 {}s)",
        "✗".red().bold(),
        age_secs,
        args.stale_secs
    );

    if !alive {
        println!("      引擎进程已退出 — systemd Restart=on-failure 会拉起新实例，无需补刀");
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        if !verify_ks_process(hb.pid) {
            bail!(
                "PID {} 的 /proc 身份不是 hrabnaz — 心跳文件可能是残留/伪造，拒绝 kill",
                hb.pid
            );
        }
        if args.dry_run {
            println!("      {} dry-run: 不发送 SIGTERM", "[跳过]".yellow());
            return Ok(());
        }
        hrabnaz_core::sys::kill_sigterm(hb.pid);
        println!(
            "      {} 已向 PID {} 发送 SIGTERM (优雅退出 → systemd 自动拉起)",
            "动作".red().bold(),
            hb.pid
        );
        println!(
            "      提示: 用 systemd timer 或 while-loop 每 {}s 调一次本命令实现自动恢复",
            args.stale_secs
        );
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = args.dry_run;
        println!(
            "      {} 非 Linux 环境，无法发送 SIGTERM",
            "[MOCK]".yellow()
        );
    }

    Ok(())
}

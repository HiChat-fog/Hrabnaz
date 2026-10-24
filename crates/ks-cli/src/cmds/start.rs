//! start 子命令（H-7 后的薄壳）：参数解析 + UI 打印 + 驱动 ks-engine。
//!
//! 检测主链与引擎生命周期全部在 `ks_engine::engine::Engine`：
//! 本文件只负责单例锁、启动横幅、把 `EngineEffect` 渲染成彩色终端输出、
//! Ctrl+C/SIGTERM 信号处理、状态文件（`ks stop` 用）与退出摘要。

use anyhow::Result;
use ks_engine::config::Config;
use ks_engine::engine::{
    AlertSource, BlockedVia, Engine, EngineEffect, EngineOptions, EventSourceSpec,
};
use std::path::Path;
use std::time::Instant;

use super::ui::{banner, severity_badge, step};
use colored::Colorize;

pub async fn run(rules_dir: &str, log_dir: &str, sd_notify: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    let _singleton_guard = match crate::cmds::singleton::acquire() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("启动中止: {}", e);
            return Err(anyhow::anyhow!("{}", e));
        }
    };

    let start_time = Instant::now();

    step(1, 6, "加载配置");
    let mut config = Config::default();
    config.apply_env_overrides();
    config.validate()?;
    println!("      缓冲区大小: {}", config.engine.buffer_size);
    println!("      异常阈值: {}", config.detection.anomaly_threshold);
    println!("      取证日志目录: {}", config.forensic.log_dir);
    println!("      取证保留天数: {}", config.forensic.retention_days);

    let resolved_log_dir = if Path::new(log_dir).exists() || log_dir != "/var/log/ks" {
        log_dir.to_string()
    } else {
        "./logs".to_string()
    };

    step(2, 6, "加载 eBPF 探针（自动 tier 检测）");
    // Engine::start 内部：tier 检测/路由 → 规则加载+完整性校验 → 组件组装 →
    // 阻断通道(pin/killer) → 取证 worker → 心跳 → 热加载
    let engine = Engine::start(EngineOptions {
        config: config.clone(),
        rules_dir: rules_dir.to_string(),
        log_dir: resolved_log_dir.clone(),
        source: EventSourceSpec::Auto,
        heartbeat_path: Some(super::heartbeat_file_path()),
        ml_observe_sec: None,
    })
    .await?;
    let info = engine.info();

    if let Some(t) = info.tier_detected {
        println!("      检测到 tier: {}", t.as_str());
    }
    println!(
        "      事件源: {} [{}]",
        info.source_desc,
        info.source_kind.as_str()
    );

    step(3, 6, "加载检测规则");
    for (name, count) in &info.rules_files {
        println!("      {}: {} 条规则", name, count);
    }
    if !info.rules_dir_exists {
        println!(
            "      [WARN] 规则目录不存在: {} (将使用空规则集)",
            rules_dir
        );
    } else if info.rules_total == 0 {
        println!(
            "      [WARN] 未加载任何规则 (将仅使用异常评分，阈值 {:.2})",
            config.detection.anomaly_threshold
        );
    } else {
        println!("      总计: {} 条规则", info.rules_total);
    }

    step(4, 6, "初始化引擎组件");
    if let Some(channel) = &info.block_channel {
        println!("      裁决通道: {} (ks block 可用)", channel);
    }
    match &info.rules_integrity {
        Some((digest, ks_engine::rules_integrity::RulesIntegrityVerdict::NoBaseline)) => {
            println!(
                "      规则完整性: 未设 KS_RULES_DIGEST 基线 (指纹 {}…, 快照已记录)",
                &digest[..16.min(digest.len())]
            );
        }
        Some((_, ks_engine::rules_integrity::RulesIntegrityVerdict::Match)) => {
            println!("      规则完整性: 与部署基线一致 ✓");
        }
        Some((_, ks_engine::rules_integrity::RulesIntegrityVerdict::Mismatch { .. })) => {
            println!(
                "  {} 规则集完整性校验失败: 与部署基线不一致 (审计告警已写入取证链)",
                "完整性".red().bold()
            );
        }
        None => {}
    }

    step(5, 6, "写入运行状态");
    write_status_file();
    println!("      状态文件已写入 (供 stop 命令使用)");
    println!("      聚合器缓冲区: {} 条", config.engine.buffer_size);
    println!("      取证日志: {}", info.forensic_path.display());
    println!("      轮转阈值: {}MB", config.forensic.max_log_size_mb);

    step(6, 6, "启动规则热加载");
    println!("      监听规则目录变更: {}", rules_dir);

    println!();
    println!("      按 Ctrl+C 停止");
    println!();

    if sd_notify {
        #[cfg(target_os = "linux")]
        {
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
            log::info!("已通知systemd服务就绪");
        }
        #[cfg(not(target_os = "linux"))]
        {
            log::debug!("sd-notify标志已忽略(非Linux平台,sd-notify crate不可用)");
        }
    }

    let mut sig = std::pin::pin!(tokio::signal::ctrl_c());
    // systemctl stop 发 SIGTERM：不接住的话进程直接死，kprobe 条目/取证 flush 全跳过
    #[cfg(target_os = "linux")]
    let mut term: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> = {
        use tokio::signal::unix::{signal, SignalKind};
        Box::pin(async move {
            match signal(SignalKind::terminate()) {
                Ok(mut s) => {
                    let _ = s.recv().await;
                }
                Err(_) => std::future::pending::<()>().await,
            }
        })
    };
    #[cfg(not(target_os = "linux"))]
    let mut term: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> =
        Box::pin(std::future::pending::<()>());

    let mut engine = engine;
    let mut last_progress: u64 = 0;
    loop {
        tokio::select! {
            _ = &mut sig => {
                println!();
                println!("收到 Ctrl+C 信号，准备安全关闭...");
                break;
            }
            _ = &mut term => {
                println!();
                println!("收到 SIGTERM，准备安全关闭...");
                break;
            }
            result = engine.tick() => {
                match result {
                    Ok(outcome) => {
                        for effect in &outcome.effects {
                            print_effect(effect);
                        }
                        if outcome.exhausted {
                            println!("      事件源已耗尽，停止消费循环");
                            break;
                        }
                        let stats = engine.stats();
                        if stats.consumed / 10 != last_progress / 10 {
                            last_progress = stats.consumed;
                            let alerts = stats.rule_alerts + stats.anomaly_alerts;
                            let alerts_str = if alerts > 0 {
                                alerts.to_string().yellow().bold().to_string()
                            } else {
                                "0".to_string().dimmed().to_string()
                            };
                            println!(
                                "  {} 已处理 {} 条事件, {} 条告警",
                                "进度".cyan().bold(),
                                stats.consumed.to_string().dimmed(),
                                alerts_str
                            );
                        }
                    }
                    Err(e) => {
                        log::warn!("事件处理失败: {}", e);
                        if !engine.is_mock() {
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        }
                    }
                }
            }
        }
    }

    println!();
    println!("{}", "── 安全关闭 ──".cyan().bold());
    println!("      释放事件源（含 eBPF 探针 fd）...");
    println!("      Flush 取证日志...");
    let summary = engine.shutdown().await?;

    println!(
        "      事件总数: {} (消费: {})",
        summary.events_logged.to_string().green().bold(),
        summary.consumed
    );
    println!(
        "      告警总数: {} (规则: {}, 异常: {})",
        summary.alerts_logged.to_string().green().bold(),
        summary.rule_alerts,
        summary.anomaly_alerts
    );
    println!("      链尾哈希: {}", summary.chain_tail_hash.dimmed());
    println!("      运行时长: {:.1}s", start_time.elapsed().as_secs_f64());

    cleanup_status_file();
    banner("内核哨兵已安全退出");

    Ok(())
}

/// 把引擎产出的效果渲染成终端输出（唯一的 UI 职责所在）
fn print_effect(effect: &EngineEffect) {
    match effect {
        EngineEffect::Alert(raised) => {
            let alert = &raised.alert;
            match &raised.source {
                AlertSource::Rule => {
                    println!(
                        "  {} {} {} — PID: {} {}",
                        "规则".magenta(),
                        severity_badge(&alert.severity),
                        alert.title.bold(),
                        alert.process.pid,
                        alert.process.comm
                    );
                }
                AlertSource::Correlation {
                    confidence,
                    trigger_pid,
                } => {
                    println!(
                        "  {} {} {} — PID: {} 置信度: {:.0}%",
                        "关联".cyan(),
                        severity_badge(&alert.severity),
                        alert.title.bold(),
                        trigger_pid,
                        confidence * 100.0
                    );
                }
                AlertSource::ProcessTree {
                    parent_comm,
                    child_comm,
                    anomaly_type,
                } => {
                    println!(
                        "  [进程树异常] {} → {} — {}",
                        parent_comm, child_comm, anomaly_type
                    );
                }
                // 基线与 ML 告警保持旧版行为：只入链不打印
                AlertSource::BaselineDeviation | AlertSource::MlAnomaly => {}
            }
            if let Some(mitre) = &alert.mitre {
                println!("    MITRE: {} / {}", mitre.tactic, mitre.technique);
            }
        }
        EngineEffect::Blocked(blocked) => match blocked.via {
            BlockedVia::Rule => {
                println!(
                    "  {} PID {} 已阻断 (规则: {})",
                    "阻断".red().bold(),
                    blocked.pid,
                    blocked.reason
                );
            }
            BlockedVia::Correlation => {
                println!(
                    "  {} PID {} 已阻断 (关联告警)",
                    "阻断".red().bold(),
                    blocked.pid
                );
            }
            BlockedVia::UserKill => {
                println!(
                    "  {} PID {} 用户态实杀 ({}), 非Modern tier由ks补杀",
                    "阻断".red().bold(),
                    blocked.pid,
                    blocked.reason
                );
            }
        },
        EngineEffect::Score(score) => {
            println!(
                "  {} 评分: {} (阈值: {:.2}) — PID: {} {}",
                "异常".yellow(),
                score.score.to_string().yellow().bold(),
                score.threshold,
                score.pid,
                score.comm
            );
        }
        EngineEffect::Chain(chain) => {
            println!(
                "  [攻击链] PID {} — {:.0}% 置信度, {} 个阶段",
                chain.root_pid,
                chain.confidence * 100.0,
                chain.steps.len()
            );
            for chain_step in &chain.steps {
                println!(
                    "    {}: {} ({} 个事件)",
                    format_phase(&chain_step.phase),
                    chain_step.description,
                    chain_step.events.len()
                );
            }
        }
    }
}

fn format_phase(phase: &ks_engine::chain::AttackPhase) -> &'static str {
    match phase {
        ks_engine::chain::AttackPhase::InitialAccess => "初始入侵",
        ks_engine::chain::AttackPhase::Execution => "执行恶意代码",
        ks_engine::chain::AttackPhase::Persistence => "持久化",
        ks_engine::chain::AttackPhase::PrivilegeEscalation => "提权",
        ks_engine::chain::AttackPhase::DefenseEvasion => "防御规避",
        ks_engine::chain::AttackPhase::CredentialAccess => "凭据访问",
        ks_engine::chain::AttackPhase::Discovery => "信息探测",
        ks_engine::chain::AttackPhase::LateralMovement => "横向移动",
        ks_engine::chain::AttackPhase::Exfiltration => "数据窃取",
        ks_engine::chain::AttackPhase::Unknown => "未知阶段",
    }
}

fn write_status_file() {
    let status_path = super::status_file_path();
    let pid = std::process::id();
    let start_time = chrono::Local::now().to_rfc3339();

    let status = serde_json::json!({
        "pid": pid,
        "start_time": start_time,
        "version": env!("CARGO_PKG_VERSION"),
        "status": "running",
    });

    if let Some(parent) = Path::new(&status_path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let data = serde_json::to_string_pretty(&status).unwrap_or_default();
    // 原子写：先写临时文件（0600）再 rename，避免读者看到半截 JSON，
    // 也消除可预测文件名 + 非原子写的被篡改窗口
    let tmp_path = status_path.with_extension(format!("json.tmp{}", pid));
    let write_res = (|| -> std::io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp_path)?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(data.as_bytes())?;
        }
        std::fs::rename(&tmp_path, &status_path)
    })();
    if let Err(e) = write_res {
        log::warn!("状态文件写入失败: {} — {}", status_path.display(), e);
        let _ = std::fs::remove_file(&tmp_path);
    }
}

fn cleanup_status_file() {
    let status_path = super::status_file_path();
    let _ = std::fs::remove_file(status_path);
}

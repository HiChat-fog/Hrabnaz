use anyhow::Result;
use ks_core::alert::{Alert, MitreInfo, ProcessInfo};
use ks_core::rule::Severity;
use ks_engine::aggregator::{DecodedEvent, EventAggregator};
use ks_engine::baseline::BaselineManager;
use ks_engine::chain::ChainReconstructor;
use ks_engine::config::Config;
use ks_engine::correlation::{CorrelationAlert, CorrelationEngine};
use ks_engine::detector::DetectionEngine;
use ks_engine::event_source::default_event_source;
use ks_engine::event_source::EventSource;
use ks_engine::forensic::{ForensicLogger, RotationConfig};
use ks_engine::loader::BpfMapReader;
use ks_engine::ml_detector::AdaptiveDetector;
use ks_engine::process_tree::ProcessTreeManager;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

use colored::Colorize;
use super::ui::{banner, severity_badge};

enum ForensicOp {
    Event(DecodedEvent),
    Alert(Alert),
}

#[derive(Clone)]
struct ForensicSink {
    tx: tokio::sync::mpsc::Sender<ForensicOp>,
}

impl ForensicSink {
    async fn log_event(&self, event: &DecodedEvent) {
        if self.tx.send(ForensicOp::Event(event.clone())).await.is_err() {
            log::warn!("forensic worker已退出,事件丢失");
        }
    }
    async fn log_alert(&self, alert: &Alert) {
        if self.tx.send(ForensicOp::Alert(alert.clone())).await.is_err() {
            log::warn!("forensic worker已退出,告警丢失");
        }
    }
}

async fn forensic_worker(
    forensic: Arc<Mutex<ForensicLogger>>,
    mut rx: tokio::sync::mpsc::Receiver<ForensicOp>,
) {
    while let Some(op) = rx.recv().await {
        let r = match op {
            ForensicOp::Event(e) => forensic.lock().await.log_event(&e),
            ForensicOp::Alert(a) => forensic.lock().await.log_alert(&a),
        };
        if let Err(e) = r {
            log::warn!("forensic写入失败: {}", e);
        }
    }
    if let Err(e) = forensic.lock().await.flush() {
        log::warn!("forensic flush失败: {}", e);
    }
}

static PROF_NS: [std::sync::atomic::AtomicU64; 9] = [
    std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0),
    std::sync::atomic::AtomicU64::new(0),
];
static PROF_CNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn prof_add(idx: usize, ns: u64) {
    PROF_NS[idx].fetch_add(ns, std::sync::atomic::Ordering::Relaxed);
}

fn prof_print() {
    // 剖析产物不再无条件追加到可预测路径 /tmp/ks-prof.log，改为 KS_PROF=1 显式开启
    if std::env::var("KS_PROF").as_deref() != Ok("1") {
        return;
    }
    let cnt = PROF_CNT.load(std::sync::atomic::Ordering::Relaxed);
    if cnt == 0 { return; }
    let names = ["decode","forensic_log","baseline","process_tree+corr","ml","detector_match","anomaly_score(incr)","forensic_alert","total"];
    let mut s = format!("[prof] events={}\n", cnt);
    for (i, n) in names.iter().enumerate() {
        let ns = PROF_NS[i].load(std::sync::atomic::Ordering::Relaxed);
        let avg_ns = ns / cnt.max(1);
        s.push_str(&format!("  {:<28} total={:>10}μs  avg={:>8}ns\n", n, ns/1000, avg_ns));
    }
    if let Some(path) = std::env::var("KS_PROF").ok().and_then(|v| {
        if v == "1" { None } else { Some(std::path::PathBuf::from(v)) }
    }) {
        let _ = std::fs::OpenOptions::new().create(true).append(true).open(path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, s.as_bytes()));
    } else {
        eprintln!("{}", s);
    }
}

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

    super::ui::step(1, 6, "加载配置");
    let mut config = Config::default();
    config.apply_env_overrides();
    config.validate()?;
    println!("      缓冲区大小: {}", config.engine.buffer_size);
    println!("      异常阈值: {}", config.detection.anomaly_threshold);
    println!("      取证日志目录: {}", config.forensic.log_dir);
    println!("      取证保留天数: {}", config.forensic.retention_days);

    super::ui::step(2, 6, "加载 eBPF 探针（自动 tier 检测）");
    let detected_tier = ks_engine::tier_detect::detect_ebpf_tier();
    if let Some(t) = detected_tier {
        println!("      检测到 tier: {}", t.as_str());
    }

    #[cfg(target_os = "linux")]
    let (mut source, map_reader): (Box<dyn EventSource>, Option<Arc<dyn BpfMapReader>>) =
        default_event_source().await;
    #[cfg(not(target_os = "linux"))]
    let (mut source, map_reader): (Box<dyn EventSource>, Option<Arc<dyn BpfMapReader>>) = {
        println!("      (非 Linux 平台，使用 mock 事件源)");
        default_event_source().await
    };
    println!(
        "      事件源: {} [{}]",
        source.description(),
        source.kind().as_str()
    );

    super::ui::step(3, 6, "加载检测规则");
    let detector = Arc::new(Mutex::new(DetectionEngine::new()));
    load_rules(&detector, rules_dir).await?;

    super::ui::step(4, 6, "初始化引擎组件");
    let aggregator = Arc::new(Mutex::new(EventAggregator::new(config.engine.buffer_size)));
    let baseline_mgr = Arc::new(Mutex::new(BaselineManager::new()));
    let correlation_engine = Arc::new(Mutex::new(CorrelationEngine::new(300)));
    let process_tree_mgr = Arc::new(Mutex::new(ProcessTreeManager::new()));
    let ml_detector: Arc<Mutex<AdaptiveDetector>> = Arc::new(Mutex::new(AdaptiveDetector::from_env()));
    let block_mgr: Arc<Mutex<ks_engine::blocker::BlockManager>> =
        Arc::new(Mutex::new(ks_engine::blocker::BlockManager::new()));
    {
        let mut bm = block_mgr.lock().await;
        bm.set_enabled(config.detection.block_enabled);
        // ADR-011 闭环：block/unblock 同步下发内核 block_decisions map。
        // C loader（NOBTF）与 mock 路径没有用户态 map 句柄（map_reader 为 None 或
        // Mock 写入报错），阻断自动降级为仅记录用户态表——与 8-31 前行为一致。
        match &map_reader {
            Some(mr) => {
                bm.set_kernel_sink(std::sync::Arc::new(
                    ks_engine::blocker::MapWriterSink(mr.clone()),
                ));
                log::info!("block_decisions 内核下发通道已接通（阻断决策将写入内核 map，Modern tier 查表实杀）");
            }
            None => {
                log::info!("当前事件源无 BPF map reader（C loader/mock），阻断仅记录用户态表，内核不会查表实杀");
            }
        }
    }
    let block_ttl = config.detection.block_ttl_secs;
    let block_severity_threshold = config.detection.block_severity_threshold.clone();

    // pin block_decisions 到 bpffs：ks block 等独立进程靠它跨进程写裁决
    let block_pinned = if let Some(mr) = &map_reader {
        match mr.pin_block_map(ks_engine::blocker::BLOCK_DECISIONS_PIN) {
            Ok(()) => {
                println!(
                    "      裁决通道: {} (ks block 可用)",
                    ks_engine::blocker::BLOCK_DECISIONS_PIN
                );
                true
            }
            Err(e) => {
                log::warn!("block_decisions pin 失败: {} — ks block 不可用，自动阻断不受影响", e);
                false
            }
        }
    } else {
        false
    };

    // 非 Modern tier 的用户态实杀：老内核 ks_check_block 只查表不杀（无 bpf_send_signal），
    // 由本进程轮询 block_decisions 全表补 SIGKILL。Modern 由内核即时杀，无需重复。
    let protected_pids: std::collections::HashSet<u32> =
        source.protected_pids().iter().copied().collect();
    let user_kill_enabled = config.detection.block_enabled
        && map_reader.is_some()
        && detected_tier != Some(ks_engine::event_source::SourceKind::EbpfModern)
        && std::env::var("KS_USER_KILL").as_deref() != Ok("0");
    if user_kill_enabled {
        let mr = map_reader.clone().expect("map_reader 已判定存在");
        let protected_for_kill = protected_pids.clone();
        let killed: Arc<Mutex<std::collections::HashMap<u32, u64>>> =
            Arc::new(Mutex::new(std::collections::HashMap::new()));
        tokio::spawn(async move {
            let protect = ks_engine::blocker::protected_comms();
            let mut tick = tokio::time::interval(std::time::Duration::from_millis(300));
            loop {
                tick.tick().await;
                let entries = mr.read_block_decisions();
                if entries.is_empty() {
                    continue;
                }
                let outcome = {
                    let mut killed = killed.lock().await;
                    ks_engine::blocker::user_kill_tick(
                        &entries,
                        &mut killed,
                        &protected_for_kill,
                        // comm 可伪造（prctl PR_SET_NAME），与内核 ks_check_block 同款守卫：
                        // 从 /tmp、/dev/shm 等可疑路径启动的进程不享受 comm 豁免
                        |pid| {
                            ks_engine::blocker::comm_of(pid)
                                .is_some_and(|comm| protect.iter().any(|p| *p == comm))
                                && !ks_engine::blocker::exe_path_suspicious(pid)
                        },
                        ks_engine::blocker::monotonic_now_ns(),
                        ks_engine::blocker::kill_pid_sigkill,
                    )
                };
                for pid in outcome.exempt {
                    log::info!("跳过实杀 pid={} (comm 在保护名单且 exe 路径可信)", pid);
                }
                for (pid, reason) in outcome.fired {
                    log::info!("用户态实杀 pid={} (reason={}, 内核无 bpf_send_signal)", pid, reason);
                    println!(
                        "  {} PID {} 用户态实杀 ({}), 非Modern tier由ks补杀",
                        "阻断".red().bold(),
                        pid,
                        reason
                    );
                }
            }
        });
        log::info!("用户态 killer 已启用（非 Modern tier，300ms 轮询 block_decisions）");
    }

    let resolved_log_dir = if Path::new(log_dir).exists() || log_dir != "/var/log/ks" {
        log_dir.to_string()
    } else {
        "./logs".to_string()
    };
    let log_path = Path::new(&resolved_log_dir).join(format!(
        "events_{}.jsonl",
        chrono::Local::now().format("%Y%m%d")
    ));

    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    } else {
        anyhow::bail!("无法获取日志路径的父目录: {}", log_path.display());
    }

    let rotation_config = RotationConfig {
        max_file_size: config.forensic.max_log_size_mb as u64 * 1024 * 1024,
        retain_days: config.forensic.retention_days,
        compress_archives: true,
    };
    let forensic = Arc::new(Mutex::new(ForensicLogger::with_rotation(
        log_path,
        rotation_config,
    )?));
    let (forensic_tx, forensic_rx) = tokio::sync::mpsc::channel::<ForensicOp>(65536);
    let forensic_sink = ForensicSink { tx: forensic_tx };

    // H-1.5 规则完整性：目录指纹与 KS_RULES_DIGEST 基线比对，快照落取证目录；
    // MISMATCH 产生审计告警进哈希链留痕；STRICT 模式直接拒绝启动
    match ks_engine::rules_integrity::check_and_record(Path::new(rules_dir), Path::new(&resolved_log_dir)) {
        Ok((integrity, verdict)) => {
            match &verdict {
                ks_engine::rules_integrity::RulesIntegrityVerdict::NoBaseline => {
                    println!(
                        "      规则完整性: 未设 KS_RULES_DIGEST 基线 (指纹 {}…, 快照已记录)",
                        &integrity.combined_digest[..16.min(integrity.combined_digest.len())]
                    );
                }
                ks_engine::rules_integrity::RulesIntegrityVerdict::Match => {
                    println!("      规则完整性: 与部署基线一致 ✓");
                }
                ks_engine::rules_integrity::RulesIntegrityVerdict::Mismatch { .. } => {
                    log::warn!(
                        "[rules-integrity] 规则集与 KS_RULES_DIGEST 基线不一致 — 审计告警将写入取证日志"
                    );
                }
            }
            if let Some(alert) = ks_engine::rules_integrity::mismatch_alert(&verdict) {
                let title = alert.title.clone();
                forensic_sink.log_alert(&alert).await;
                println!(
                    "  {} {} (规则集与部署基线不一致, 已写入取证链)",
                    "完整性".red().bold(),
                    title.bold()
                );
            }
            if matches!(
                verdict,
                ks_engine::rules_integrity::RulesIntegrityVerdict::Mismatch { .. }
            ) && std::env::var("KS_RULES_DIGEST_STRICT").as_deref() == Ok("1")
            {
                anyhow::bail!(
                    "KS_RULES_DIGEST_STRICT=1 且规则集与部署基线不一致 — 拒绝启动。\
                     正常变更请用 `ks rules-digest` 更新基线"
                );
            }
        }
        Err(e) => {
            println!("      规则完整性: 无法计算指纹 ({}) — 跳过", e);
        }
    }
    let forensic_worker_handle = {
        let f = forensic.clone();
        tokio::spawn(async move { forensic_worker(f, forensic_rx).await; })
    };
    let chain_reconstructor = ChainReconstructor::new();

    println!("      聚合器缓冲区: {} 条", config.engine.buffer_size);
    println!("      取证日志: {}", forensic.lock().await.path().display());
    println!("      轮转阈值: {}MB", config.forensic.max_log_size_mb);

    super::ui::step(5, 6, "写入运行状态");
    write_status_file();
    println!("      状态文件已写入 (供 stop 命令使用)");

    super::ui::step(6, 6, "启动规则热加载");
    let hot_reload_rules_dir = rules_dir.to_string();
    let hot_reload_detector = detector.clone();
    let hot_reload_log_dir = resolved_log_dir.clone();
    tokio::spawn(async move {
        rule_hot_loader(&hot_reload_detector, &hot_reload_rules_dir, &hot_reload_log_dir).await;
    });
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

    let mut stats = EventStats::new();
    let anomaly_threshold = config.detection.anomaly_threshold;
    let continue_on_empty = !source.is_mock();

    // H-1.6 引擎心跳：主循环存活即周期性原子刷新心跳文件（含累计消费数），
    // `ks watchdog` 靠它的年龄判断"消费循环停摆"——进程活着但事件泵死了的窗口
    let heartbeat_path = super::heartbeat_file_path();
    let heartbeat_stats = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let heartbeat_stats_writer = heartbeat_stats.clone();
    let heartbeat_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            let payload = serde_json::json!({
                "pid": std::process::id(),
                "ts_epoch_ms": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0),
                "consumed": heartbeat_stats_writer.load(std::sync::atomic::Ordering::Relaxed),
            });
            let tmp = heartbeat_path.with_extension(format!("hb.tmp{}", std::process::id()));
            if std::fs::write(&tmp, payload.to_string()).is_ok() {
                let _ = std::fs::rename(&tmp, &heartbeat_path);
            }
        }
    });

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
            result = async {
                let bytes = match source.next_bytes().await {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        if continue_on_empty {
                            tokio::task::yield_now().await;
                            return Ok(true);
                        } else {
                            return Ok(false);
                        }
                    }
                    Err(e) => return Err(e),
                };
                process_event_bytes(&bytes, &aggregator, &detector, &forensic_sink, &chain_reconstructor, &mut stats, anomaly_threshold, &baseline_mgr, &correlation_engine, &process_tree_mgr, &ml_detector, &block_mgr, block_ttl, &block_severity_threshold, &protected_pids).await?;
                heartbeat_stats.store(stats.consumed, std::sync::atomic::Ordering::Relaxed);
                Ok(true)
            } => {
                match result {
                    Ok(true) => {}
                    Ok(false) => {
                        println!("      事件源已耗尽，停止消费循环");
                        break;
                    }
                    Err(e) => {
                        log::warn!("事件处理失败: {}", e);
                        if continue_on_empty {
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        }
                    }
                }
            }
        }
    }

    println!();
    println!("{}", "── 安全关闭 ──".cyan().bold());
    heartbeat_task.abort();
    let _ = std::fs::remove_file(super::heartbeat_file_path());
    println!("      释放事件源（含 eBPF 探针 fd）...");
    drop(source);
    // 清理本次运行释放到 /tmp 的 ks_loader 与 .o 私有目录
    ks_engine::event_source::cleanup_released_dirs();
    println!("      Flush 取证日志...");
    drop(forensic_sink);
    let _ = forensic_worker_handle.await;

    let elapsed = start_time.elapsed();
    let event_count = forensic.lock().await.event_count();
    let alert_count = forensic.lock().await.alert_count();
    println!("      事件总数: {} (消费: {})", event_count.to_string().green().bold(), stats.consumed);
    println!(
        "      告警总数: {} (规则: {}, 异常: {})",
        alert_count.to_string().green().bold(), stats.rule_alerts, stats.anomaly_alerts
    );
    println!(
        "      链尾哈希: {}",
        forensic.lock().await.chain_tail_hash().to_string().dimmed()
    );
    println!("      运行时长: {:.1}s", elapsed.as_secs_f64());

    if block_pinned {
        let _ = std::fs::remove_file(ks_engine::blocker::BLOCK_DECISIONS_PIN);
    }
    cleanup_status_file();
    prof_print();
    banner("内核哨兵已安全退出");

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_event_bytes(
    bytes: &[u8],
    aggregator: &Arc<Mutex<EventAggregator>>,
    detector: &Arc<Mutex<DetectionEngine>>,
    forensic: &ForensicSink,
    chain_reconstructor: &ChainReconstructor,
    stats: &mut EventStats,
    anomaly_threshold: f64,
    baseline_mgr: &Arc<Mutex<BaselineManager>>,
    correlation_engine: &Arc<Mutex<CorrelationEngine>>,
    process_tree_mgr: &Arc<Mutex<ProcessTreeManager>>,
    ml_detector: &Arc<Mutex<AdaptiveDetector>>,
    block_mgr: &Arc<Mutex<ks_engine::blocker::BlockManager>>,
    block_ttl: u64,
    block_severity_threshold: &str,
    protected_pids: &std::collections::HashSet<u32>,
) -> Result<bool> {
    let t0 = std::time::Instant::now();
    let t = std::time::Instant::now();
    let event = aggregator.lock().await.decode(bytes)?;
    prof_add(0, t.elapsed().as_nanos() as u64);
    let is_protected = protected_pids.contains(&event.header.pid);
    stats.consumed += 1;

    let t = std::time::Instant::now();
    forensic.log_event(&event).await;
    prof_add(1, t.elapsed().as_nanos() as u64);

    let t = std::time::Instant::now();
    if !is_protected {
        baseline_mgr.lock().await.update_from_event(&event);
    }
    prof_add(2, t.elapsed().as_nanos() as u64);
    let t = std::time::Instant::now();
    let mut pt_guard = process_tree_mgr.lock().await;
    pt_guard.update_from_event(&event);
    let corr_alerts = correlation_engine
        .lock()
        .await
        .detect_correlations_with_tree(&event, Some(&*pt_guard));
    drop(pt_guard);
    prof_add(3, t.elapsed().as_nanos() as u64);
    let t = std::time::Instant::now();
    let mut ml_guard = ml_detector.lock().await;
    let t_lock = t.elapsed().as_nanos() as u64;
    let t = std::time::Instant::now();
    ml_guard.update_from_event(&event);
    let t_upd = t.elapsed().as_nanos() as u64;
    prof_add(4, t_lock + t_upd);
    drop(ml_guard);
    for ca in &corr_alerts {
        let alert = correlation_to_alert(ca);
        println!(
            "  {} {} {} — PID: {} 置信度: {:.0}%",
            "关联".cyan(),
            severity_badge(&alert.severity),
            alert.title.bold(),
            event.header.pid,
            ca.confidence * 100.0
        );
        forensic.log_alert(&alert).await;
        stats.rule_alerts += 1;
        if let Some(mitre) = &alert.mitre {
            println!("    MITRE: {} / {}", mitre.tactic, mitre.technique);
        }
        if severity_meets_threshold(&alert.severity, block_severity_threshold)
            && ca.enforce
            && !protected_pids.contains(&event.header.pid)
            && block_mgr.lock().await.block_pid(
                event.header.pid,
                block_ttl,
                ks_engine::blocker::BlockReason::Correlation,
                &alert.title,
            )
        {
            println!("  {} PID {} 已阻断 (关联告警)", "阻断".red().bold(), event.header.pid);
        }
    }

    let t = std::time::Instant::now();
    let matches = detector.lock().await.match_event(&event);
    prof_add(5, t.elapsed().as_nanos() as u64);
    for m in &matches {
        let alert = detector.lock().await.generate_alert(m, &event);
        println!(
            "  {} {} {} — PID: {} {}",
            "规则".magenta(),
            severity_badge(&alert.severity),
            alert.title.bold(),
            alert.process.pid,
            event.comm
        );
        forensic.log_alert(&alert).await;
        stats.rule_alerts += 1;

        if let Some(mitre) = &alert.mitre {
            println!("    MITRE: {} / {}", mitre.tactic, mitre.technique);
        }
        if m.enforce
            && severity_meets_threshold(&alert.severity, block_severity_threshold)
            && !protected_pids.contains(&alert.process.pid)
            && block_mgr.lock().await.block_pid(
                alert.process.pid,
                block_ttl,
                ks_engine::blocker::BlockReason::RuleMatch,
                &alert.rule_name,
            )
        {
            println!(
                "  {} PID {} 已阻断 (规则: {})",
                "阻断".red().bold(),
                alert.process.pid,
                alert.rule_name
            );
        }
    }

    let t = std::time::Instant::now();
    let score = if is_protected {
        0.0
    } else {
        let recent_count = aggregator
            .lock()
            .await
            .recent_syscall_count(event.header.pid, event.header.timestamp_ns);
        detector.lock().await.anomaly_score(&event, recent_count)
    };
    prof_add(6, t.elapsed().as_nanos() as u64);
    if score > anomaly_threshold {
        println!(
            "  {} 评分: {} (阈值: {:.2}) — PID: {} {}",
            "异常".yellow(),
            score.to_string().yellow().bold(),
            anomaly_threshold,
            event.header.pid,
            event.comm
        );
        stats.anomaly_alerts += 1;
    }

    if stats.consumed.is_multiple_of(50) || !matches.is_empty() {
        let need_heavy_scan = stats.consumed.is_multiple_of(500)
            || !matches.is_empty()
            || !corr_alerts.is_empty();
        // H-1.4：天然高频白名单进程（wget/curl/python 等 + KS_BASELINE_HIGHFREQ 扩展）
        // 跳过基线偏离与 ML 冷启动告警——这两类告警在训练期用固定阈值兜底，
        // 批量下载/构建这类白名单进程的正常突刺是冷启动误报的主要来源
        let is_high_freq_comm = !is_protected
            && baseline_mgr
                .lock()
                .await
                .is_inherently_high_freq(&event.comm);
        if !is_protected && !is_high_freq_comm {
            if let Some(dev) = baseline_mgr.lock().await.detect_deviation(event.header.pid) {
            let dim = dev
                .most_deviated_dimension
                .map(|d| format!("{:?}", d))
                .unwrap_or_else(|| "unknown".to_string());
            let alert = Alert::new(
                Severity::High,
                event.header.timestamp_ns,
                format!("基线偏离: {} (PID {})", dim, event.header.pid),
                "baseline_deviation".to_string(),
                ProcessInfo {
                    pid: event.header.pid,
                    ppid: event.header.ppid,
                    comm: event.comm.clone(),
                    uid: event.header.uid,
                    exe_path: None,
                    cmdline: None,
                },
            );
            forensic.log_alert(&alert).await;
            stats.anomaly_alerts += 1;
            }
        }

        if !is_protected && !is_high_freq_comm {
            if let Some(ml_result) = ml_detector.lock().await.detect(event.header.pid) {
            let dim_str = ml_result
                .dimensions
                .first()
                .map(|d| format!("{:?}", d.dimension))
                .unwrap_or_else(|| "unknown".to_string());
            let model_str = match ml_result.model {
                ks_engine::ml_detector::AnomalyModel::Ewma => "EWMA",
                ks_engine::ml_detector::AnomalyModel::ColdStart => "ColdStart",
            };
            let alert = Alert::new(
                Severity::High,
                event.header.timestamp_ns,
                format!(
                    "ML异常检测: {} (PID {}, {})",
                    dim_str, event.header.pid, model_str
                ),
                "ml_anomaly".to_string(),
                ProcessInfo {
                    pid: event.header.pid,
                    ppid: event.header.ppid,
                    comm: event.comm.clone(),
                    uid: event.header.uid,
                    exe_path: None,
                    cmdline: None,
                },
            );
            forensic.log_alert(&alert).await;
            stats.anomaly_alerts += 1;
            }
        }

        if need_heavy_scan {
            for family in process_tree_mgr.lock().await.anomalous_families() {
                for rel in &family.anomaly_relations {
                    let alert = Alert::new(
                        Severity::High,
                        event.header.timestamp_ns,
                        format!("进程树异常: {}", rel.anomaly_type),
                        "process_tree_anomaly".to_string(),
                        ProcessInfo {
                            pid: rel.child_pid,
                            ppid: rel.parent_pid,
                            comm: rel.child_comm.clone(),
                            uid: 0,
                            exe_path: None,
                            cmdline: None,
                        },
                    );
                    println!(
                        "  [进程树异常] {} → {} — {}",
                        rel.parent_comm, rel.child_comm, rel.anomaly_type
                    );
                    forensic.log_alert(&alert).await;
                    stats.anomaly_alerts += 1;
                }
            }
        }

        if need_heavy_scan {
            let pid_events: Vec<_> = aggregator
                .lock()
                .await
                .by_pid(event.header.pid)
                .into_iter()
                .cloned()
                .collect();
            if let Some(chain) = chain_reconstructor.reconstruct(&pid_events) {
                if chain.confidence > 0.5 {
                    println!(
                        "  [攻击链] PID {} — {:.0}% 置信度, {} 个阶段",
                        chain.root_pid,
                        chain.confidence * 100.0,
                        chain.steps.len()
                    );
                    for step in &chain.steps {
                        println!(
                            "    {}: {} ({} 个事件)",
                            format_phase(&step.phase),
                            step.description,
                            step.events.len()
                        );
                    }
                }
            }
        }
    }

    if stats.consumed.is_multiple_of(10) {
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

    prof_add(8, t0.elapsed().as_nanos() as u64);
    PROF_CNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    Ok(true)
}

fn correlation_to_alert(ca: &CorrelationAlert) -> Alert {
    let proc = ca
        .events
        .first()
        .map(|e| ProcessInfo {
            pid: e.header.pid,
            ppid: e.header.ppid,
            comm: e.comm.clone(),
            uid: e.header.uid,
            exe_path: e.filename.clone(),
            cmdline: e.args.clone(),
        })
        .unwrap_or_else(|| ProcessInfo {
            pid: 0,
            ppid: 0,
            comm: "unknown".to_string(),
            uid: 0,
            exe_path: None,
            cmdline: None,
        });

    let severity = match ca.severity.as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        _ => Severity::Low,
    };

    let ts = ca.events.first().map(|e| e.header.timestamp_ns).unwrap_or(0);
    let mut alert = Alert::new(severity, ts, ca.rule_name.clone(), ca.rule_name.clone(), proc);
    alert.description = ca.description.clone();
    alert.event_ids = ca.events.iter().map(|e| e.seq).collect();
    alert.mitre = ca.mitre.as_ref().map(|m| MitreInfo {
        tactic: m.tactic.clone(),
        technique: m.technique.clone(),
        sub_technique: None,
    });
    alert
}

fn severity_meets_threshold(severity: &Severity, threshold: &str) -> bool {
    let order = ["low", "medium", "high", "critical"];
    let sev_str = match severity {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    };
    let thr_idx = order.iter().position(|s| *s == threshold).unwrap_or(3);
    sev_str >= thr_idx
}

struct EventStats {
    consumed: u64,
    rule_alerts: u64,
    anomaly_alerts: u64,
}

impl EventStats {
    fn new() -> Self {
        Self {
            consumed: 0,
            rule_alerts: 0,
            anomaly_alerts: 0,
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

async fn load_rules(detector: &Arc<Mutex<DetectionEngine>>, rules_dir: &str) -> Result<()> {
    let rules_path = Path::new(rules_dir);
    if rules_path.is_dir() {
        let mut total = 0;
        for entry in std::fs::read_dir(rules_path)? {
            let entry = entry?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
            {
                let content = std::fs::read_to_string(&path)?;
                let count = detector.lock().await.load_rules_from_yaml(&content)?;
                println!(
                    "      {}: {} 条规则",
                    path.file_name().unwrap().to_string_lossy(),
                    count
                );
                total += count;
            }
        }
        if total == 0 {
            println!(
                "      [WARN] 未加载任何规则 (将仅使用异常评分，阈值 {:.2})",
                0.7
            );
        } else {
            println!("      总计: {} 条规则", total);
        }
    } else {
        println!(
            "      [WARN] 规则目录不存在: {} (将使用空规则集)",
            rules_dir
        );
    }
    Ok(())
}

async fn rule_hot_loader(detector: &Arc<Mutex<DetectionEngine>>, rules_dir: &str, log_dir: &str) {
    use std::collections::HashMap;
    use std::time::SystemTime;

    let mut file_mtimes: HashMap<String, SystemTime> = HashMap::new();
    let mut scan_interval = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        scan_interval.tick().await;

        let rules_path = Path::new(rules_dir);
        if !rules_path.is_dir() {
            continue;
        }

        let mut changed = false;
        let entries: Vec<_> = match std::fs::read_dir(rules_path) {
            Ok(e) => e.filter_map(|e| e.ok()).collect(),
            Err(_) => continue,
        };

        for entry in &entries {
            let path = entry.path();
            if !path
                .extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
            {
                continue;
            }
            let key = path.to_string_lossy().to_string();
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    let prev = file_mtimes.get(&key).copied();
                    if prev != Some(modified) {
                        changed = true;
                        file_mtimes.insert(key, modified);
                    }
                }
            }
        }

        if changed {
            log::info!("检测到规则文件变更，重新加载...");
            // H-1.5：热加载前后规则集可能变化，同步落一次完整性快照。
            // 未设 KS_RULES_DIGEST 时只记录（不比对），供事后回溯对照
            match ks_engine::rules_integrity::check_and_record(Path::new(rules_dir), Path::new(log_dir)) {
                Ok((i, v)) => log::info!(
                    "[rules-integrity] 热加载快照: digest={}… verdict={}",
                    &i.combined_digest[..16.min(i.combined_digest.len())],
                    match v {
                        ks_engine::rules_integrity::RulesIntegrityVerdict::NoBaseline => "no-baseline",
                        ks_engine::rules_integrity::RulesIntegrityVerdict::Match => "match",
                        ks_engine::rules_integrity::RulesIntegrityVerdict::Mismatch { .. } => "MISMATCH",
                    }
                ),
                Err(e) => log::warn!("[rules-integrity] 热加载快照失败: {}", e),
            }
            let mut new_detector = DetectionEngine::new();
            for entry in &entries {
                let path = entry.path();
                if path
                    .extension()
                    .is_some_and(|ext| ext == "yml" || ext == "yaml")
                {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        match new_detector.load_rules_from_yaml(&content) {
                            Ok(count) => log::info!(
                                "热加载: {} — {} 条规则",
                                path.file_name().unwrap().to_string_lossy(),
                                count
                            ),
                            Err(e) => log::warn!(
                                "热加载失败: {} — {} (保留旧规则)",
                                path.file_name().unwrap().to_string_lossy(),
                                e
                            ),
                        }
                    }
                }
            }
            *detector.lock().await = new_detector;
            log::info!(
                "规则热加载完成: {} 条规则",
                detector.lock().await.rule_count()
            );
        }
    }
}

#[allow(dead_code)]
trait AlertDisplay {
    fn header_pid_or_process(&self) -> String;
}

impl AlertDisplay for ks_core::alert::Alert {
    fn header_pid_or_process(&self) -> String {
        format!("PID={}", self.process.pid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::event::EventHeader;
    use ks_engine::aggregator::DecodedEvent;
    use ks_engine::correlation::{CorrelationCondition, CorrelationType, MitreMapping};

    fn make_decoded_event(pid: u32, comm: &str) -> DecodedEvent {
        let mut cb = [0u8; 16];
        let len = comm.len().min(16);
        cb[..len].copy_from_slice(&comm.as_bytes()[..len]);
        DecodedEvent {
            seq: 42,
            comm: comm.to_string(),
            header: EventHeader {
                event_type: 1,
                _pad1: 0,
                timestamp_ns: 1_000_000_000,
                pid,
                tid: 0,
                uid: 1000,
                ppid: 1,
                comm: cb,
                syscall_nr: 0,
                _pad2: 0,
                retval: 0,
            },
            filename: Some("/bin/test".to_string()),
            args: Some("test arg".to_string()),
            saddr: None,
            daddr: None,
            sport: None,
            dport: None,
            proto: None,
            target_pid: None,
            signal: None,
            file_bytes: None,
            module_name: None,
            prog_name: None,
            source_ns_inum: None,
            target_ns_inum: None,
            cap_eff: None,
            action: None,
        }
    }

    fn make_correlation_alert(severity: &str, with_mitre: bool) -> CorrelationAlert {
        CorrelationAlert {
            enforce: false,
            rule_name: "测试关联规则".to_string(),
            correlation_type: CorrelationType::Window {
                window_secs: 30,
                condition_a: CorrelationCondition::EventType(1),
                condition_b: CorrelationCondition::EventType(20),
            },
            events: vec![make_decoded_event(1234, "bash")],
            description: "测试描述".to_string(),
            severity: severity.to_string(),
            mitre: if with_mitre {
                Some(MitreMapping {
                    tactic: "TA0002".to_string(),
                    technique: "T1059.004".to_string(),
                })
            } else {
                None
            },
            confidence: 0.85,
        }
    }

    #[test]
    fn test_correlation_to_alert_basic() {
        let ca = make_correlation_alert("critical", false);
        let alert = correlation_to_alert(&ca);
        assert_eq!(alert.severity, Severity::Critical);
        assert_eq!(alert.title, "测试关联规则");
        assert_eq!(alert.rule_name, "测试关联规则");
        assert_eq!(alert.description, "测试描述");
        assert_eq!(alert.process.pid, 1234);
        assert_eq!(alert.process.comm, "bash");
        assert_eq!(alert.process.uid, 1000);
        assert_eq!(alert.process.ppid, 1);
    }

    #[test]
    fn test_correlation_to_alert_mitre_mapping() {
        let ca = make_correlation_alert("high", true);
        let alert = correlation_to_alert(&ca);
        let mitre = alert.mitre.expect("mitre should be present");
        assert_eq!(mitre.tactic, "TA0002");
        assert_eq!(mitre.technique, "T1059.004");
    }

    #[test]
    fn test_correlation_to_alert_empty_events() {
        let ca = CorrelationAlert {
            enforce: false,
            rule_name: "空事件".to_string(),
            correlation_type: CorrelationType::Window {
                window_secs: 30,
                condition_a: CorrelationCondition::EventType(1),
                condition_b: CorrelationCondition::EventType(20),
            },
            events: vec![],
            description: String::new(),
            severity: "low".to_string(),
            mitre: None,
            confidence: 0.5,
        };
        let alert = correlation_to_alert(&ca);
        assert_eq!(alert.process.pid, 0);
        assert_eq!(alert.process.comm, "unknown");
    }

    #[test]
    fn test_correlation_to_alert_severity_mapping() {
        assert_eq!(
            correlation_to_alert(&make_correlation_alert("critical", false)).severity,
            Severity::Critical
        );
        assert_eq!(
            correlation_to_alert(&make_correlation_alert("high", false)).severity,
            Severity::High
        );
        assert_eq!(
            correlation_to_alert(&make_correlation_alert("medium", false)).severity,
            Severity::Medium
        );
        assert_eq!(
            correlation_to_alert(&make_correlation_alert("low", false)).severity,
            Severity::Low
        );
        assert_eq!(
            correlation_to_alert(&make_correlation_alert("unknown", false)).severity,
            Severity::Low
        );
    }

    #[test]
    fn test_correlation_to_alert_event_ids() {
        let ca = make_correlation_alert("critical", false);
        let alert = correlation_to_alert(&ca);
        assert_eq!(alert.event_ids, vec![42]);
    }
}

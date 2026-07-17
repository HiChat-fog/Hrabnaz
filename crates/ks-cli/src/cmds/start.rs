use anyhow::Result;
use ks_core::alert::{Alert, MitreInfo, ProcessInfo};
use ks_core::rule::Severity;
use ks_engine::aggregator::EventAggregator;
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

use crate::cmds::{build_server_config, SecurityArgs};

#[cfg(target_os = "linux")]
const STATUS_FILE: &str = "/tmp/ks-status.json";
#[cfg(not(target_os = "linux"))]
const STATUS_FILE: &str = "./ks-status.json";

/// F4: ks-cli `start` 子命令入口 — 启动 eBPF 探针 + 检测引擎 + 数据服务。
///
/// `security` 参数仅在 `serve_port=Some(port)` 时生效（即 `--serve` 指定端口时
/// 才启动 ks-server）。当 `serve_port=None` 时，`security` 被忽略。
pub async fn run(
    rules_dir: &str,
    log_dir: &str,
    serve_port: Option<u16>,
    sd_notify: bool,
    security: &SecurityArgs,
) -> Result<()> {
    let start_time = Instant::now();

    println!("[1/6] 加载配置...");
    let mut config = Config::default();
    config.apply_env_overrides();
    config.validate()?;
    println!("      缓冲区大小: {}", config.engine.buffer_size);
    println!("      异常阈值: {}", config.detection.anomaly_threshold);
    println!("      取证日志目录: {}", config.forensic.log_dir);
    println!("      取证保留天数: {}", config.forensic.retention_days);

    // ── A7: 统一事件源 ──
    // Linux 上：EbpfModernSource 包装 loader，事件循环通过 trait 路由
    // 非 Linux：mock 回放（CI/演示）
    println!("[2/6] 加载 eBPF 探针（自动 tier 检测）...");
    let detected_tier = ks_engine::tier_detect::detect_ebpf_tier();
    let tier_label: &'static str = detected_tier.map(|t| t.as_str()).unwrap_or("unknown");
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
    // D6: 持有 Arc<ServerState> 而非仅 broadcast::Sender，
    // 使告警同时写入 REST 存储 + 广播给 WebSocket 订阅者。
    // Phase E1.2：将 map_reader 注入 ServerState，供 /api/v1/stats 端点读取 map_stats。
    // F4：用 SecurityArgs 构建 ServerConfig（auth/tls/audit/rate_limit），由 ks-server 应用。
    let serve_state: Option<std::sync::Arc<ks_server::ServerState>> = match serve_port {
        Some(port) => {
            let state = match map_reader {
                Some(mr) => {
                    std::sync::Arc::new(ks_server::ServerState::with_map_reader(tier_label, mr))
                }
                None => std::sync::Arc::new(ks_server::ServerState::with_tier(tier_label)),
            };
            let st = state.clone();
            let server_config = build_server_config(security);
            tokio::spawn(async move {
                if let Err(e) = ks_server::run_server_with_config(st, port, server_config).await {
                    log::warn!("ks-server 退出: {}", e);
                }
            });
            println!("      数据服务: http://127.0.0.1:{}/api/v1/", port);
            println!("      WebSocket: ws://127.0.0.1:{}/ws/alerts", port);
            Some(state)
        }
        None => None,
    };
    println!(
        "      事件源: {} [{}]",
        source.description(),
        source.kind().as_str()
    );

    println!("[3/6] 加载检测规则...");
    let detector = Arc::new(Mutex::new(DetectionEngine::new()));
    load_rules(&detector, rules_dir).await?;

    println!("[4/6] 初始化引擎组件...");
    let aggregator = Arc::new(Mutex::new(EventAggregator::new(config.engine.buffer_size)));
    // G1.1: 三引擎接线 — baseline（z-score 基线偏离）/ correlation（跨事件关联）/ process_tree（进程树异常）
    let baseline_mgr = Arc::new(Mutex::new(BaselineManager::new()));
    let correlation_engine = Arc::new(Mutex::new(CorrelationEngine::new(300)));
    let process_tree_mgr = Arc::new(Mutex::new(ProcessTreeManager::new()));
    // G4.1: EWMA 自适应检测器 — 与 ServerState 共享（feedback 端点可联动调整阈值）
    let ml_detector: Arc<Mutex<AdaptiveDetector>> = match &serve_state {
        Some(st) => st.ml_detector.clone(),
        None => Arc::new(Mutex::new(AdaptiveDetector::new())),
    };
    // G2.2: 用户态阻断管理器 — 与 ServerState 共享（REST 端点可手动阻断/解除）
    let block_mgr: Arc<Mutex<ks_engine::blocker::BlockManager>> = match &serve_state {
        Some(st) => st.block_manager.clone(),
        None => Arc::new(Mutex::new(ks_engine::blocker::BlockManager::new())),
    };
    // G2.3: 从配置初始化阻断策略
    {
        let mut bm = block_mgr.lock().await;
        bm.set_enabled(config.detection.block_enabled);
    }
    let block_ttl = config.detection.block_ttl_secs;
    let block_severity_threshold = config.detection.block_severity_threshold.clone();

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
    let chain_reconstructor = ChainReconstructor::new();

    println!("      聚合器缓冲区: {} 条", config.engine.buffer_size);
    println!("      取证日志: {}", forensic.lock().await.path().display());
    println!("      轮转阈值: {}MB", config.forensic.max_log_size_mb);

    println!("[5/6] 写入运行状态...");
    write_status_file();
    println!("      状态文件已写入 (供 stop 命令使用)");

    println!("[6/6] 启动规则热加载...");
    let hot_reload_rules_dir = rules_dir.to_string();
    let hot_reload_detector = detector.clone();
    tokio::spawn(async move {
        rule_hot_loader(&hot_reload_detector, &hot_reload_rules_dir).await;
    });
    println!("      监听规则目录变更: {}", rules_dir);

    println!();
    println!("      按 Ctrl+C 停止");
    println!();

    // 所有初始化完成（配置/eBPF/规则/引擎/状态/热加载/ks-server），
    // 进入事件循环前通知 systemd 服务就绪（Type=notify）。
    // 非 systemd 环境（无 NOTIFY_SOCKET）下 notify 静默失败，不影响运行。
    if sd_notify {
        #[cfg(target_os = "linux")]
        {
            // unset_environment=false 保留 NOTIFY_SOCKET 供后续 STATUS= 调用复用
            let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Ready]);
            log::info!("已通知 systemd 服务就绪");
        }
        #[cfg(not(target_os = "linux"))]
        {
            log::debug!("sd-notify 标志已忽略（非 Linux 平台，sd-notify crate 不可用）");
        }
    }

    let mut stats = EventStats::new();
    let anomaly_threshold = config.detection.anomaly_threshold;
    // mock 耗尽（loop_mode=false）时退出；eBPF ringbuf 暂空时 sleep 1ms 继续
    let continue_on_empty = !source.is_mock();

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!();
                println!("收到 Ctrl+C 信号，准备安全关闭...");
                break;
            }
            result = async {
                let bytes = match source.next_bytes().await {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        if continue_on_empty {
                            // eBPF ringbuf 暂空，sleep 1ms 后继续轮询
                            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                            return Ok(true);
                        } else {
                            // mock 耗尽，退出循环
                            return Ok(false);
                        }
                    }
                    Err(e) => return Err(e),
                };
                process_event_bytes(&bytes, &aggregator, &detector, &forensic, &chain_reconstructor, &mut stats, anomaly_threshold, &serve_state, &baseline_mgr, &correlation_engine, &process_tree_mgr, &ml_detector, &block_mgr, block_ttl, &block_severity_threshold).await
            } => {
                match result {
                    Ok(true) => {}
                    Ok(false) => {
                        println!("      事件源已耗尽，停止消费循环");
                        break;
                    }
                    Err(e) => {
                        log::warn!("事件处理失败: {}", e);
                        // eBPF 路径：错误后短暂 sleep 避免 busy loop
                        if continue_on_empty {
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        }
                    }
                }
            }
        }
    }

    println!();
    println!("安全关闭...");
    println!("      释放事件源（含 eBPF 探针 fd）...");
    // A7: source drop 时 EbpfModernSource 自动 drop EbpfLoader，
    // loader 内部 rings/bpf fd 自动关闭，无需显式 stop_all。
    drop(source);
    println!("      Flush 取证日志...");
    forensic.lock().await.flush()?;

    let elapsed = start_time.elapsed();
    let event_count = forensic.lock().await.event_count();
    let alert_count = forensic.lock().await.alert_count();
    println!("      事件总数: {} (消费: {})", event_count, stats.consumed);
    println!(
        "      告警总数: {} (规则: {}, 异常: {})",
        alert_count, stats.rule_alerts, stats.anomaly_alerts
    );
    println!(
        "      链尾哈希: {}",
        forensic.lock().await.chain_tail_hash()
    );
    println!("      运行时长: {:.1}s", elapsed.as_secs_f64());

    cleanup_status_file();
    println!("      内核哨兵已安全退出");

    Ok(())
}

/// 处理单条事件字节（统一入口，eBPF/mock 共用）
#[allow(clippy::too_many_arguments)]
async fn process_event_bytes(
    bytes: &[u8],
    aggregator: &Arc<Mutex<EventAggregator>>,
    detector: &Arc<Mutex<DetectionEngine>>,
    forensic: &Arc<Mutex<ForensicLogger>>,
    chain_reconstructor: &ChainReconstructor,
    stats: &mut EventStats,
    anomaly_threshold: f64,
    serve_state: &Option<std::sync::Arc<ks_server::ServerState>>,
    baseline_mgr: &Arc<Mutex<BaselineManager>>,
    correlation_engine: &Arc<Mutex<CorrelationEngine>>,
    process_tree_mgr: &Arc<Mutex<ProcessTreeManager>>,
    ml_detector: &Arc<Mutex<AdaptiveDetector>>,
    block_mgr: &Arc<Mutex<ks_engine::blocker::BlockManager>>,
    block_ttl: u64,
    block_severity_threshold: &str,
) -> Result<bool> {
    let event = aggregator.lock().await.decode(bytes)?;
    stats.consumed += 1;

    forensic.lock().await.log_event(&event)?;

    // G1.1/G1.2: 三引擎接线 — 在规则检测之前，更新基线/进程树/关联引擎
    // G1.2: ProcessTree 关联规则需查询进程树获取父进程信息，故 lock 顺序为
    // baseline → process_tree → correlation；调用完立即 drop pt_guard 避免后续
    // baseline_mgr.detect_deviation 时死锁。
    baseline_mgr.lock().await.update_from_event(&event);
    let mut pt_guard = process_tree_mgr.lock().await;
    pt_guard.update_from_event(&event);
    let corr_alerts = correlation_engine
        .lock()
        .await
        .detect_correlations_with_tree(&event, Some(&*pt_guard));
    drop(pt_guard);
    // G4.1: EWMA 自适应检测 — 更新在线学习模型
    ml_detector.lock().await.update_from_event(&event);
    for ca in &corr_alerts {
        let alert = correlation_to_alert(ca);
        println!(
            "  [关联告警] [{}] {} — PID: {}, 置信度: {:.0}%",
            alert.severity,
            alert.title,
            event.header.pid,
            ca.confidence * 100.0
        );
        forensic.lock().await.log_alert(&alert)?;
        if let Some(st) = serve_state {
            st.push_alert(alert.clone()).await;
            st.push_correlation_alert(ca.clone()).await;
        }
        stats.rule_alerts += 1;
        if let Some(mitre) = &alert.mitre {
            println!("    MITRE: {} / {}", mitre.tactic, mitre.technique);
        }
        // G2.2: 关联告警触发阻断
        if severity_meets_threshold(&alert.severity, block_severity_threshold)
            && block_mgr.lock().await.block_pid(
                event.header.pid,
                block_ttl,
                ks_engine::blocker::BlockReason::Correlation,
                &alert.title,
            )
        {
            println!("  [阻断] PID {} 已阻断 (关联告警)", event.header.pid);
        }
    }

    let matches = detector.lock().await.match_event(&event);
    for m in &matches {
        let alert = detector.lock().await.generate_alert(m, &event);
        println!(
            "  [规则告警] [{}] {} — PID: {}, COMM: {}",
            alert.severity, alert.title, alert.process.pid, event.comm
        );
        forensic.lock().await.log_alert(&alert)?;
        stats.rule_alerts += 1;
        if let Some(st) = serve_state {
            st.push_alert(alert.clone()).await;
        }

        if let Some(mitre) = &alert.mitre {
            println!("    MITRE: {} / {}", mitre.tactic, mitre.technique);
        }
        // G2.2: 规则告警触发阻断
        if severity_meets_threshold(&alert.severity, block_severity_threshold)
            && block_mgr.lock().await.block_pid(
                alert.process.pid,
                block_ttl,
                ks_engine::blocker::BlockReason::RuleMatch,
                &alert.rule_name,
            )
        {
            println!(
                "  [阻断] PID {} 已阻断 (规则: {})",
                alert.process.pid, alert.rule_name
            );
        }
    }

    let history: Vec<_> = aggregator
        .lock()
        .await
        .recent(1000)
        .into_iter()
        .cloned()
        .collect();
    let score = detector.lock().await.anomaly_score(&event, &history);
    if score > anomaly_threshold {
        println!(
            "  [异常告警] 评分: {:.2} (阈值: {:.2}) — PID: {}, COMM: {}",
            score, anomaly_threshold, event.header.pid, event.comm
        );
        stats.anomaly_alerts += 1;
    }

    if stats.consumed.is_multiple_of(50) || !matches.is_empty() {
        // G1.3: 周期推送基线快照到 ServerState（供 /api/v1/baselines 端点）
        if let Some(st) = serve_state {
            let snapshots: std::collections::HashMap<u32, _> = baseline_mgr
                .lock()
                .await
                .all_baselines()
                .iter()
                .map(|(pid, b)| (*pid, b.clone()))
                .collect();
            st.update_baselines(snapshots).await;
        }
        // G1.1: baseline 偏离检测 — z-score 超阈值时告警
        if let Some(dev) = baseline_mgr.lock().await.detect_deviation(event.header.pid) {
            let dim = dev
                .most_deviated_dimension
                .map(|d| format!("{:?}", d))
                .unwrap_or_else(|| "unknown".to_string());
            let alert = Alert::new(
                Severity::High,
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
            println!(
                "  [基线偏离] PID {} — 评分: {:.2}, 维度: {}",
                event.header.pid, dev.overall_score, dim
            );
            forensic.lock().await.log_alert(&alert)?;
            if let Some(st) = serve_state {
                st.push_alert(alert.clone()).await;
            }
            stats.anomaly_alerts += 1;
        }

        // G4.1: EWMA 自适应检测 — 双模型并行，任一触发即告警
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
            println!(
                "  [ML异常] PID {} — 评分: {:.2}, 模型: {}, 维度: {}",
                event.header.pid, ml_result.overall_score, model_str, dim_str
            );
            forensic.lock().await.log_alert(&alert)?;
            if let Some(st) = serve_state {
                st.push_alert(alert.clone()).await;
            }
            stats.anomaly_alerts += 1;
        }

        // G1.1: process_tree 异常族检测 — 进程树中出现异常父子关系时告警
        for family in process_tree_mgr.lock().await.anomalous_families() {
            for rel in &family.anomaly_relations {
                let alert = Alert::new(
                    Severity::High,
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
                forensic.lock().await.log_alert(&alert)?;
                if let Some(st) = serve_state {
                    st.push_alert(alert.clone()).await;
                }
                stats.anomaly_alerts += 1;
            }
        }

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

    if stats.consumed.is_multiple_of(10) {
        println!(
            "  [进度] 已处理 {} 条事件, {} 条告警",
            stats.consumed,
            stats.rule_alerts + stats.anomaly_alerts
        );
    }

    Ok(true)
}

/// G1.1: 将 CorrelationAlert 转换为 ks_core::alert::Alert，复用现有告警管道。
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

    let mut alert = Alert::new(severity, ca.rule_name.clone(), ca.rule_name.clone(), proc);
    alert.description = ca.description.clone();
    alert.event_ids = ca.events.iter().map(|e| e.seq).collect();
    alert.mitre = ca.mitre.as_ref().map(|m| MitreInfo {
        tactic: m.tactic.clone(),
        technique: m.technique.clone(),
        sub_technique: None,
    });
    alert
}

/// G2.3: 检查告警严重度是否达到阻断阈值。
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
    let status_path = get_status_file_path();
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

    if let Err(e) = std::fs::write(
        status_path,
        serde_json::to_string_pretty(&status).unwrap_or_default(),
    ) {
        log::warn!("状态文件写入失败: {} — {}", status_path, e);
    }
}

fn cleanup_status_file() {
    let status_path = get_status_file_path();
    let _ = std::fs::remove_file(status_path);
}

fn get_status_file_path() -> &'static str {
    STATUS_FILE
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

async fn rule_hot_loader(detector: &Arc<Mutex<DetectionEngine>>, rules_dir: &str) {
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

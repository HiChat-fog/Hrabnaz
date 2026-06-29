use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use ks_engine::detector::DetectionEngine;
use ks_engine::aggregator::EventAggregator;
use ks_engine::forensic::{ForensicLogger, RotationConfig};
use ks_engine::chain::ChainReconstructor;
use ks_engine::config::Config;
use ks_engine::event_source::{EventSource, default_event_source};

#[cfg(target_os = "linux")]
const STATUS_FILE: &str = "/tmp/ks-status.json";
#[cfg(not(target_os = "linux"))]
const STATUS_FILE: &str = "./ks-status.json";

pub async fn run(rules_dir: &str, log_dir: &str) -> Result<()> {
    let start_time = Instant::now();

    println!("[1/6] 加载配置...");
    let mut config = Config::default();
    config.apply_env_overrides();
    config.validate()?;
    println!("      缓冲区大小: {}", config.engine.buffer_size);
    println!("      异常阈值: {}", config.detection.anomaly_threshold);
    println!("      取证日志目录: {}", config.forensic.log_dir);
    println!("      取证保留天数: {}", config.forensic.retention_days);

    println!("[2/6] 加载 eBPF 探针...");
    let mut loader = ks_engine::loader::EbpfLoader::new();
    loader.start_all().await?;
    println!("      探针已挂载: {} 个", loader.loaded_probes().len());

    println!("[3/6] 加载检测规则...");
    let detector = Arc::new(Mutex::new(DetectionEngine::new()));
    load_rules(&detector, rules_dir).await?;

    println!("[4/6] 初始化引擎组件...");
    let aggregator = Arc::new(Mutex::new(
        EventAggregator::new(config.engine.buffer_size)
    ));

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
    let forensic = Arc::new(Mutex::new(
        ForensicLogger::with_rotation(log_path, rotation_config)?
    ));
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
    let event_source = default_event_source();
    println!("      事件源: {}", event_source.description());
    println!("      按 Ctrl+C 停止");
    println!();

    #[cfg(target_os = "linux")]
    let using_ebpf = loader.loaded_probes().len() > 0;
    #[cfg(not(target_os = "linux"))]
    let using_ebpf = false;
    if using_ebpf {
        println!("      事件源: eBPF ring buffer (4 tracepoints)");
    } else {
        println!("      事件源: {}", event_source.description());
    }
    let mut source: Box<dyn EventSource> = event_source;
    let mut stats = EventStats::new();
    let anomaly_threshold = config.detection.anomaly_threshold;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!();
                println!("收到 Ctrl+C 信号，准备安全关闭...");
                break;
            }
            result = async {
                // Linux 上优先从 eBPF ring buffer 读，否则 fallback 到 mock
                #[cfg(target_os = "linux")]
                {
                    if using_ebpf {
                        if let Some(data) = loader.try_next_event() {
                            return consume_next_event_data(data, &aggregator, &detector, &forensic, &chain_reconstructor, &mut stats, anomaly_threshold).await;
                        }
                        // ring buffer 空时等 1ms
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        return Ok(true);
                    }
                }
                // Mock 或非 Linux：从事件源读
                let bytes = match source.next_bytes() {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        #[cfg(not(target_os = "linux"))]
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        return Ok(true);
                    }
                    Err(e) => return Err(e),
                };
                consume_next_event_data(bytes, &aggregator, &detector, &forensic, &chain_reconstructor, &mut stats, anomaly_threshold).await
            } => {
                match result {
                    Ok(true) => {}
                    Ok(false) => {
                        println!("      事件源已耗尽，停止消费循环");
                        break;
                    }
                    Err(e) => {
                        log::warn!("事件处理失败: {}", e);
                        #[cfg(not(target_os = "linux"))]
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    }
                }
            }
        }
    }

    println!();
    println!("安全关闭...");
    println!("      停止探针...");
    loader.stop_all().await?;
    println!("      Flush 取证日志...");
    forensic.lock().await.flush()?;

    let elapsed = start_time.elapsed();
    let event_count = forensic.lock().await.event_count();
    let alert_count = forensic.lock().await.alert_count();
    println!("      事件总数: {} (消费: {})", event_count, stats.consumed);
    println!("      告警总数: {} (规则: {}, 异常: {})", alert_count, stats.rule_alerts, stats.anomaly_alerts);
    println!("      链尾哈希: {}", forensic.lock().await.chain_tail_hash());
    println!("      运行时长: {:.1}s", elapsed.as_secs_f64());

    cleanup_status_file();
    println!("      内核哨兵已安全退出");

    Ok(())
}

/// 直接处理原始事件字节（来自 eBPF ring buffer）
async fn consume_next_event_data(
    data: Vec<u8>,
    aggregator: &Arc<Mutex<EventAggregator>>,
    detector: &Arc<Mutex<DetectionEngine>>,
    forensic: &Arc<Mutex<ForensicLogger>>,
    chain_reconstructor: &ChainReconstructor,
    stats: &mut EventStats,
    anomaly_threshold: f64,
) -> Result<bool> {
    process_event_bytes(&data, aggregator, detector, forensic, chain_reconstructor, stats, anomaly_threshold).await
}

async fn consume_next_event(
    source: &mut dyn EventSource,
    aggregator: &Arc<Mutex<EventAggregator>>,
    detector: &Arc<Mutex<DetectionEngine>>,
    forensic: &Arc<Mutex<ForensicLogger>>,
    chain_reconstructor: &ChainReconstructor,
    stats: &mut EventStats,
    anomaly_threshold: f64,
) -> Result<bool> {
    let bytes = match source.next_bytes()? {
        Some(b) => b,
        None => return Ok(false),
    };
    process_event_bytes(&bytes, aggregator, detector, forensic, chain_reconstructor, stats, anomaly_threshold).await
}

/// 处理单条事件字节（consume_next_event 和 ring buffer 共用）
async fn process_event_bytes(
    bytes: &[u8],
    aggregator: &Arc<Mutex<EventAggregator>>,
    detector: &Arc<Mutex<DetectionEngine>>,
    forensic: &Arc<Mutex<ForensicLogger>>,
    chain_reconstructor: &ChainReconstructor,
    stats: &mut EventStats,
    anomaly_threshold: f64,
) -> Result<bool> {
    let event = aggregator.lock().await.decode(bytes)?;
    stats.consumed += 1;

    forensic.lock().await.log_event(&event)?;

    let matches = detector.lock().await.match_event(&event);
    for m in &matches {
        let alert = detector.lock().await.generate_alert(m, &event);
        println!("  [规则告警] [{}] {} — PID: {}, COMM: {}",
                 alert.severity, alert.title, alert.header_pid_or_process(), event.comm);
        forensic.lock().await.log_alert(&alert)?;
        stats.rule_alerts += 1;

        if let Some(mitre) = &alert.mitre {
            println!("    MITRE: {} / {}", mitre.tactic, mitre.technique);
        }
    }

    let history: Vec<_> = aggregator.lock().await.recent(1000)
        .into_iter().cloned().collect();
    let score = detector.lock().await.anomaly_score(&event, &history);
    if score > anomaly_threshold {
        println!("  [异常告警] 评分: {:.2} (阈值: {:.2}) — PID: {}, COMM: {}",
                 score, anomaly_threshold, event.header.pid, event.comm);
        stats.anomaly_alerts += 1;
    }

    if stats.consumed % 50 == 0 || !matches.is_empty() {
        let pid_events: Vec<_> = aggregator.lock().await.by_pid(event.header.pid)
            .into_iter().cloned().collect();
        if let Some(chain) = chain_reconstructor.reconstruct(&pid_events) {
            if chain.confidence > 0.5 {
                println!("  [攻击链] PID {} — {:.0}% 置信度, {} 个阶段",
                         chain.root_pid, chain.confidence * 100.0, chain.steps.len());
                for step in &chain.steps {
                    println!("    {}: {} ({} 个事件)",
                             format_phase(&step.phase), step.description, step.events.len());
                }
            }
        }
    }

    if stats.consumed % 10 == 0 {
        println!("  [进度] 已处理 {} 条事件, {} 条告警",
                 stats.consumed, stats.rule_alerts + stats.anomaly_alerts);
    }

    Ok(true)
}

struct EventStats {
    consumed: u64,
    rule_alerts: u64,
    anomaly_alerts: u64,
}

impl EventStats {
    fn new() -> Self {
        Self { consumed: 0, rule_alerts: 0, anomaly_alerts: 0 }
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

    if let Err(e) = std::fs::write(&status_path, serde_json::to_string_pretty(&status).unwrap_or_default()) {
        log::warn!("状态文件写入失败: {} — {}", status_path, e);
    }
}

fn cleanup_status_file() {
    let status_path = get_status_file_path();
    let _ = std::fs::remove_file(&status_path);
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
            if path.extension().map_or(false, |ext| ext == "yml" || ext == "yaml") {
                let content = std::fs::read_to_string(&path)?;
                let count = detector.lock().await.load_rules_from_yaml(&content)?;
                println!("      {}: {} 条规则", path.file_name().unwrap().to_string_lossy(), count);
                total += count;
            }
        }
        if total == 0 {
            println!("      [WARN] 未加载任何规则 (将仅使用异常评分，阈值 {:.2})", 0.7);
        } else {
            println!("      总计: {} 条规则", total);
        }
    } else {
        println!("      [WARN] 规则目录不存在: {} (将使用空规则集)", rules_dir);
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
            if !path.extension().map_or(false, |ext| ext == "yml" || ext == "yaml") {
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
                if path.extension().map_or(false, |ext| ext == "yml" || ext == "yaml") {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        match new_detector.load_rules_from_yaml(&content) {
                            Ok(count) => log::info!("热加载: {} — {} 条规则",
                                path.file_name().unwrap().to_string_lossy(), count),
                            Err(e) => log::warn!("热加载失败: {} — {} (保留旧规则)",
                                path.file_name().unwrap().to_string_lossy(), e),
                        }
                    }
                }
            }
            *detector.lock().await = new_detector;
            log::info!("规则热加载完成: {} 条规则", detector.lock().await.rule_count());
        }
    }
}

trait AlertDisplay {
    fn header_pid_or_process(&self) -> String;
}

impl AlertDisplay for ks_core::alert::Alert {
    fn header_pid_or_process(&self) -> String {
        format!("PID={}", self.process.pid)
    }
}
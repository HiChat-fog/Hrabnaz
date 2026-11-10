//! 引擎运行时（ROADMAP H-7 引擎内聚）。
//!
//! 把原先散落在 hrabnaz-cli `start.rs` 里的两样东西收敛为本模块的公共 API：
//! 1. **事件处理主链**：decode → 取证入链 → 基线 → 进程树 → 关联 → ML → 规则 →
//!    周期重扫（基线偏离 / ML / 进程树家族 / 攻击链还原）；
//! 2. **引擎生命周期**：事件源/tier 路由、规则加载与热加载、规则完整性校验、
//!    取证 logger + worker、block_decisions pin 与内核下发、老内核用户态 killer、
//!    心跳任务。
//!
//! 设计约束（有意为之）：
//! - **引擎不产生任何 UI 输出**：检测过程只写 `Alert`/取证链，检测结果的呈现
//!   （打印/JSON/HTTP）由消费方对 [`EngineEffect`] 自行决定；
//! - **循环控制权在消费方**：引擎暴露 [`Engine::tick`]/[`Engine::process_event`]，
//!   CLI 的 Ctrl+C/SIGTERM select 循环、嵌入方的自有循环都是同一公共面上的薄壳；
//! - 引擎内部单消费者持有全部检测状态（除热加载共享的 detector 与取证的 worker），
//!   不含锁/回调解耦层。

use anyhow::Result;
use hrabnaz_core::alert::{Alert, ProcessInfo};
use hrabnaz_core::rule::Severity;
use log::{info, warn};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::aggregator::{DecodedEvent, EventAggregator};
use crate::baseline::BaselineManager;
use crate::blocker::{BlockManager, BlockReason};
use crate::chain::{AttackStep, ChainReconstructor};
use crate::config::Config;
use crate::correlation::CorrelationEngine;
use crate::detector::DetectionEngine;
use crate::event_source::{EventSource, SourceKind};
use crate::forensic::{ForensicLogger, RotationConfig};
use crate::loader::BpfMapReader;
use crate::ml_detector::AdaptiveDetector;
use crate::process_tree::ProcessTreeManager;
use crate::rules_integrity::{check_and_record, mismatch_alert, RulesIntegrityVerdict};
use crate::tier_detect::detect_ebpf_tier;

// ─────────────────────────── 选项与信息 ───────────────────────────

/// 事件源获取方式
pub enum EventSourceSpec {
    /// 与 CLI 相同的行为：tier_detect 自动路由（aya modern/legacy/ancient、
    /// NOBTF C loader），失败回退 mock。需要 root。
    Auto,
    /// 注入现成的事件源与 map reader（测试/嵌入方自带来源）
    Provided(Box<dyn EventSource>, Option<Arc<dyn BpfMapReader>>),
}

pub struct EngineOptions {
    pub config: Config,
    pub rules_dir: String,
    /// 已解析的取证日志目录（"/var/log/ks 不存在则回退 ./logs" 之类的部署策略
    /// 由调用方决定后传入）
    pub log_dir: String,
    pub source: EventSourceSpec,
    /// 心跳文件路径（H-1.6 watchdog 依赖）；None = 不写心跳
    pub heartbeat_path: Option<PathBuf>,
    /// ML 学习期覆盖（测试用）；None = 走 HRABNAZ_ML_OBSERVE_SEC 环境/默认值
    pub ml_observe_sec: Option<u64>,
}

/// 引擎启动后的静态信息（供消费方打印"启动横幅"这类内容）
pub struct EngineInfo {
    /// tier_detect 探测结果（Provided 源时为 None）
    pub tier_detected: Option<SourceKind>,
    pub source_kind: SourceKind,
    pub source_desc: String,
    /// 规则目录是否存在（不存在时规则集为空，引擎照常运行）
    pub rules_dir_exists: bool,
    /// (文件名, 规则数)，文件名序
    pub rules_files: Vec<(String, usize)>,
    pub rules_total: usize,
    /// block_decisions pin 成功时的通道路径（ks block 可用性标志）
    pub block_channel: Option<String>,
    pub user_kill_enabled: bool,
    /// (目录指纹, 比对结论)；规则目录不存在时为 None
    pub rules_integrity: Option<(String, RulesIntegrityVerdict)>,
    pub forensic_path: PathBuf,
}

// ─────────────────────────── 处理结果（公共面） ───────────────────────────

/// 告警来源：展示侧需要的附加上下文（置信度/触发 pid/父子进程）随来源携带，
/// 避免消费方再去反查
pub enum AlertSource {
    Rule,
    Correlation {
        confidence: f64,
        trigger_pid: u32,
    },
    BaselineDeviation,
    MlAnomaly,
    ProcessTree {
        parent_comm: String,
        child_comm: String,
        anomaly_type: String,
    },
}

pub struct RaisedAlert {
    pub alert: Alert,
    pub source: AlertSource,
}

/// 阻断执行通道
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedVia {
    Rule,
    Correlation,
    /// 非 Modern tier 的用户态补杀（老内核无 bpf_send_signal）
    UserKill,
}

pub struct BlockedRecord {
    pub pid: u32,
    /// 规则名（Rule）/关联规则名（Correlation）/ BlockReason 字符串（UserKill）
    pub reason: String,
    pub via: BlockedVia,
}

/// 超阈值异常评分（展示用，不入取证链——与旧 CLI 行为一致）
pub struct ScoreEvent {
    pub pid: u32,
    pub comm: String,
    pub score: f64,
    pub threshold: f64,
}

pub struct ChainFinding {
    pub root_pid: u32,
    pub confidence: f64,
    pub steps: Vec<AttackStep>,
}

/// 单次处理（tick/process_event）产生的全部效果，**按发生顺序**排列——
/// 消费方顺序遍历即可复现引擎的检测叙事
pub enum EngineEffect {
    /// Box: Alert 结构体 ~512B，效果向量按条累积时避免整个枚举被撑大
    Alert(Box<RaisedAlert>),
    Blocked(BlockedRecord),
    Score(ScoreEvent),
    Chain(ChainFinding),
}

#[derive(Default)]
pub struct EngineOutcome {
    /// 本次处理的原始事件条数
    pub consumed: usize,
    /// 事件源耗尽（仅 mock/文件回放类源会置位；真实探针源永不为 true）
    pub exhausted: bool,
    pub effects: Vec<EngineEffect>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct EngineStats {
    pub consumed: u64,
    pub rule_alerts: u64,
    pub anomaly_alerts: u64,
    /// 被去重窗口压掉的告警数（仅观测用；压制策略见 AlertThrottle）
    pub suppressed_alerts: u64,
    /// 自身进程事件丢弃数：取证写入/gzip 线程与引擎同 tgid，不丢弃会自反馈
    pub self_events_dropped: u64,
    /// 同 (pid, 路径) 重复读写被合并的事件数：只保留窗口内首条
    pub repeated_io_collapsed: u64,
    /// 取证日志目录内的读写事件丢弃数（消费自身产物的放大回路）
    pub self_forensic_events_dropped: u64,
}

pub struct ShutdownSummary {
    pub consumed: u64,
    /// 入取证链的事件数
    pub events_logged: u64,
    /// 入取证链的告警数
    pub alerts_logged: u64,
    pub rule_alerts: u64,
    pub anomaly_alerts: u64,
    pub chain_tail_hash: String,
    pub elapsed_secs: f64,
}

// ─────────────────────────── 剖析（HRABNAZ_PROF=1 时输出到 stderr） ───────────────────────────

static PROF_NS: [AtomicU64; 9] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static PROF_CNT: AtomicU64 = AtomicU64::new(0);

fn prof_add(idx: usize, ns: u64) {
    PROF_NS[idx].fetch_add(ns, std::sync::atomic::Ordering::Relaxed);
}

fn prof_emit() {
    if std::env::var("HRABNAZ_PROF").as_deref() != Ok("1") {
        return;
    }
    let cnt = PROF_CNT.load(std::sync::atomic::Ordering::Relaxed);
    if cnt == 0 {
        return;
    }
    let names = [
        "decode",
        "forensic_log",
        "baseline",
        "process_tree+corr",
        "ml",
        "detector_match",
        "anomaly_score(incr)",
        "forensic_alert",
        "total",
    ];
    let mut s = format!("[prof] events={}\n", cnt);
    for (i, n) in names.iter().enumerate() {
        let ns = PROF_NS[i].load(std::sync::atomic::Ordering::Relaxed);
        let avg_ns = ns / cnt.max(1);
        s.push_str(&format!(
            "  {:<28} total={:>10}μs  avg={:>8}ns\n",
            n,
            ns / 1000,
            avg_ns
        ));
    }
    eprintln!("{}", s);
}

// ─────────────────────────── 取证异步写入 ───────────────────────────

enum ForensicOp {
    Event(Arc<DecodedEvent>),
    /// Box: 同 EngineEffect::Alert（Alert ~512B）
    Alert(Box<Alert>),
}

struct ForensicSink {
    tx: tokio::sync::mpsc::Sender<ForensicOp>,
}

impl ForensicSink {
    async fn log_event(&self, event: &Arc<DecodedEvent>) {
        if self
            .tx
            .send(ForensicOp::Event(event.clone()))
            .await
            .is_err()
        {
            warn!("forensic worker已退出,事件丢失");
        }
    }
    async fn log_alert(&self, alert: &Alert) {
        if self
            .tx
            .send(ForensicOp::Alert(Box::new(alert.clone())))
            .await
            .is_err()
        {
            warn!("forensic worker已退出,告警丢失");
        }
    }
}

/// 取证目录规范化：去掉尾部重复分隔符后补一个，便于按前缀整段匹配。
fn normalize_dir(dir: &str) -> String {
    let trimmed = dir.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else {
        format!("{}/", trimmed)
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
            warn!("forensic写入失败: {}", e);
        }
    }
    if let Err(e) = forensic.lock().await.flush() {
        warn!("forensic flush失败: {}", e);
    }
}

// ─────────────────────────── 规则加载 / 热加载 ───────────────────────────

/// 目录扫描 → 逐文件加载。返回 (文件, 规则数) 列表；规则目录不存在不算错误
/// （引擎照常运行，只是规则集为空——与旧 CLI 行为一致）
fn load_rules_into(
    detector: &mut DetectionEngine,
    rules_dir: &str,
) -> Result<(bool, Vec<(String, usize)>)> {
    let rules_path = std::path::Path::new(rules_dir);
    let mut files = Vec::new();
    if rules_path.is_dir() {
        for entry in std::fs::read_dir(rules_path)? {
            let entry = entry?;
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
            {
                let content = std::fs::read_to_string(&path)?;
                let count = detector.load_rules_from_yaml(&content)?;
                files.push((
                    path.file_name().unwrap().to_string_lossy().to_string(),
                    count,
                ));
            }
        }
        Ok((true, files))
    } else {
        Ok((false, files))
    }
}

/// 规则热加载（H-1.5 起每次重载同步落完整性快照）
async fn rule_hot_loader(
    detector: Arc<Mutex<DetectionEngine>>,
    rules_dir: String,
    log_dir: String,
) {
    use std::collections::HashMap;
    use std::time::SystemTime;

    let mut file_mtimes: HashMap<String, SystemTime> = HashMap::new();
    let mut scan_interval = tokio::time::interval(std::time::Duration::from_secs(5));

    loop {
        scan_interval.tick().await;

        let rules_path = std::path::Path::new(&rules_dir);
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
            info!("检测到规则文件变更，重新加载...");
            // H-1.5：热加载前后规则集可能变化，同步落一次完整性快照
            match check_and_record(
                std::path::Path::new(&rules_dir),
                std::path::Path::new(&log_dir),
            ) {
                Ok((i, v)) => info!(
                    "[rules-integrity] 热加载快照: digest={}… verdict={}",
                    &i.combined_digest[..16.min(i.combined_digest.len())],
                    match v {
                        RulesIntegrityVerdict::NoBaseline => "no-baseline",
                        RulesIntegrityVerdict::Match => "match",
                        RulesIntegrityVerdict::Mismatch { .. } => "MISMATCH",
                    }
                ),
                Err(e) => warn!("[rules-integrity] 热加载快照失败: {}", e),
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
                            Ok(count) => info!(
                                "热加载: {} — {} 条规则",
                                path.file_name().unwrap().to_string_lossy(),
                                count
                            ),
                            Err(e) => warn!(
                                "热加载失败: {} — {} (保留旧规则)",
                                path.file_name().unwrap().to_string_lossy(),
                                e
                            ),
                        }
                    }
                }
            }
            *detector.lock().await = new_detector;
            info!(
                "规则热加载完成: {} 条规则",
                detector.lock().await.rule_count()
            );
        }
    }
}

/// 阻断门槛：severity 达到配置阈值才允许写 block_decisions
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

// ─────────────────────────── 引擎 ───────────────────────────

/// 告警去重窗口（H-4 误报压制）。
///
/// 同一 (规则名, pid) 在窗口内只发一条告警：
/// - 事件型（普通规则/关联规则）窗口 60s——避免同一攻击行为逐事件刷屏；
/// - 状态型（ml_anomaly / baseline_deviation / process_tree_anomaly）窗口
///   1800s——它们描述"这个进程当前状态异常"，常驻代理会持续命中，
///   进入异常态告警一次即可，不应按事件重复。
///
/// `HRABNAZ_ALERT_COOLDOWN_SEC` 覆盖两类窗口（0 = 关闭去重）。
/// 重复 I/O 合并：同一进程对同一路径的 open/read/write 在一个窗口内只保留首条。
/// 逐条记录同一文件的连续读写不提供新的取证信息，却能把日志放大两三个数量级
/// （真机：索引器写 SQLite 1 小时 170 万条 file_write）。删除/改名/改权限不合并。
struct RepeatIoFilter {
    seen: std::collections::HashMap<(u32, String), Instant>,
    window: Duration,
}

impl RepeatIoFilter {
    fn new() -> Self {
        Self {
            seen: std::collections::HashMap::new(),
            window: Duration::from_secs(
                std::env::var("HRABNAZ_REPEAT_IO_WINDOW_SEC")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(10),
            ),
        }
    }

    /// 返回 true 表示应保留（窗口内首条），false 表示合并掉。
    fn keep(&mut self, event: &hrabnaz_core::event::DecodedEvent) -> bool {
        const FILE_OPEN: u32 = 10;
        const FILE_READ: u32 = 11;
        const FILE_WRITE: u32 = 12;
        let et = event.header.event_type;
        if et != FILE_OPEN && et != FILE_READ && et != FILE_WRITE {
            return true;
        }
        let Some(path) = event.filename.as_deref() else {
            return true;
        };
        if self.window.is_zero() {
            return true;
        }
        let key = (event.header.pid, path.to_string());
        let now = Instant::now();
        if let Some(last) = self.seen.get(&key) {
            if now.saturating_duration_since(*last) < self.window {
                return false;
            }
        }
        if self.seen.len() > 65536 {
            self.seen
                .retain(|_, t| now.saturating_duration_since(*t) < self.window);
        }
        self.seen.insert(key, now);
        true
    }
}

struct AlertThrottle {
    last: std::collections::HashMap<(String, u32), Instant>,
    override_secs: Option<u64>,
}

impl AlertThrottle {
    fn new() -> Self {
        Self {
            last: std::collections::HashMap::new(),
            override_secs: std::env::var("HRABNAZ_ALERT_COOLDOWN_SEC")
                .ok()
                .and_then(|v| v.parse::<u64>().ok()),
        }
    }

    fn ttl_secs(rule_name: &str, override_secs: Option<u64>) -> u64 {
        if let Some(v) = override_secs {
            return v;
        }
        match rule_name {
            "ml_anomaly" | "baseline_deviation" | "process_tree_anomaly" => 1800,
            _ => 60,
        }
    }

    /// `now` 显式传入便于单测；窗口从"上次放行"起算，不随被压制事件续期
    fn allow_at(&mut self, rule_name: &str, pid: u32, now: Instant) -> bool {
        let ttl = Self::ttl_secs(rule_name, self.override_secs);
        if ttl == 0 {
            return true;
        }
        let key = (rule_name.to_string(), pid);
        if let Some(last) = self.last.get(&key) {
            if now.saturating_duration_since(*last).as_secs() < ttl {
                return false;
            }
        }
        if self.last.len() > 8192 {
            // 长跑兜底：重置窗口状态（最多多放行一轮，不会无限膨胀）
            self.last.clear();
        }
        self.last.insert(key, now);
        true
    }

    fn allow(&mut self, rule_name: &str, pid: u32) -> bool {
        self.allow_at(rule_name, pid, Instant::now())
    }
}

pub struct Engine {
    config: Config,
    source: Box<dyn EventSource>,
    aggregator: EventAggregator,
    // Arc：热加载任务持有写端
    detector: Arc<Mutex<DetectionEngine>>,
    baseline_mgr: BaselineManager,
    correlation_engine: CorrelationEngine,
    process_tree_mgr: ProcessTreeManager,
    ml_detector: AdaptiveDetector,
    block_mgr: BlockManager,
    // Arc：取证 worker 持有写端
    forensic: Arc<Mutex<ForensicLogger>>,
    forensic_sink: ForensicSink,
    forensic_worker: tokio::task::JoinHandle<()>,
    chain_reconstructor: ChainReconstructor,
    stats: EngineStats,
    alert_throttle: AlertThrottle,
    repeat_io_filter: RepeatIoFilter,
    anomaly_threshold: f64,
    block_ttl: u64,
    block_severity_threshold: String,
    protected_pids: HashSet<u32>,
    /// 引擎自身 tgid（含 tokio 写入线程与 gzip 线程）：事件头 pid 即 tgid，
    /// 与之相同的事件在进任何消费方之前整条丢弃
    self_tgid: u32,
    /// 本实例取证日志目录（规范化后带末尾分隔符）；读取/写入该目录下文件的事件
    /// 在进任何消费方之前丢弃，避免"消费自己的产物"形成放大回路
    self_forensic_dir: String,
    block_pinned: bool,
    info: EngineInfo,
    hot_reload_task: tokio::task::JoinHandle<()>,
    heartbeat_task: Option<tokio::task::JoinHandle<()>>,
    heartbeat_path: Option<PathBuf>,
    heartbeat_stats: Arc<AtomicU64>,
    kill_notices_rx: Option<tokio::sync::mpsc::UnboundedReceiver<(u32, String)>>,
    _killer_task: Option<tokio::task::JoinHandle<()>>,
    start_time: Instant,
}

impl Engine {
    /// 生命周期起点：事件源/tier 路由 → 规则加载+完整性校验 → 组件组装 →
    /// 阻断通道（pin/内核下发/用户态 killer）→ 取证 worker → 心跳 → 热加载。
    pub async fn start(options: EngineOptions) -> Result<Engine> {
        let start_time = Instant::now();
        let config = options.config;

        // 1. 事件源（tier 自动路由或注入）
        let (source, map_reader, tier_detected) = match options.source {
            EventSourceSpec::Auto => {
                let tier = detect_ebpf_tier();
                if let Some(t) = tier {
                    info!("[tier-detect] 检测到 tier: {}", t.as_str());
                }
                let (s, mr) = crate::event_source::default_event_source().await;
                (s, mr, tier)
            }
            EventSourceSpec::Provided(s, mr) => (s, mr, None),
        };
        let source_kind = source.kind();
        let source_desc = source.description().to_string();
        let protected_pids: HashSet<u32> = source.protected_pids().iter().copied().collect();

        // 2. 规则加载
        let detector = Arc::new(Mutex::new(DetectionEngine::new()));
        let (rules_dir_exists, rules_files) = {
            let mut d = detector.lock().await;
            load_rules_into(&mut d, &options.rules_dir)?
        };
        let rules_total: usize = rules_files.iter().map(|(_, c)| *c).sum();

        // 3. 组件组装
        let mut aggregator = EventAggregator::new(config.engine.buffer_size);
        let baseline_mgr = BaselineManager::new();
        let correlation_engine = CorrelationEngine::new(300);
        let process_tree_mgr = ProcessTreeManager::new();
        let ml_detector = match options.ml_observe_sec {
            Some(sec) => {
                AdaptiveDetector::with_config(crate::ml_detector::FixedThresholds::default(), sec)
            }
            None => AdaptiveDetector::from_env(),
        };
        let mut block_mgr = BlockManager::new();
        block_mgr.set_enabled(config.detection.block_enabled);
        if let Some(mr) = &map_reader {
            block_mgr.set_kernel_sink(Arc::new(crate::blocker::MapWriterSink(mr.clone())));
        }

        // 4. 阻断通道 pin（ks block 跨进程访问）
        let block_channel = match &map_reader {
            Some(mr) => match mr.pin_block_map(crate::blocker::BLOCK_DECISIONS_PIN) {
                Ok(()) => Some(crate::blocker::BLOCK_DECISIONS_PIN.to_string()),
                Err(e) => {
                    warn!(
                        "block_decisions pin 失败: {} — ks block 不可用，自动阻断不受影响",
                        e
                    );
                    None
                }
            },
            None => None,
        };

        // 5. 老内核用户态补偿 killer（非 Modern tier，300ms 轮询 block_decisions 补杀）
        let user_kill_enabled = config.detection.block_enabled
            && map_reader.is_some()
            && tier_detected != Some(SourceKind::EbpfModern)
            && std::env::var("HRABNAZ_USER_KILL").as_deref() != Ok("0");
        let mut kill_notices_rx = None;
        let mut killer_task = None;
        #[cfg(target_os = "linux")]
        if user_kill_enabled {
            let mr = map_reader.clone().expect("map_reader 已判定存在");
            let protected_for_kill = protected_pids.clone();
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<(u32, String)>();
            kill_notices_rx = Some(rx);
            killer_task = Some(tokio::spawn(async move {
                let protect = crate::blocker::protected_comms();
                let killed: Arc<Mutex<std::collections::HashMap<u32, u64>>> =
                    Arc::new(Mutex::new(std::collections::HashMap::new()));
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(300));
                loop {
                    tick.tick().await;
                    let entries = mr.read_block_decisions();
                    if entries.is_empty() {
                        continue;
                    }
                    let outcome = {
                        let mut killed = killed.lock().await;
                        crate::blocker::user_kill_tick(
                            &entries,
                            &mut killed,
                            &protected_for_kill,
                            // comm 可伪造（prctl PR_SET_NAME），与内核 ks_check_block 同款守卫：
                            // 从 /tmp、/dev/shm 等可疑路径启动的进程不享受 comm 豁免
                            |pid| {
                                crate::blocker::comm_of(pid)
                                    .is_some_and(|comm| protect.contains(&comm))
                                    && !crate::blocker::exe_path_suspicious(pid)
                            },
                            crate::blocker::monotonic_now_ns(),
                            crate::blocker::kill_pid_sigkill,
                        )
                    };
                    for pid in outcome.exempt {
                        info!("跳过实杀 pid={} (comm 在保护名单且 exe 路径可信)", pid);
                    }
                    for (pid, reason) in outcome.fired {
                        info!(
                            "用户态实杀 pid={} (reason={}, 内核无 bpf_send_signal)",
                            pid, reason
                        );
                        let _ = tx.send((pid, reason.to_string()));
                    }
                }
            }));
            info!("用户态 killer 已启用（非 Modern tier，300ms 轮询 block_decisions）");
        }
        let _ = user_kill_enabled;

        // 6. 取证 logger + 异步 worker
        std::fs::create_dir_all(&options.log_dir)?;
        let log_path = std::path::Path::new(&options.log_dir).join(format!(
            "events_{}.jsonl",
            chrono::Local::now().format("%Y%m%d")
        ));
        let rotation_config = RotationConfig {
            max_file_size: config.forensic.max_log_size_mb as u64 * 1024 * 1024,
            retain_days: config.forensic.retention_days,
            compress_archives: true,
        };
        let forensic = Arc::new(Mutex::new(ForensicLogger::with_rotation(
            log_path.clone(),
            rotation_config,
        )?));
        // 重启后续号：用取证链恢复出的链尾 seq 播种 aggregator。旧实现 aggregator
        // 每次进程启动从 0 开始，在同一日志文件内造成 seq 回退（真机实测 2468541→1），
        // alert.event_ids 的定位会因此歧义。
        {
            let recovered_seq = forensic.lock().await.event_count();
            aggregator.set_seq(recovered_seq);
        }
        let (forensic_tx, forensic_rx) = tokio::sync::mpsc::channel::<ForensicOp>(65536);
        let forensic_sink = ForensicSink { tx: forensic_tx };
        let forensic_worker = {
            let f = forensic.clone();
            tokio::spawn(async move { forensic_worker(f, forensic_rx).await })
        };

        // 7. 规则完整性校验（H-1.5）：MISMATCH 产生审计告警进取证链；
        //    HRABNAZ_RULES_DIGEST_STRICT=1 拒绝启动
        let rules_integrity = if rules_dir_exists {
            match check_and_record(
                std::path::Path::new(&options.rules_dir),
                std::path::Path::new(&options.log_dir),
            ) {
                Ok((integrity, verdict)) => {
                    if let Some(alert) = mismatch_alert(&verdict) {
                        warn!(
                            "[rules-integrity] 规则集与 HRABNAZ_RULES_DIGEST 基线不一致 — 审计告警写入取证链"
                        );
                        forensic_sink.log_alert(&alert).await;
                    }
                    if matches!(verdict, RulesIntegrityVerdict::Mismatch { .. })
                        && std::env::var("HRABNAZ_RULES_DIGEST_STRICT").as_deref() == Ok("1")
                    {
                        anyhow::bail!(
                            "HRABNAZ_RULES_DIGEST_STRICT=1 且规则集与部署基线不一致 — 拒绝启动。\
                             正常变更请用 `ks rules-digest` 更新基线"
                        );
                    }
                    Some((integrity.combined_digest, verdict))
                }
                Err(e) => {
                    warn!("[rules-integrity] 无法计算指纹: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // 8. 心跳任务（H-1.6 watchdog 数据源）
        let heartbeat_stats = Arc::new(AtomicU64::new(0));
        let heartbeat_task = options.heartbeat_path.as_ref().map(|path| {
            let path = path.clone();
            let stats = heartbeat_stats.clone();
            tokio::spawn(async move {
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
                        "consumed": stats.load(std::sync::atomic::Ordering::Relaxed),
                    });
                    let tmp = path.with_extension(format!("hb.tmp{}", std::process::id()));
                    // 心跳含 pid/消费数，权限契约与状态文件一致（0600）
                    let write_res = (|| -> std::io::Result<()> {
                        #[cfg(unix)]
                        {
                            use std::io::Write;
                            use std::os::unix::fs::OpenOptionsExt;
                            let mut f = std::fs::OpenOptions::new()
                                .create(true)
                                .write(true)
                                .truncate(true)
                                .mode(0o600)
                                .open(&tmp)?;
                            f.write_all(payload.to_string().as_bytes())
                        }
                        #[cfg(not(unix))]
                        {
                            std::fs::write(&tmp, payload.to_string())
                        }
                    })();
                    if write_res.is_ok() {
                        let _ = std::fs::rename(&tmp, &path);
                    }
                }
            })
        });

        // 9. 规则热加载
        let hot_reload_task = tokio::spawn(rule_hot_loader(
            detector.clone(),
            options.rules_dir.clone(),
            options.log_dir.clone(),
        ));

        let anomaly_threshold = config.detection.anomaly_threshold;
        let block_ttl = config.detection.block_ttl_secs;
        let block_severity_threshold = config.detection.block_severity_threshold.clone();

        let info = EngineInfo {
            tier_detected,
            source_kind,
            source_desc,
            rules_dir_exists,
            rules_files,
            rules_total,
            block_channel,
            user_kill_enabled,
            rules_integrity,
            forensic_path: log_path,
        };

        Ok(Engine {
            config,
            source,
            aggregator,
            detector,
            baseline_mgr,
            correlation_engine,
            process_tree_mgr,
            ml_detector,
            block_mgr,
            forensic,
            forensic_sink,
            forensic_worker,
            chain_reconstructor: ChainReconstructor::new(),
            stats: EngineStats::default(),
            alert_throttle: AlertThrottle::new(),
            repeat_io_filter: RepeatIoFilter::new(),
            anomaly_threshold,
            block_ttl,
            block_severity_threshold,
            protected_pids,
            self_tgid: std::process::id(),
            self_forensic_dir: normalize_dir(&options.log_dir),
            block_pinned: info.block_channel.is_some(),
            info,
            hot_reload_task,
            heartbeat_task,
            heartbeat_path: options.heartbeat_path,
            heartbeat_stats,
            kill_notices_rx,
            _killer_task: killer_task,
            start_time,
        })
    }

    pub fn info(&self) -> &EngineInfo {
        &self.info
    }

    pub fn stats(&self) -> &EngineStats {
        &self.stats
    }

    /// 当前事件源是否为 mock（错误恢复的退避策略用）
    pub fn is_mock(&self) -> bool {
        self.source.is_mock()
    }

    /// 批量 drain（≤config.engine.batch_size）后逐事件处理；满批让出调度
    /// （自适应 busy-poll，H-3）。`exhausted` 仅事件源耗尽时为 true。
    pub async fn tick(&mut self) -> Result<EngineOutcome> {
        let mut outcome = EngineOutcome::default();
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(self.config.engine.batch_size as usize);
        let mut reuse_buf: Vec<u8> = Vec::with_capacity(1024);
        for _ in 0..self.config.engine.batch_size {
            match self.source.next_bytes_reuse(&mut reuse_buf).await {
                Ok(true) => batch.push(std::mem::take(&mut reuse_buf)),
                Ok(false) => {
                    if batch.is_empty() {
                        if self.source.is_mock() {
                            outcome.exhausted = true;
                            return Ok(outcome);
                        }
                        tokio::task::yield_now().await;
                        return Ok(outcome);
                    }
                    break;
                }
                Err(e) => {
                    if batch.is_empty() {
                        return Err(e);
                    }
                    break;
                }
            }
        }
        for bytes in &batch {
            let effects = self.process_event_inner(bytes).await?;
            outcome.consumed += 1;
            outcome.effects.extend(effects);
            self.heartbeat_stats
                .store(self.stats.consumed, std::sync::atomic::Ordering::Relaxed);
        }
        if batch.len() == self.config.engine.batch_size as usize {
            tokio::task::yield_now().await;
        }
        self.drain_kill_notices(&mut outcome);
        Ok(outcome)
    }

    /// 单事件入口（自带事件源/自有循环的消费方用；等价于 tick 处理一条）
    pub async fn process_event(&mut self, bytes: &[u8]) -> Result<EngineOutcome> {
        let effects = self.process_event_inner(bytes).await?;
        self.heartbeat_stats
            .store(self.stats.consumed, std::sync::atomic::Ordering::Relaxed);
        let mut outcome = EngineOutcome {
            consumed: 1,
            exhausted: false,
            effects,
        };
        self.drain_kill_notices(&mut outcome);
        Ok(outcome)
    }

    /// 取证目录内的读取/写入/打开事件：属于消费本产品产物，不是被监控行为。
    /// 删除/改名/改权限不在其列，证据破坏必须仍然可检测。
    fn is_self_forensic_io(&self, event: &hrabnaz_core::event::DecodedEvent) -> bool {
        const FILE_OPEN: u32 = 10;
        const FILE_READ: u32 = 11;
        const FILE_WRITE: u32 = 12;
        let et = event.header.event_type;
        if et != FILE_OPEN && et != FILE_READ && et != FILE_WRITE {
            return false;
        }
        event
            .filename
            .as_deref()
            .is_some_and(|p| p.starts_with(&self.self_forensic_dir))
    }

    fn drain_kill_notices(&mut self, outcome: &mut EngineOutcome) {
        if let Some(rx) = self.kill_notices_rx.as_mut() {
            while let Ok((pid, reason)) = rx.try_recv() {
                outcome.effects.push(EngineEffect::Blocked(BlockedRecord {
                    pid,
                    reason,
                    via: BlockedVia::UserKill,
                }));
            }
        }
    }

    /// 事件处理主链（自旧 hrabnaz-cli start.rs 逐行搬迁，行为等价）：
    /// decode → 取证入链 → 基线 → 进程树 → 关联 → ML → 规则 → 评分 →
    /// 周期重扫（基线偏离 / ML / 进程树家族 / 攻击链）
    async fn process_event_inner(&mut self, bytes: &[u8]) -> Result<Vec<EngineEffect>> {
        let mut effects = Vec::new();
        let t0 = Instant::now();

        let t = Instant::now();
        let event = self.aggregator.decode(bytes)?;
        prof_add(0, t.elapsed().as_nanos() as u64);
        let is_protected = self.protected_pids.contains(&event.header.pid);
        self.stats.consumed += 1;

        // 自排除（根因修复）：取证写入线程（tokio worker）与 gzip 线程与引擎同
        // tgid，vfs_write 探针会把"写取证日志"本身再记成 FILE_WRITE 事件并写进
        // 日志，形成自反馈——真机实测 5 分钟 11 万条自写事件、日志以 ~300KB/s
        // 自噬。事件头 pid 即 tgid（bpf_get_current_pid_tgid >> 32），等于自身
        // 进程号的事件在进取证/基线/规则之前整条丢弃，环路增益归零。
        if event.header.pid == self.self_tgid {
            self.stats.self_events_dropped += 1;
            return Ok(effects);
        }

        // 自产物消费（与进程名无关）：任何进程读取或写入本实例取证目录下的文件，
        // 都是"消费产物"而非被监控行为。取证目录是产品自身参数，对所有部署成立。
        // 只排除读/写/打开：delete/rename/chmod 仍要过检测——那是证据破坏。
        if self.is_self_forensic_io(&event) {
            self.stats.self_forensic_events_dropped += 1;
            return Ok(effects);
        }

        // 重复 I/O 合并：同一进程对同一路径的连续 open/read/write 只留首条。
        // 逐条记录不增加取证信息，却会把日志放大几个数量级。
        if !self.repeat_io_filter.keep(&event) {
            self.stats.repeated_io_collapsed += 1;
            return Ok(effects);
        }

        let t = Instant::now();
        self.forensic_sink.log_event(&event).await;
        prof_add(1, t.elapsed().as_nanos() as u64);

        let t = Instant::now();
        if !is_protected {
            self.baseline_mgr.update_from_event(&event);
        }
        prof_add(2, t.elapsed().as_nanos() as u64);

        let t = Instant::now();
        self.process_tree_mgr.update_from_event(&event);
        let corr_alerts = self
            .correlation_engine
            .detect_correlations_with_tree(&event, Some(&self.process_tree_mgr));
        prof_add(3, t.elapsed().as_nanos() as u64);

        let t = Instant::now();
        self.ml_detector.update_from_event(&event);
        prof_add(4, t.elapsed().as_nanos() as u64);

        for ca in &corr_alerts {
            if !self.alert_throttle.allow(&ca.rule_name, event.header.pid) {
                self.stats.suppressed_alerts += 1;
                continue;
            }
            let alert = ca.to_alert();
            self.forensic_sink.log_alert(&alert).await;
            self.stats.rule_alerts += 1;
            let blocked = severity_meets_threshold(&alert.severity, &self.block_severity_threshold)
                && ca.enforce
                && !self.protected_pids.contains(&event.header.pid)
                && self.block_mgr.block_pid(
                    event.header.pid,
                    self.block_ttl,
                    BlockReason::Correlation,
                    &alert.title,
                );
            effects.push(EngineEffect::Alert(Box::new(RaisedAlert {
                alert,
                source: AlertSource::Correlation {
                    confidence: ca.confidence,
                    trigger_pid: event.header.pid,
                },
            })));
            if blocked {
                effects.push(EngineEffect::Blocked(BlockedRecord {
                    pid: event.header.pid,
                    reason: ca.rule_name.clone(),
                    via: BlockedVia::Correlation,
                }));
            }
        }

        let t = Instant::now();
        let matches = self.detector.lock().await.match_event(&event);
        prof_add(5, t.elapsed().as_nanos() as u64);
        for m in &matches {
            if !self.alert_throttle.allow(&m.rule_name, event.header.pid) {
                self.stats.suppressed_alerts += 1;
                continue;
            }
            let alert = self.detector.lock().await.generate_alert(m, &event);
            self.forensic_sink.log_alert(&alert).await;
            self.stats.rule_alerts += 1;
            let blocked = m.enforce
                && severity_meets_threshold(&alert.severity, &self.block_severity_threshold)
                && !self.protected_pids.contains(&alert.process.pid)
                && self.block_mgr.block_pid(
                    alert.process.pid,
                    self.block_ttl,
                    BlockReason::RuleMatch,
                    &alert.rule_name,
                );
            effects.push(EngineEffect::Alert(Box::new(RaisedAlert {
                alert,
                source: AlertSource::Rule,
            })));
            if blocked {
                let pid = match effects.last() {
                    Some(EngineEffect::Alert(r)) => r.alert.process.pid,
                    _ => 0,
                };
                effects.push(EngineEffect::Blocked(BlockedRecord {
                    pid,
                    reason: m.rule_name.clone(),
                    via: BlockedVia::Rule,
                }));
            }
        }

        let t = Instant::now();
        let score = if is_protected {
            0.0
        } else {
            let recent_count = self
                .aggregator
                .recent_syscall_count(event.header.pid, event.header.timestamp_ns);
            self.detector
                .lock()
                .await
                .anomaly_score(&event, recent_count)
        };
        prof_add(6, t.elapsed().as_nanos() as u64);
        if score > self.anomaly_threshold {
            self.stats.anomaly_alerts += 1;
            effects.push(EngineEffect::Score(ScoreEvent {
                pid: event.header.pid,
                comm: event.comm.clone(),
                score,
                threshold: self.anomaly_threshold,
            }));
        }

        if self.stats.consumed.is_multiple_of(50) || !matches.is_empty() {
            let need_heavy_scan = self.stats.consumed.is_multiple_of(500)
                || !matches.is_empty()
                || !corr_alerts.is_empty();
            // H-1.4：天然高频白名单进程跳过基线偏离与 ML 冷启动告警
            let is_high_freq_comm =
                !is_protected && self.baseline_mgr.is_inherently_high_freq(&event.comm);
            if !is_protected && !is_high_freq_comm {
                if let Some(dev) = self.baseline_mgr.detect_deviation(event.header.pid) {
                    if self
                        .alert_throttle
                        .allow("baseline_deviation", event.header.pid)
                    {
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
                        self.forensic_sink.log_alert(&alert).await;
                        self.stats.anomaly_alerts += 1;
                        effects.push(EngineEffect::Alert(Box::new(RaisedAlert {
                            alert,
                            source: AlertSource::BaselineDeviation,
                        })));
                    } else {
                        self.stats.suppressed_alerts += 1;
                    }
                }
            }

            if !is_protected && !is_high_freq_comm {
                if let Some(ml_result) = self.ml_detector.detect(event.header.pid) {
                    if self.alert_throttle.allow("ml_anomaly", event.header.pid) {
                        let dim_str = ml_result
                            .dimensions
                            .first()
                            .map(|d| format!("{:?}", d.dimension))
                            .unwrap_or_else(|| "unknown".to_string());
                        let model_str = match ml_result.model {
                            crate::ml_detector::AnomalyModel::Ewma => "EWMA",
                            crate::ml_detector::AnomalyModel::ColdStart => "ColdStart",
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
                        self.forensic_sink.log_alert(&alert).await;
                        self.stats.anomaly_alerts += 1;
                        effects.push(EngineEffect::Alert(Box::new(RaisedAlert {
                            alert,
                            source: AlertSource::MlAnomaly,
                        })));
                    } else {
                        self.stats.suppressed_alerts += 1;
                    }
                }
            }

            if need_heavy_scan {
                for family in self.process_tree_mgr.anomalous_families() {
                    for rel in &family.anomaly_relations {
                        if !self
                            .alert_throttle
                            .allow("process_tree_anomaly", rel.child_pid)
                        {
                            self.stats.suppressed_alerts += 1;
                            continue;
                        }
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
                        self.forensic_sink.log_alert(&alert).await;
                        self.stats.anomaly_alerts += 1;
                        effects.push(EngineEffect::Alert(Box::new(RaisedAlert {
                            alert,
                            source: AlertSource::ProcessTree {
                                parent_comm: rel.parent_comm.clone(),
                                child_comm: rel.child_comm.clone(),
                                anomaly_type: rel.anomaly_type.clone(),
                            },
                        })));
                    }
                }
            }

            if need_heavy_scan {
                // H-3: Arc 引用直达攻击链还原，不做逐事件深拷贝
                let pid_events = self.aggregator.by_pid_arcs(event.header.pid);
                if let Some(chain) = self.chain_reconstructor.reconstruct(&pid_events) {
                    if chain.confidence > 0.5 {
                        effects.push(EngineEffect::Chain(ChainFinding {
                            root_pid: chain.root_pid,
                            confidence: chain.confidence,
                            steps: chain.steps,
                        }));
                    }
                }
            }
        }

        prof_add(8, t0.elapsed().as_nanos() as u64);
        PROF_CNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        Ok(effects)
    }

    /// 生命周期终点：停任务 → 释放事件源（含探针 fd）→ flush 取证 →
    /// 摘 pin → 删心跳文件 → 返回终态统计
    pub async fn shutdown(mut self) -> Result<ShutdownSummary> {
        self.hot_reload_task.abort();
        if let Some(h) = self.heartbeat_task.take() {
            h.abort();
        }
        // 优雅退出清理心跳文件（watchdog 据此区分"正常停服"与"心跳停摆"）
        if let Some(path) = &self.heartbeat_path {
            let _ = std::fs::remove_file(path);
        }
        if let Some(h) = self._killer_task.take() {
            h.abort();
        }
        drop(self.source);
        crate::event_source::cleanup_released_dirs();
        drop(self.forensic_sink);
        let _ = self.forensic_worker.await;

        let events_logged = self.forensic.lock().await.event_count();
        let alerts_logged = self.forensic.lock().await.alert_count();
        let chain_tail_hash = self.forensic.lock().await.chain_tail_hash().to_string();

        if self.block_pinned {
            let _ = std::fs::remove_file(crate::blocker::BLOCK_DECISIONS_PIN);
        }

        prof_emit();

        Ok(ShutdownSummary {
            consumed: self.stats.consumed,
            events_logged,
            alerts_logged,
            rule_alerts: self.stats.rule_alerts,
            anomaly_alerts: self.stats.anomaly_alerts,
            chain_tail_hash,
            elapsed_secs: self.start_time.elapsed().as_secs_f64(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_source::{MockEventSource, MockScenario};

    /// 告警去重：事件型窗口 60s、状态型 1800s；窗口从上次放行起算不续期；
    /// HRABNAZ_ALERT_COOLDOWN_SEC=0 时完全关闭（排障/取证场景）
    #[test]
    fn test_alert_throttle_windows() {
        let mut t = AlertThrottle {
            last: std::collections::HashMap::new(),
            override_secs: None,
        };
        let t0 = Instant::now();
        assert!(t.allow_at("rule_a", 100, t0));
        assert!(!t.allow_at("rule_a", 100, t0 + std::time::Duration::from_secs(59)));
        assert!(
            t.allow_at("rule_a", 100, t0 + std::time::Duration::from_secs(61)),
            "事件型窗口 60s 后应重新放行"
        );
        assert!(
            t.allow_at("rule_a", 200, t0 + std::time::Duration::from_secs(1)),
            "不同 pid 互不影响"
        );

        let t1 = t0 + std::time::Duration::from_secs(100);
        assert!(t.allow_at("ml_anomaly", 300, t1));
        assert!(
            !t.allow_at("ml_anomaly", 300, t1 + std::time::Duration::from_secs(1799)),
            "状态型告警窗口应为 1800s"
        );
        assert!(t.allow_at("ml_anomaly", 300, t1 + std::time::Duration::from_secs(1801)));
    }

    #[test]
    fn test_alert_throttle_override_zero_disables() {
        let mut t = AlertThrottle {
            last: std::collections::HashMap::new(),
            override_secs: Some(0),
        };
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(t.allow_at("ml_anomaly", 1, t0));
        }
    }

    #[test]
    fn test_severity_threshold() {
        assert!(severity_meets_threshold(&Severity::Critical, "critical"));
        assert!(!severity_meets_threshold(&Severity::High, "critical"));
        assert!(severity_meets_threshold(&Severity::High, "high"));
        assert!(severity_meets_threshold(&Severity::Low, "low"));
    }

    fn file_bytes(pid: u32, event_type: u32, path: &[u8]) -> Vec<u8> {
        use hrabnaz_core::event::{EventHeader, FileEvent};
        use zerocopy::IntoBytes as _;
        let ev = FileEvent {
            header: EventHeader {
                event_type,
                _pad1: 0,
                timestamp_ns: 1,
                pid,
                tid: pid,
                uid: 0,
                ppid: 1,
                comm: {
                    let mut b = [0u8; 16];
                    b[..8].copy_from_slice(b"tailer\0\0");
                    b
                },
                syscall_nr: 1,
                _pad2: 0,
                retval: 0,
            },
            filename: {
                let mut b = [0u8; 256];
                b[..path.len()].copy_from_slice(path);
                b
            },
            bytes: 65536,
            fd: 3,
            flags: 0,
        };
        ev.as_bytes().to_vec()
    }

    /// 自产物消费：任何进程读写本实例取证目录下的文件都不该入链，
    /// 但同目录之外的读写、以及删除/改名仍要检测（证据破坏）。
    #[tokio::test(flavor = "current_thread")]
    async fn test_engine_drops_own_forensic_io_but_keeps_tamper() {
        let dir = tempfile::TempDir::new().unwrap();
        let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let log_dir = dir.path().to_string_lossy().to_string();
        let options = EngineOptions {
            config: Config::default(),
            rules_dir: rules.to_string_lossy().to_string(),
            log_dir: log_dir.clone(),
            source: EventSourceSpec::Provided(
                Box::new(MockEventSource::new_with_scenario(MockScenario::All)),
                None,
            ),
            heartbeat_path: None,
            ml_observe_sec: None,
        };
        let mut engine = Engine::start(options).await.unwrap();
        let forensic_path = engine.info().forensic_path.clone();
        let inside = format!("{}/events_20260101.jsonl", log_dir.trim_end_matches('/'));
        let outside = "/var/log/other/app.log";

        // 目录内 read/write/open：丢弃
        for et in [10u32, 11, 12] {
            let out = engine
                .process_event(&file_bytes(5000, et, inside.as_bytes()))
                .await
                .unwrap();
            assert_eq!(out.effects.len(), 0);
        }
        assert_eq!(engine.stats().self_forensic_events_dropped, 3);

        // 目录内的 delete：必须保留（证据破坏）
        let out = engine
            .process_event(&file_bytes(5001, 13, inside.as_bytes()))
            .await
            .unwrap();
        assert_eq!(out.consumed, 1);
        assert_eq!(engine.stats().self_forensic_events_dropped, 3);

        // 目录外的写：正常入链
        let out = engine
            .process_event(&file_bytes(5002, 12, outside.as_bytes()))
            .await
            .unwrap();
        assert_eq!(out.consumed, 1);

        engine.shutdown().await.unwrap();
        let events: Vec<serde_json::Value> = std::fs::read_to_string(&forensic_path)
            .unwrap()
            .lines()
            .filter(|l| l.contains("\"type\":\"event\""))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        let count = events.len();
        assert_eq!(count, 2, "只有删除与目录外写入应入链");
    }

    /// 重复 I/O 合并：同 pid 同路径的连续写只留一条，不同路径与删除事件不受影响。
    #[tokio::test(flavor = "current_thread")]
    async fn test_engine_collapses_repeated_io() {
        let dir = tempfile::TempDir::new().unwrap();
        let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let options = EngineOptions {
            config: Config::default(),
            rules_dir: rules.to_string_lossy().to_string(),
            log_dir: dir.path().to_string_lossy().to_string(),
            source: EventSourceSpec::Provided(
                Box::new(MockEventSource::new_with_scenario(MockScenario::All)),
                None,
            ),
            heartbeat_path: None,
            ml_observe_sec: None,
        };
        let mut engine = Engine::start(options).await.unwrap();
        let forensic_path = engine.info().forensic_path.clone();

        let a = b"/var/lib/app/index.sqlite";
        for _ in 0..5 {
            engine
                .process_event(&file_bytes(6000, 12, a))
                .await
                .unwrap();
        }
        assert_eq!(engine.stats().repeated_io_collapsed, 4);

        // 不同路径仍保留
        engine
            .process_event(&file_bytes(6000, 12, b"/var/lib/app/other.sqlite"))
            .await
            .unwrap();
        assert_eq!(engine.stats().repeated_io_collapsed, 4);

        // 同路径的删除不合并
        engine
            .process_event(&file_bytes(6000, 13, a))
            .await
            .unwrap();
        assert_eq!(engine.stats().repeated_io_collapsed, 4);

        engine.shutdown().await.unwrap();
        let events: Vec<serde_json::Value> = std::fs::read_to_string(&forensic_path)
            .unwrap()
            .lines()
            .filter(|l| l.contains("\"type\":\"event\""))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        assert_eq!(events.len(), 3, "首条写 + 另一路径写 + 删除");
    }

    fn file_write_bytes(pid: u32) -> Vec<u8> {
        use hrabnaz_core::event::{EventHeader, FileEvent};
        use zerocopy::IntoBytes as _;
        let ev = FileEvent {
            header: EventHeader {
                event_type: 12, // FILE_WRITE
                _pad1: 0,
                timestamp_ns: 1,
                pid,
                tid: pid,
                uid: 0,
                ppid: 1,
                comm: {
                    let mut b = [0u8; 16];
                    b[..8].copy_from_slice(b"tokio-rt");
                    b
                },
                syscall_nr: 1,
                _pad2: 0,
                retval: 0,
            },
            filename: {
                let mut b = [0u8; 256];
                let p = b"/var/log/hrabnaz/events_test.jsonl";
                b[..p.len()].copy_from_slice(p);
                b
            },
            bytes: 65536,
            fd: 3,
            flags: 0,
        };
        ev.as_bytes().to_vec()
    }

    /// 自排除回归：pid == 自身 tgid 的事件（取证写入线程产生的 FILE_WRITE）
    /// 不得进入任何消费方——否则"写日志"被记成事件、事件又被写进日志，
    /// 自反馈把日志灌成自噬流（真机实测 5min 11 万条自写事件）。
    #[tokio::test(flavor = "current_thread")]
    async fn test_engine_drops_own_process_events() {
        let dir = tempfile::TempDir::new().unwrap();
        let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let options = EngineOptions {
            config: Config::default(),
            rules_dir: rules.to_string_lossy().to_string(),
            log_dir: dir.path().to_string_lossy().to_string(),
            source: EventSourceSpec::Provided(
                Box::new(MockEventSource::new_with_scenario(MockScenario::All)),
                None,
            ),
            heartbeat_path: None,
            ml_observe_sec: None,
        };
        let mut engine = Engine::start(options).await.unwrap();
        let forensic_path = engine.info().forensic_path.clone();

        // 自身 tgid 的事件：消费但不落链、不产效果
        let out = engine
            .process_event(&file_write_bytes(std::process::id()))
            .await
            .unwrap();
        assert_eq!(out.effects.len(), 0);
        assert_eq!(engine.stats().self_events_dropped, 1);

        // 其他进程的同一事件：正常落链
        let out = engine.process_event(&file_write_bytes(4242)).await.unwrap();
        assert_eq!(out.consumed, 1);

        engine.shutdown().await.unwrap();
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&forensic_path)
            .unwrap()
            .lines()
            .filter(|l| l.contains("\"type\":\"event\""))
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        assert_eq!(lines.len(), 1, "只有非自身事件应入链");
        assert_eq!(lines[0]["pid"].as_u64(), Some(4242));
    }

    /// 引擎 e2e：Provided mock（无需 root/内核）走完整主链——
    /// tier路由以外的全部（规则/关联/取证链/攻击链/统计）都在本测试覆盖内
    #[tokio::test(flavor = "current_thread")]
    async fn test_engine_full_pipeline_with_mock_source() {
        let dir = tempfile::TempDir::new().unwrap();
        let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let options = EngineOptions {
            config: Config::default(),
            rules_dir: rules.to_string_lossy().to_string(),
            log_dir: dir.path().to_string_lossy().to_string(),
            source: EventSourceSpec::Provided(
                Box::new(MockEventSource::new_with_scenario(MockScenario::All)),
                None,
            ),
            heartbeat_path: None,
            ml_observe_sec: None,
        };
        let mut engine = Engine::start(options).await.unwrap();
        assert!(engine.info().rules_total > 0, "规则应加载成功");
        let forensic_path = engine.info().forensic_path.clone();

        let mut total = 0usize;
        let mut alert_count = 0usize;
        let mut rounds = 0;
        loop {
            rounds += 1;
            assert!(rounds < 1000, "mock 源应在有限轮次内耗尽");
            let out = engine.tick().await.unwrap();
            total += out.consumed;
            alert_count += out
                .effects
                .iter()
                .filter(|e| matches!(e, EngineEffect::Alert(_)))
                .count();
            if out.exhausted {
                break;
            }
        }
        assert!(total >= 30, "mock 全场景应产出 30+ 事件, 实际 {}", total);
        assert!(alert_count > 0, "全场景应至少产生一条告警");

        let stats = *engine.stats();
        let summary = engine.shutdown().await.unwrap();
        assert_eq!(summary.consumed, total as u64);
        assert_eq!(summary.consumed, stats.consumed);
        assert!(summary.alerts_logged > 0, "取证链上应有告警");

        // 取证哈希链自洽
        let v = ForensicLogger::verify_chain(&forensic_path).unwrap();
        assert!(v.is_valid, "引擎产出的取证链应完整: {:?}", v.broken_at);
        assert_eq!(
            v.total_records,
            summary.events_logged + summary.alerts_logged
        );
    }

    fn event_seqs(path: &std::path::Path) -> Vec<u64> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v.get("seq").and_then(|s| s.as_u64()))
            .collect()
    }

    /// 重启续号：同一日志文件内 seq 不能因进程重启而回退（旧实现从 1 重新开始，
    /// alert.event_ids 的定位会指向错误事件；真机实测回退 2468541→1）
    #[tokio::test(flavor = "current_thread")]
    async fn test_engine_seq_continues_across_restart() {
        let dir = tempfile::TempDir::new().unwrap();
        let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let mk_options = || EngineOptions {
            config: Config::default(),
            rules_dir: rules.to_string_lossy().to_string(),
            log_dir: dir.path().to_string_lossy().to_string(),
            source: EventSourceSpec::Provided(
                Box::new(MockEventSource::new_with_scenario(MockScenario::All)),
                None,
            ),
            heartbeat_path: None,
            ml_observe_sec: None,
        };

        // 第一次运行：跑完整 mock 场景
        let mut e1 = Engine::start(mk_options()).await.unwrap();
        let forensic_path = e1.info().forensic_path.clone();
        let mut consumed1 = 0usize;
        loop {
            let out = e1.tick().await.unwrap();
            consumed1 += out.consumed;
            if out.exhausted {
                break;
            }
        }
        e1.shutdown().await.unwrap();
        let seqs1 = event_seqs(&forensic_path);
        assert_eq!(seqs1.len(), consumed1, "mock 事件应全部入链");
        let last = *seqs1.last().unwrap();

        // 第二次运行：同一日志目录重启，seq 应从链尾续号
        let mut e2 = Engine::start(mk_options()).await.unwrap();
        let out = e2.tick().await.unwrap();
        assert!(out.consumed > 0);
        e2.shutdown().await.unwrap();

        let seqs2 = event_seqs(&forensic_path);
        assert!(seqs2.len() > seqs1.len(), "第二次运行应追加事件");
        let run2_first = seqs2[seqs1.len()];
        assert_eq!(
            run2_first,
            last + 1,
            "重启后 seq 应从链尾续号，而不是从 1 重新开始"
        );
    }

    /// 反向 Shell 场景单事件流：tick→effects 顺序应包含规则告警
    #[tokio::test(flavor = "current_thread")]
    async fn test_engine_reverse_shell_scenario_alerts() {
        let dir = tempfile::TempDir::new().unwrap();
        let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let options = EngineOptions {
            config: Config::default(),
            rules_dir: rules.to_string_lossy().to_string(),
            log_dir: dir.path().to_string_lossy().to_string(),
            source: EventSourceSpec::Provided(
                Box::new(MockEventSource::new_with_scenario(
                    MockScenario::ReverseShell,
                )),
                None,
            ),
            heartbeat_path: None,
            ml_observe_sec: None,
        };
        let mut engine = Engine::start(options).await.unwrap();
        let mut titles = Vec::new();
        loop {
            let out = engine.tick().await.unwrap();
            for e in &out.effects {
                if let EngineEffect::Alert(r) = e {
                    titles.push(r.alert.title.clone());
                }
            }
            if out.exhausted {
                break;
            }
        }
        let _ = engine.shutdown().await.unwrap();
        assert!(
            titles.iter().any(|t| t.contains("反弹Shell")),
            "反弹 Shell 场景应命中规则, 实际: {:?}",
            titles
        );
    }
}

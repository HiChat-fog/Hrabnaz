//! D2: 共享状态 — 告警存储 + broadcast channel
//!
//! ServerState 持有：
//! - RwLock<Vec<Alert>>：内存告警存储（FIFO 淘汰，上限 MAX_ALERTS）
//! - broadcast::Sender<Alert>：实时推送通道（多订阅者）
//! - map_reader：Phase E1.2 新增，BPF map 读取器（LinuxBpfMapReader / MockBpfMapReader），
//!   供 /api/v1/stats 端点读取 5 个共享 map 的统计信息。
//! - baseline_snapshots：G1.3 新增，z-score 基线快照（最近一次 consumed%50 周期触发时推送）
//! - correlation_alerts：G1.3 新增，跨事件关联告警存储（FIFO，上限 MAX_CORR_ALERTS）

use ks_core::alert::{Alert, AlertStatus};
use ks_engine::baseline::BehaviorBaseline;
use ks_engine::blocker::BlockManager;
use ks_engine::correlation::CorrelationAlert;
use ks_engine::loader::BpfMapReader;
use ks_engine::ml_detector::AdaptiveDetector;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, RwLock};

const MAX_ALERTS: usize = 10000;
const MAX_CORR_ALERTS: usize = 1000;
const CHANNEL_CAP: usize = 256;

pub struct ServerState {
    pub alerts: RwLock<Vec<Alert>>,
    pub tx: broadcast::Sender<Alert>,
    pub tier_label: &'static str,
    /// Phase E1.2：BPF map 读取器，供 /api/v1/stats 端点读取 map_stats。
    /// - Linux + eBPF 已加载：Some(LinuxBpfMapReader)（读取真实 map_type/max_entries）
    /// - 未加载或非 Linux：None（stats 端点返回空 map_stats 数组）
    pub map_reader: Option<Arc<dyn BpfMapReader + Send + Sync>>,
    /// G1.3：z-score 基线快照 — start.rs 周期触发时（consumed%50）推送全量基线
    pub baseline_snapshots: RwLock<HashMap<u32, BehaviorBaseline>>,
    /// G1.3：跨事件关联告警存储 — start.rs 每次产生 CorrelationAlert 时推送
    pub correlation_alerts: RwLock<Vec<CorrelationAlert>>,
    /// G4.1：EWMA 自适应检测器 — 与 start.rs 事件循环共享，供 feedback 端点调用
    pub ml_detector: Arc<Mutex<AdaptiveDetector>>,
    /// G2.2：用户态阻断管理器 — 供 REST 端点 (POST/DELETE /api/v1/block) 调用
    pub block_manager: Arc<Mutex<BlockManager>>,
}

impl ServerState {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAP);
        Self {
            alerts: RwLock::new(Vec::with_capacity(1024)),
            tx,
            tier_label: "unknown (standalone)",
            map_reader: None,
            baseline_snapshots: RwLock::new(HashMap::new()),
            correlation_alerts: RwLock::new(Vec::with_capacity(256)),
            ml_detector: Arc::new(Mutex::new(AdaptiveDetector::new())),
            block_manager: Arc::new(Mutex::new(BlockManager::new())),
        }
    }

    pub fn with_tier(tier: &'static str) -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAP);
        Self {
            alerts: RwLock::new(Vec::with_capacity(1024)),
            tx,
            tier_label: tier,
            map_reader: None,
            baseline_snapshots: RwLock::new(HashMap::new()),
            correlation_alerts: RwLock::new(Vec::with_capacity(256)),
            ml_detector: Arc::new(Mutex::new(AdaptiveDetector::new())),
            block_manager: Arc::new(Mutex::new(BlockManager::new())),
        }
    }

    /// Phase E1.2：带 map_reader 的构造方法（start.rs 在 eBPF 加载成功后调用）。
    pub fn with_map_reader(
        tier: &'static str,
        map_reader: Arc<dyn BpfMapReader + Send + Sync>,
    ) -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAP);
        Self {
            alerts: RwLock::new(Vec::with_capacity(1024)),
            tx,
            tier_label: tier,
            map_reader: Some(map_reader),
            baseline_snapshots: RwLock::new(HashMap::new()),
            correlation_alerts: RwLock::new(Vec::with_capacity(256)),
            ml_detector: Arc::new(Mutex::new(AdaptiveDetector::new())),
            block_manager: Arc::new(Mutex::new(BlockManager::new())),
        }
    }

    pub async fn push_alert(&self, alert: Alert) {
        // F3: 记录告警计数（按 severity 累加 ks_alerts_total）。
        // severity 字符串与 ks-core::rule::Severity 的 Display 实现一致。
        crate::metrics::record_alert(alert.severity.to_string().as_str());

        {
            let mut store = self.alerts.write().await;
            if store.len() >= MAX_ALERTS {
                store.remove(0);
            }
            store.push(alert.clone());
        }
        let _ = self.tx.send(alert);
    }

    pub async fn list_alerts(&self, limit: usize) -> Vec<Alert> {
        let store = self.alerts.read().await;
        store.iter().rev().take(limit).cloned().collect()
    }

    pub async fn get_alert(&self, id: uuid::Uuid) -> Option<Alert> {
        let store = self.alerts.read().await;
        store.iter().find(|a| a.id == id).cloned()
    }

    pub async fn update_status(&self, id: uuid::Uuid, status: AlertStatus) -> bool {
        let mut store = self.alerts.write().await;
        if let Some(alert) = store.iter_mut().find(|a| a.id == id) {
            alert.status = status;
            return true;
        }
        false
    }

    /// G4.2: 更新告警反馈标记（误报/确认）。
    /// 返回 Some(pid) 如果找到告警（供调用方调用 ml_detector.false_feedback）。
    pub async fn update_feedback(&self, id: uuid::Uuid, is_false_positive: bool) -> Option<u32> {
        let mut store = self.alerts.write().await;
        if let Some(alert) = store.iter_mut().find(|a| a.id == id) {
            alert.feedback = Some(!is_false_positive);
            if is_false_positive {
                alert.status = AlertStatus::FalsePositive;
            }
            return Some(alert.process.pid);
        }
        None
    }

    /// G1.3: 推送关联告警到存储（FIFO 淘汰，上限 MAX_CORR_ALERTS）。
    /// start.rs 在 correlation_engine.detect_correlations_with_tree 返回告警时调用。
    pub async fn push_correlation_alert(&self, alert: CorrelationAlert) {
        let mut store = self.correlation_alerts.write().await;
        if store.len() >= MAX_CORR_ALERTS {
            store.remove(0);
        }
        store.push(alert);
    }

    /// G1.3: 列出最近 N 条关联告警（倒序，最新在前）。
    pub async fn list_correlation_alerts(&self, limit: usize) -> Vec<CorrelationAlert> {
        let store = self.correlation_alerts.read().await;
        store.iter().rev().take(limit).cloned().collect()
    }

    /// G1.3: 更新基线快照（全量替换）。
    /// start.rs 在周期触发时（consumed%50）调用，把 BaselineManager.all_baselines() 推送过来。
    pub async fn update_baselines(&self, baselines: HashMap<u32, BehaviorBaseline>) {
        let mut store = self.baseline_snapshots.write().await;
        *store = baselines;
    }

    /// G1.3: 列出所有基线快照。
    pub async fn list_baselines(&self) -> Vec<BehaviorBaseline> {
        let store = self.baseline_snapshots.read().await;
        store.values().cloned().collect()
    }
}

pub type SharedState = Arc<ServerState>;

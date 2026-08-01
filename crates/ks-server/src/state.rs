//! 共享状态,告警存储加broadcast channel。
//!
//! ServerState持有RwLock<Vec<Alert>>(内存告警存储,FIFO淘汰,上限MAX_ALERTS)、broadcast::Sender<Alert>(实时推送通道,多订阅者)、map_reader(BPF map读取器LinuxBpfMapReader或MockBpfMapReader,供/api/v1/stats端点读5个共享map的统计)、baseline_snapshots(z-score基线快照,最近一次consumed%50周期触发时推送)、correlation_alerts(跨事件关联告警存储,FIFO,上限MAX_CORR_ALERTS)。

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
    /// BPF map读取器,供/api/v1/stats端点读map_stats。Linux且eBPF已加载时为Some(LinuxBpfMapReader)读真实map_type/max_entries,未加载或非Linux时为None,stats端点返回空map_stats数组。
    pub map_reader: Option<Arc<dyn BpfMapReader + Send + Sync>>,
    /// z-score基线快照,start.rs周期触发时(consumed%50)推送全量基线。
    pub baseline_snapshots: RwLock<HashMap<u32, BehaviorBaseline>>,
    /// 跨事件关联告警存储,start.rs每次产生CorrelationAlert时推送。
    pub correlation_alerts: RwLock<Vec<CorrelationAlert>>,
    /// EWMA自适应检测器,与start.rs事件循环共享,供feedback端点调用。
    pub ml_detector: Arc<Mutex<AdaptiveDetector>>,
    /// 用户态阻断管理器,供REST端点(POST/DELETE /api/v1/block)调用。
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

    /// 带map_reader的构造方法,start.rs在eBPF加载成功后调用。
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
        // 记录告警计数(按severity累加ks_alerts_total)。
        // severity字符串与ks-core::rule::Severity的Display实现一致。
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

    /// 更新告警反馈标记(误报或确认)。
    /// 找到告警返回Some(pid),供调用方调用ml_detector.false_feedback。
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

    /// 推送关联告警到存储(FIFO淘汰,上限MAX_CORR_ALERTS)。
    /// start.rs在correlation_engine.detect_correlations_with_tree返回告警时调用。
    pub async fn push_correlation_alert(&self, alert: CorrelationAlert) {
        let mut store = self.correlation_alerts.write().await;
        if store.len() >= MAX_CORR_ALERTS {
            store.remove(0);
        }
        store.push(alert);
    }

    /// 列出最近N条关联告警(倒序,最新在前)。
    pub async fn list_correlation_alerts(&self, limit: usize) -> Vec<CorrelationAlert> {
        let store = self.correlation_alerts.read().await;
        store.iter().rev().take(limit).cloned().collect()
    }

    /// 更新基线快照(全量替换)。
    /// start.rs在周期触发时(consumed%50)调用,把BaselineManager.all_baselines()推送过来。
    pub async fn update_baselines(&self, baselines: HashMap<u32, BehaviorBaseline>) {
        let mut store = self.baseline_snapshots.write().await;
        *store = baselines;
    }

    /// 列出所有基线快照。
    pub async fn list_baselines(&self) -> Vec<BehaviorBaseline> {
        let store = self.baseline_snapshots.read().await;
        store.values().cloned().collect()
    }
}

pub type SharedState = Arc<ServerState>;

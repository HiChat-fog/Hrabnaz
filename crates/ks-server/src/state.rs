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

    pub map_reader: Option<Arc<dyn BpfMapReader + Send + Sync>>,

    pub baseline_snapshots: RwLock<HashMap<u32, BehaviorBaseline>>,

    pub correlation_alerts: RwLock<Vec<CorrelationAlert>>,

    pub ml_detector: Arc<Mutex<AdaptiveDetector>>,

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
            ml_detector: Arc::new(Mutex::new(AdaptiveDetector::from_env())),
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
            ml_detector: Arc::new(Mutex::new(AdaptiveDetector::from_env())),
            block_manager: Arc::new(Mutex::new(BlockManager::new())),
        }
    }

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
            ml_detector: Arc::new(Mutex::new(AdaptiveDetector::from_env())),
            block_manager: Arc::new(Mutex::new(BlockManager::new())),
        }
    }

    pub async fn push_alert(&self, alert: Alert) {

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

    pub async fn push_correlation_alert(&self, alert: CorrelationAlert) {
        let mut store = self.correlation_alerts.write().await;
        if store.len() >= MAX_CORR_ALERTS {
            store.remove(0);
        }
        store.push(alert);
    }

    pub async fn list_correlation_alerts(&self, limit: usize) -> Vec<CorrelationAlert> {
        let store = self.correlation_alerts.read().await;
        store.iter().rev().take(limit).cloned().collect()
    }

    pub async fn update_baselines(&self, baselines: HashMap<u32, BehaviorBaseline>) {
        let mut store = self.baseline_snapshots.write().await;
        *store = baselines;
    }

    pub async fn list_baselines(&self) -> Vec<BehaviorBaseline> {
        let store = self.baseline_snapshots.read().await;
        store.values().cloned().collect()
    }
}

pub type SharedState = Arc<ServerState>;

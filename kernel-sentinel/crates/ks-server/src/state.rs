use ks_core::alert::{Alert, AlertStatus};
use ks_engine::baseline::BehaviorBaseline;
use ks_engine::blocker::BlockManager;
use ks_engine::correlation::CorrelationAlert;
use ks_engine::loader::BpfMapReader;
use ks_engine::ml_detector::AdaptiveDetector;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex, Notify, RwLock};

const MAX_ALERTS: usize = 10000;
const MAX_CORR_ALERTS: usize = 1000;
const CHANNEL_CAP: usize = 256;

pub struct ServerState {
    // VecDeque 使 push_alert 淘汰最老告警为 O(1)（旧 Vec::remove(0) 是 O(n) 且在告警热路径上）
    pub alerts: RwLock<VecDeque<Alert>>,
    pub tx: broadcast::Sender<Alert>,
    pub tier_label: &'static str,

    pub map_reader: Option<Arc<dyn BpfMapReader + Send + Sync>>,

    pub baseline_snapshots: RwLock<HashMap<u32, BehaviorBaseline>>,

    pub correlation_alerts: RwLock<VecDeque<CorrelationAlert>>,

    pub ml_detector: Arc<Mutex<AdaptiveDetector>>,

    pub block_manager: Arc<Mutex<BlockManager>>,

    /// 鉴权配置副本：WebSocket 升级前用它校验 token（REST 走 auth_middleware 的独立状态）。
    /// serve() 装配阶段写入一次，运行期只读
    pub auth: std::sync::RwLock<crate::auth::AuthToken>,

    /// POST /api/v1/reload 用来唤醒 start 侧规则热加载循环（旧实现是无操作 stub）
    pub reload_notify: Arc<Notify>,

    /// 进程启动时刻，/api/v1/health 的 uptime 用（旧实现硬编码 0）
    created_at: std::time::Instant,

    /// 保护名单（引擎自身/祖先链/pid 1），REST 阻断端点据此拒绝误杀
    protected_pids: RwLock<std::collections::HashSet<u32>>,
}

impl ServerState {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self::with_tier("unknown (standalone)")
    }

    fn with_common(tier: &'static str, map_reader: Option<Arc<dyn BpfMapReader + Send + Sync>>) -> Self {
        let (tx, _rx) = broadcast::channel(CHANNEL_CAP);
        Self {
            alerts: RwLock::new(VecDeque::with_capacity(1024)),
            tx,
            tier_label: tier,
            map_reader,
            baseline_snapshots: RwLock::new(HashMap::new()),
            correlation_alerts: RwLock::new(VecDeque::with_capacity(256)),
            ml_detector: Arc::new(Mutex::new(AdaptiveDetector::from_env())),
            block_manager: Arc::new(Mutex::new(BlockManager::new())),
            auth: std::sync::RwLock::new(crate::auth::AuthToken::disabled()),
            reload_notify: Arc::new(Notify::new()),
            created_at: std::time::Instant::now(),
            protected_pids: RwLock::new(std::collections::HashSet::new()),
        }
    }

    pub fn with_tier(tier: &'static str) -> Self {
        Self::with_common(tier, None)
    }

    pub fn with_map_reader(
        tier: &'static str,
        map_reader: Arc<dyn BpfMapReader + Send + Sync>,
    ) -> Self {
        Self::with_common(tier, Some(map_reader))
    }

    /// serve() 在启动装配阶段把生效的鉴权配置同步给 WS handler（运行期只读）
    pub fn set_auth(&self, auth: crate::auth::AuthToken) {
        *self.auth.write().expect("auth rwlock中毒") = auth;
    }

    /// WS/内部读取当前鉴权配置
    pub fn auth_snapshot(&self) -> crate::auth::AuthToken {
        self.auth.read().expect("auth rwlock中毒").clone()
    }

    pub fn uptime_secs(&self) -> u64 {
        self.created_at.elapsed().as_secs()
    }

    /// start 侧在装配阶段注入保护名单
    pub async fn set_protected_pids(&self, pids: std::collections::HashSet<u32>) {
        *self.protected_pids.write().await = pids;
    }

    pub async fn is_protected_pid(&self, pid: u32) -> bool {
        self.protected_pids.read().await.contains(&pid)
    }

    pub async fn push_alert(&self, alert: Alert) {

        crate::metrics::record_alert(alert.severity.to_string().as_str());

        {
            let mut store = self.alerts.write().await;
            if store.len() >= MAX_ALERTS {
                store.pop_front();
            }
            store.push_back(alert.clone());
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
            store.pop_front();
        }
        store.push_back(alert);
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

use crate::metrics;
use crate::state::SharedState;
use crate::ws;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use ks_core::alert::{Alert, AlertStatus};
use ks_core::rule::Severity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct AlertQuery {
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct MapStatResponse {
    pub name: String,
    pub map_type: String,
    pub entry_count: usize,
}

#[derive(Serialize)]
pub struct StatsResponse {
    pub total: usize,
    pub by_severity: serde_json::Value,
    pub by_status: serde_json::Value,

    pub map_stats: Vec<MapStatResponse>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub uptime_secs: u64,
}

#[derive(Serialize)]
pub struct VersionResponse {
    pub version: &'static str,
    pub component: &'static str,
}

pub fn router(state: SharedState) -> Router {
    Router::new()
        .route("/api/v1/alerts", get(list_alerts))
        .route("/api/v1/alerts/:id", get(get_alert))
        .route("/api/v1/alerts/:id/ack", post(ack_alert))
        .route("/api/v1/alerts/:id/resolve", post(resolve_alert))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/health", get(health))
        .route("/api/v1/tier", get(tier_info))
        .route("/api/v1/reload", post(reload))
        .route("/api/v1/version", get(version))

        .route("/api/v1/baselines", get(list_baselines))
        .route("/api/v1/correlations", get(list_correlations))

        .route("/api/v1/alerts/:id/feedback", post(feedback_alert))

        .route("/api/v1/block/:pid", post(block_pid_handler))
        .route("/api/v1/block/:pid", delete(unblock_pid_handler))
        .route("/api/v1/blocked", get(list_blocked_handler))

        .route("/api/v1/maps", get(list_maps_handler))
        .route("/api/v1/maps/:name", get(read_map_handler))
        .route("/ws/alerts", get(ws::ws_handler))

        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

async fn list_baselines(
    State(st): State<SharedState>,
) -> Json<Vec<ks_engine::baseline::BehaviorBaseline>> {
    Json(st.list_baselines().await)
}

async fn list_correlations(
    State(st): State<SharedState>,
    Query(q): Query<AlertQuery>,
) -> Json<Vec<ks_engine::correlation::CorrelationAlert>> {
    Json(st.list_correlation_alerts(q.limit.unwrap_or(100)).await)
}

#[derive(Deserialize)]
struct FeedbackRequest {
    is_false_positive: bool,
    #[serde(default)]
    #[allow(dead_code)]
    comment: Option<String>,
}

async fn feedback_alert(
    State(st): State<SharedState>,
    Path(id): Path<Uuid>,
    Json(req): Json<FeedbackRequest>,
) -> impl IntoResponse {
    if let Some(pid) = st.update_feedback(id, req.is_false_positive).await {

        st.ml_detector
            .lock()
            .await
            .false_feedback(pid, req.is_false_positive);
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

#[derive(Deserialize)]
struct BlockQuery {
    #[serde(default)]
    ttl: Option<u64>,
    #[serde(default)]
    reason: Option<u8>,
    #[serde(default)]
    trigger: Option<String>,
}

async fn block_pid_handler(
    State(st): State<SharedState>,
    Path(pid): Path<u32>,
    Query(q): Query<BlockQuery>,
) -> impl IntoResponse {
    // 与 CLI 内部阻断路径一致：保护名单（自身/祖先链/pid 1）不允许通过 REST 阻断
    if st.is_protected_pid(pid).await {
        log::warn!("PID {} 在保护名单内，拒绝阻断", pid);
        return (
            StatusCode::FORBIDDEN,
            format!("pid {} is protected (engine self/ancestor/pid 1)", pid),
        )
            .into_response();
    }
    let reason = ks_engine::blocker::BlockReason::from_u8(q.reason.unwrap_or(5));
    let trigger = q.trigger.unwrap_or_else(|| "rest_api".to_string());
    let added = st
        .block_manager
        .lock()
        .await
        .block_pid(pid, q.ttl.unwrap_or(0), reason, &trigger);
    if added {
        log::info!(
            "PID {} 阻断成功 (reason={}, trigger={})",
            pid,
            reason,
            trigger
        );
        StatusCode::OK.into_response()
    } else {
        // 阻断功能未启用是服务端状态问题，不是客户端权限问题：409 而非 403
        log::warn!("PID {} 阻断未生效（阻断未启用？）", pid);
        (
            StatusCode::CONFLICT,
            "blocking is disabled (block_enabled=false)",
        )
            .into_response()
    }
}

async fn unblock_pid_handler(
    State(st): State<SharedState>,
    Path(pid): Path<u32>,
) -> impl IntoResponse {
    if st.block_manager.lock().await.unblock_pid(pid) {
        log::info!("PID {}解除阻断", pid);
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn list_blocked_handler(
    State(st): State<SharedState>,
) -> Json<Vec<ks_engine::blocker::BlockedPid>> {
    Json(st.block_manager.lock().await.list_blocked())
}

async fn list_maps_handler(State(st): State<SharedState>) -> impl IntoResponse {
    match &st.map_reader {
        Some(mr) => Json(serde_json::json!({"maps": mr.list_maps()})).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "eBPF map reader not available (eBPF未加载或非Linux平台)".to_string(),
        )
            .into_response(),
    }
}

async fn read_map_handler(
    State(st): State<SharedState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    const ALLOWED: &[&str] = &[
        "process_tree",
        "net_flows",
        "freq_counters",
        "filter_stats",
        "risk_scores",
        "block_decisions",
    ];
    if !ALLOWED.contains(&name.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            format!("不支持的map名: {}(允许: {:?})", name, ALLOWED),
        )
            .into_response();
    }
    match &st.map_reader {
        Some(mr) => {
            let entries = mr.read_map_structured(&name);
            Json(serde_json::json!({
                "map": name,
                "entry_count": entries.len(),
                "entries": entries,
            }))
            .into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "eBPF map reader not available (eBPF未加载或非Linux平台)".to_string(),
        )
            .into_response(),
    }
}

async fn metrics_handler() -> impl IntoResponse {
    let body = metrics::render_metrics();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

async fn list_alerts(
    State(st): State<SharedState>,
    Query(q): Query<AlertQuery>,
) -> Json<Vec<Alert>> {
    Json(st.list_alerts(q.limit.unwrap_or(100)).await)
}

async fn get_alert(State(st): State<SharedState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match st.get_alert(id).await {
        Some(alert) => Json(alert).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn ack_alert(State(st): State<SharedState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    if st.update_status(id, AlertStatus::Investigating).await {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn resolve_alert(State(st): State<SharedState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    if st.update_status(id, AlertStatus::Resolved).await {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn stats(State(st): State<SharedState>) -> Json<StatsResponse> {
    let store = st.alerts.read().await;
    let total = store.len();
    let mut high = 0u64;
    let mut medium = 0u64;
    let mut low = 0u64;
    let mut new = 0u64;
    let mut investigating = 0u64;
    let mut resolved = 0u64;
    for a in store.iter() {
        match a.severity {
            Severity::Critical | Severity::High => high += 1,
            Severity::Medium => medium += 1,
            Severity::Low => low += 1,
        }
        match a.status {
            AlertStatus::New => new += 1,
            AlertStatus::Investigating => investigating += 1,
            AlertStatus::Resolved | AlertStatus::FalsePositive => resolved += 1,
        }
    }
    drop(store);

    let map_stats: Vec<MapStatResponse> = match &st.map_reader {
        Some(mr) => mr
            .list_map_stats()
            .into_iter()
            .map(|ms| {

                metrics::set_map_entries(&ms.name, ms.entry_count as i64);
                MapStatResponse {
                    name: ms.name,
                    map_type: ms.map_type,
                    entry_count: ms.entry_count,
                }
            })
            .collect(),
        None => vec![],
    };

    Json(StatsResponse {
        total,
        by_severity: serde_json::json!({"high": high, "medium": medium, "low": low}),
        by_status: serde_json::json!({"new": new, "investigating": investigating, "resolved": resolved}),
        map_stats,
    })
}

async fn health(State(st): State<SharedState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        uptime_secs: st.uptime_secs(),
    })
}

async fn tier_info(State(st): State<SharedState>) -> impl IntoResponse {
    format!("tier: {}", st.tier_label)
}

async fn reload(State(st): State<SharedState>) -> impl IntoResponse {
    // 旧实现是返回 202 但函数体为空的 stub。规则热加载循环在 start 侧每 5s 扫 mtime，
    // 这里主动唤醒一次让变更立即生效；同一进程内未跑检测引擎时唤醒无副作用
    st.reload_notify.notify_one();
    (
        StatusCode::ACCEPTED,
        "reload triggered (rules hot-loader woken, changes apply within seconds)",
    )
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        component: "ks-server",
    })
}

//! D3: REST API 路由（9 个端点 + WebSocket）
//!
//! | 方法 | 路径 | 功能 |
//! |------|------|------|
//! | GET  | /api/v1/alerts | 列出最近告警 |
//! | GET  | /api/v1/alerts/:id | 按 UUID 查单个告警 |
//! | POST | /api/v1/alerts/:id/ack | 确认告警 |
//! | POST | /api/v1/alerts/:id/resolve | 标记已解决 |
//! | GET  | /api/v1/stats | 统计概览 |
//! | GET  | /api/v1/health | 健康检查 |
//! | GET  | /api/v1/tier | 当前 tier 信息 |
//! | POST | /api/v1/reload | 触发规则重载（占位） |
//! | GET  | /api/v1/version | 版本信息 |
//! | GET  | /ws/alerts | WebSocket 实时告警推送 |

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

/// Phase E1.2：单个 BPF map 的统计信息（序列化给前端）。
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
    /// Phase E1.2：5 个共享 map 的统计（risk_scores / ip_whitelist / ...）。
    /// map_reader 为 None 时返回空数组。
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
        // G1.3: z-score 基线快照 + 跨事件关联告警
        .route("/api/v1/baselines", get(list_baselines))
        .route("/api/v1/correlations", get(list_correlations))
        // G4.2: 误报反馈端点 — POST /api/v1/alerts/:id/feedback
        .route("/api/v1/alerts/:id/feedback", post(feedback_alert))
        // G2.3: 阻断管理端点 — POST/DELETE/GET
        .route("/api/v1/block/:pid", post(block_pid_handler))
        .route("/api/v1/block/:pid", delete(unblock_pid_handler))
        .route("/api/v1/blocked", get(list_blocked_handler))
        // G2.4: BPF Map 全 6 个共享 map 读取端点（process_tree / net_flows /
        // freq_counters / filter_stats / risk_scores / block_decisions）
        .route("/api/v1/maps", get(list_maps_handler))
        .route("/api/v1/maps/:name", get(read_map_handler))
        .route("/ws/alerts", get(ws::ws_handler))
        // F3: Prometheus 指标导出端点，免鉴权（F4 才处理其他端点鉴权）。
        // 返回 Content-Type: text/plain; version=0.0.4; charset=utf-8
        .route("/metrics", get(metrics_handler))
        .with_state(state)
}

/// G1.3: 列出所有进程的 z-score 基线快照。
async fn list_baselines(
    State(st): State<SharedState>,
) -> Json<Vec<ks_engine::baseline::BehaviorBaseline>> {
    Json(st.list_baselines().await)
}

/// G1.3: 列出最近的跨事件关联告警（默认 100 条，最新在前）。
async fn list_correlations(
    State(st): State<SharedState>,
    Query(q): Query<AlertQuery>,
) -> Json<Vec<ks_engine::correlation::CorrelationAlert>> {
    Json(st.list_correlation_alerts(q.limit.unwrap_or(100)).await)
}

/// G4.2: 误报反馈端点 — 标记告警为误报/确认，并联动 ML 检测器调整阈值。
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
        // 联动 ML 检测器：误报则提升阈值
        st.ml_detector
            .lock()
            .await
            .false_feedback(pid, req.is_false_positive);
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

/// G2.3: 阻断指定 PID。
/// POST /api/v1/block/:pid?ttl=300&reason=1
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
        StatusCode::OK
    } else {
        log::warn!("PID {} 阻断未生效（阻断未启用？）", pid);
        StatusCode::FORBIDDEN
    }
}

/// G2.3: 解除阻断。
/// DELETE /api/v1/block/:pid
async fn unblock_pid_handler(
    State(st): State<SharedState>,
    Path(pid): Path<u32>,
) -> impl IntoResponse {
    if st.block_manager.lock().await.unblock_pid(pid) {
        log::info!("PID {} 解除阻断", pid);
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

/// G2.3: 列出所有被阻断的 PID。
/// GET /api/v1/blocked
async fn list_blocked_handler(
    State(st): State<SharedState>,
) -> Json<Vec<ks_engine::blocker::BlockedPid>> {
    Json(st.block_manager.lock().await.list_blocked())
}

/// G2.4: 列出所有可读的 BPF map 名称。
/// GET /api/v1/maps
async fn list_maps_handler(State(st): State<SharedState>) -> impl IntoResponse {
    match &st.map_reader {
        Some(mr) => Json(serde_json::json!({"maps": mr.list_maps()})).into_response(),
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "eBPF map reader not available (eBPF 未加载或非 Linux 平台)".to_string(),
        )
            .into_response(),
    }
}

/// G2.4: 读取指定 BPF map 的结构化条目。
/// GET /api/v1/maps/:name
/// 支持的 map: process_tree / net_flows / freq_counters / filter_stats /
/// risk_scores / block_decisions
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
            format!("不支持的 map 名: {}（允许: {:?}）", name, ALLOWED),
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
            "eBPF map reader not available (eBPF 未加载或非 Linux 平台)".to_string(),
        )
            .into_response(),
    }
}

/// F3: Prometheus 抓取端点。
///
/// 返回所有已注册指标（事件计数 / 告警计数 / map 大小 / 延迟 / tier 状态 / ringbuf 丢失）。
/// Content-Type 遵循 Prometheus exposition format 0.0.4 规范。
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
    drop(store); // 释放 alerts RwLock，再读 map_stats

    // Phase E1.2：从 map_reader 读取 5 个共享 map 的统计信息。
    // map_reader 为 None（未加载 eBPF / 非 Linux）时返回空数组。
    let map_stats: Vec<MapStatResponse> = match &st.map_reader {
        Some(mr) => mr
            .list_map_stats()
            .into_iter()
            .map(|ms| {
                // F3: 同步更新 ks_map_entries 指标（Gauge），供 Prometheus 抓取。
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

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        uptime_secs: 0,
    })
}

async fn tier_info(State(st): State<SharedState>) -> impl IntoResponse {
    format!("tier: {}", st.tier_label)
}

async fn reload() -> impl IntoResponse {
    StatusCode::ACCEPTED
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION"),
        component: "ks-server",
    })
}

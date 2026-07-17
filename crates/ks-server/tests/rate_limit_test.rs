//! F4 安全加固 — 速率限制中间件集成测试
//!
//! 测试 `tower_governor::GovernorLayer` 在我们的 `build_rate_limiter` 配置下：
//! - 正常请求（在配额内）→ 200
//! - 超限请求 → 429
//!
//! 测试方式：用 `tower::ServiceExt::oneshot` 直接调用 axum Router。
//! 注：`PeerIpKeyExtractor` 从 `ConnectInfo<SocketAddr>` extension 提取客户端 IP，
//! 测试中需手动注入此 extension（无真实 TCP 连接）。
//!
//! 测试策略：
//! - 设置极低配额（每分钟 3 个请求）便于触发 429
//! - 所有请求注入相同 ConnectInfo（同 IP），共享令牌桶
//! - 用 `inject_connect_info_for_test` 辅助函数注入

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use ks_server::rate_limit::{build_rate_limiter, inject_connect_info_for_test};
use ks_server::routes::router;
use ks_server::ServerState;

/// 构建一个带 rate_limit layer 的测试 Router（limit_per_min = 3，便于触发 429）。
fn build_app(limit_per_min: u32) -> axum::Router {
    let state: Arc<ServerState> = Arc::new(ServerState::with_tier("test"));
    router(state).layer(build_rate_limiter(limit_per_min))
}

/// 注入 ConnectInfo 并发送一个 GET /api/v1/alerts 请求。
async fn send_alerts_request(app: axum::Router, addr: SocketAddr) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/alerts")
        .body(Body::empty())
        .unwrap();
    let req = inject_connect_info_for_test(req, addr);
    let response = app.oneshot(req).await.expect("oneshot 不应失败");
    response.status()
}

/// 1) 正常请求（在配额内）→ 200
#[tokio::test]
async fn test_normal_request_ok() {
    let app = build_app(3);
    let addr: SocketAddr = "127.0.0.1:5555".parse().unwrap();

    // 配额 3：前 3 个请求应成功（200）
    for i in 0..3 {
        let status = send_alerts_request(app.clone(), addr).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "第 {} 个请求应在配额内返回 200，实际: {}",
            i + 1,
            status
        );
    }
}

/// 2) 超限请求 → 429
#[tokio::test]
async fn test_exceed_limit_returns_429() {
    let app = build_app(2);
    let addr: SocketAddr = "127.0.0.1:5556".parse().unwrap();

    // 配额 2：前 2 个 200，第 3 个开始 429
    let s1 = send_alerts_request(app.clone(), addr).await;
    assert_eq!(s1, StatusCode::OK, "第 1 个请求应 200，实际: {}", s1);

    let s2 = send_alerts_request(app.clone(), addr).await;
    assert_eq!(s2, StatusCode::OK, "第 2 个请求应 200，实际: {}", s2);

    let s3 = send_alerts_request(app.clone(), addr).await;
    assert_eq!(
        s3,
        StatusCode::TOO_MANY_REQUESTS,
        "第 3 个请求应超限返回 429，实际: {}",
        s3
    );

    // 第 4 个也应继续 429
    let s4 = send_alerts_request(app.clone(), addr).await;
    assert_eq!(
        s4,
        StatusCode::TOO_MANY_REQUESTS,
        "第 4 个请求应继续 429，实际: {}",
        s4
    );
}

/// 3) 不同 IP 各自独立配额（验证 PeerIpKeyExtractor 按 IP 区分）
#[tokio::test]
async fn test_different_ips_independent_quota() {
    let app = build_app(1);
    let addr_a: SocketAddr = "127.0.0.1:5557".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.2:5557".parse().unwrap();

    // IP A 用尽配额
    let s_a1 = send_alerts_request(app.clone(), addr_a).await;
    assert_eq!(s_a1, StatusCode::OK);

    let s_a2 = send_alerts_request(app.clone(), addr_a).await;
    assert_eq!(s_a2, StatusCode::TOO_MANY_REQUESTS);

    // IP B 应不受 A 影响，仍能正常请求
    let s_b1 = send_alerts_request(app.clone(), addr_b).await;
    assert_eq!(
        s_b1,
        StatusCode::OK,
        "不同 IP 应有独立配额，B 第 1 个请求应 200，实际: {}",
        s_b1
    );
}

/// 4) 缺失 ConnectInfo extension → 500（UnableToExtractKey）
///
/// 此测试验证：在生产环境必须用 `into_make_service_with_connect_info`，
/// 否则 PeerIpKeyExtractor 无法提取 IP。
#[tokio::test]
async fn test_missing_connect_info_returns_500() {
    let app = build_app(3);
    // 故意不注入 ConnectInfo
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/alerts")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.expect("oneshot 不应失败");
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "缺失 ConnectInfo 应返回 500 (UnableToExtractKey)，实际: {}",
        response.status()
    );
}

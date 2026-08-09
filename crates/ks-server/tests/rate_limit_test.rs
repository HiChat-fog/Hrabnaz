//! 速率限制中间件集成测试。
//!
//! 测试tower_governor::GovernorLayer在build_rate_limiter配置下:正常请求(在配额内)返回200,超限请求返回429。
//!
//! 测试方式:用tower::ServiceExt::oneshot直接调用axum Router。PeerIpKeyExtractor从ConnectInfo<SocketAddr> extension提取客户端IP,测试中需手动注入此extension(无真实TCP连接)。测试策略:设置极低配额(每分钟3个请求)便于触发429,所有请求注入相同ConnectInfo(同IP)共享令牌桶,用inject_connect_info_for_test辅助函数注入。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use ks_server::rate_limit::{build_rate_limiter, inject_connect_info_for_test};
use ks_server::routes::router;
use ks_server::ServerState;

/// 构建一个带rate_limit layer的测试Router(limit_per_min=3,便于触发429)。
fn build_app(limit_per_min: u32) -> axum::Router {
    let state: Arc<ServerState> = Arc::new(ServerState::with_tier("test"));
    router(state).layer(build_rate_limiter(limit_per_min))
}

/// 注入ConnectInfo并发送一个GET /api/v1/alerts请求。
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

/// 1)正常请求(在配额内)返回200
#[tokio::test]
async fn test_normal_request_ok() {
    let app = build_app(3);
    let addr: SocketAddr = "127.0.0.1:5555".parse().unwrap();

    // 配额3:前3个请求应成功(200)
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

/// 2)超限请求返回429
#[tokio::test]
async fn test_exceed_limit_returns_429() {
    let app = build_app(2);
    let addr: SocketAddr = "127.0.0.1:5556".parse().unwrap();

    // 配额2:前2个200,第3个开始429
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

    // 第4个也应继续429
    let s4 = send_alerts_request(app.clone(), addr).await;
    assert_eq!(
        s4,
        StatusCode::TOO_MANY_REQUESTS,
        "第 4 个请求应继续 429，实际: {}",
        s4
    );
}

/// 3)不同IP各自独立配额(验证PeerIpKeyExtractor按IP区分)
#[tokio::test]
async fn test_different_ips_independent_quota() {
    let app = build_app(1);
    let addr_a: SocketAddr = "127.0.0.1:5557".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.2:5557".parse().unwrap();

    // IP A用尽配额
    let s_a1 = send_alerts_request(app.clone(), addr_a).await;
    assert_eq!(s_a1, StatusCode::OK);

    let s_a2 = send_alerts_request(app.clone(), addr_a).await;
    assert_eq!(s_a2, StatusCode::TOO_MANY_REQUESTS);

    // IP B应不受A影响,仍能正常请求
    let s_b1 = send_alerts_request(app.clone(), addr_b).await;
    assert_eq!(
        s_b1,
        StatusCode::OK,
        "不同 IP 应有独立配额，B 第 1 个请求应 200，实际: {}",
        s_b1
    );
}

/// 4)缺失ConnectInfo extension返回500(UnableToExtractKey)
///
/// 此测试验证:在生产环境必须用into_make_service_with_connect_info,
/// 否则PeerIpKeyExtractor无法提取IP。
#[tokio::test]
async fn test_missing_connect_info_returns_500() {
    let app = build_app(3);
    // 故意不注入ConnectInfo
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

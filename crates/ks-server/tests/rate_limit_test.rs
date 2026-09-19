use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use ks_server::rate_limit::{build_rate_limiter, inject_connect_info_for_test};
use ks_server::routes::router;
use ks_server::ServerState;

fn build_app(limit_per_min: u32) -> axum::Router {
    let state: Arc<ServerState> = Arc::new(ServerState::with_tier("test"));
    router(state).layer(build_rate_limiter(limit_per_min))
}

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

#[tokio::test]
async fn test_normal_request_ok() {
    let app = build_app(3);
    let addr: SocketAddr = "127.0.0.1:5555".parse().unwrap();

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

#[tokio::test]
async fn test_exceed_limit_returns_429() {
    let app = build_app(2);
    let addr: SocketAddr = "127.0.0.1:5556".parse().unwrap();

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

    let s4 = send_alerts_request(app.clone(), addr).await;
    assert_eq!(
        s4,
        StatusCode::TOO_MANY_REQUESTS,
        "第 4 个请求应继续 429，实际: {}",
        s4
    );
}

#[tokio::test]
async fn test_different_ips_independent_quota() {
    let app = build_app(1);
    let addr_a: SocketAddr = "127.0.0.1:5557".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.2:5557".parse().unwrap();

    let s_a1 = send_alerts_request(app.clone(), addr_a).await;
    assert_eq!(s_a1, StatusCode::OK);

    let s_a2 = send_alerts_request(app.clone(), addr_a).await;
    assert_eq!(s_a2, StatusCode::TOO_MANY_REQUESTS);

    let s_b1 = send_alerts_request(app.clone(), addr_b).await;
    assert_eq!(
        s_b1,
        StatusCode::OK,
        "不同 IP 应有独立配额，B 第 1 个请求应 200，实际: {}",
        s_b1
    );
}

#[tokio::test]
async fn test_missing_connect_info_returns_500() {
    let app = build_app(3);

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

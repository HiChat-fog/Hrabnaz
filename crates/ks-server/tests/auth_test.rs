use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use tower::ServiceExt;

use ks_server::auth::{auth_middleware, AuthToken};
use ks_server::routes::router;
use ks_server::ServerState;

fn build_app(auth: AuthToken) -> axum::Router {
    let state: Arc<ServerState> = Arc::new(ServerState::with_tier("test"));
    router(state).layer(from_fn_with_state(auth, auth_middleware))
}

async fn send_get(uri: &str, auth_header: Option<&str>) -> StatusCode {
    let app = build_app(AuthToken::new("test-secret-token"));
    let mut builder = Request::builder().method("GET").uri(uri);
    if let Some(h) = auth_header {
        builder = builder.header("authorization", h);
    }
    let response = app
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .expect("oneshot 不应失败");
    response.status()
}

#[tokio::test]
async fn test_no_token_returns_401() {
    let status = send_get("/api/v1/alerts", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "无 Authorization header 应返回 401，实际: {}",
        status
    );
}

#[tokio::test]
async fn test_wrong_token_returns_401() {
    let status = send_get("/api/v1/alerts", Some("Bearer wrong-token-xxx")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "错误 token 应返回 401，实际: {}",
        status
    );
}

#[tokio::test]
async fn test_correct_token_returns_200() {
    let status = send_get("/api/v1/alerts", Some("Bearer test-secret-token")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "正确 Bearer token 应返回 200，实际: {}",
        status
    );
}

#[tokio::test]
async fn test_no_auth_flag_bypasses() {
    let app = build_app(AuthToken::disabled());
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/alerts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot 不应失败");
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "--no-auth 模式应放行所有请求 (200)，实际: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_health_no_auth_needed() {
    let status = send_get("/api/v1/health", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "/api/v1/health 应免鉴权返回 200，实际: {}",
        status
    );
}

#[tokio::test]
async fn test_metrics_no_auth_needed() {
    let status = send_get("/metrics", None).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "/metrics 应免鉴权返回 200，实际: {}",
        status
    );
}

#[tokio::test]
async fn test_api_v1_version_requires_auth() {

    let status = send_get("/api/v1/version", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "/api/v1/version 不在白名单，无 token 应 401，实际: {}",
        status
    );
}

#[tokio::test]
async fn test_token_case_sensitive() {

    let status = send_get("/api/v1/alerts", Some("Bearer TEST-SECRET-TOKEN")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "token 比对应大小写敏感，大写应 401，实际: {}",
        status
    );
}

#[tokio::test]
async fn test_missing_bearer_prefix_returns_401() {
    let status = send_get("/api/v1/alerts", Some("test-secret-token")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "缺少 Bearer 前缀应 401，实际: {}",
        status
    );
}

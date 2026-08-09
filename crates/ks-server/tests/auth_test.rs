//! 鉴权中间件集成测试。
//!
//! 测试auth_middleware的核心场景:未携带Authorization header返回401,错误token返回401,正确Bearer token返回200,--no-auth(enabled=false)时所有端点放行返回200,白名单路径/api/v1/health免鉴权返回200。
//!
//! 测试方式:用tower::ServiceExt::oneshot直接调用axum Router,无需启动真实TCP监听。Router仅layer auth_middleware(不含audit/rate_limit),专注验证鉴权逻辑。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use tower::ServiceExt;

use ks_server::auth::{auth_middleware, AuthToken};
use ks_server::routes::router;
use ks_server::ServerState;

/// 构建一个带auth_middleware的测试Router。
fn build_app(auth: AuthToken) -> axum::Router {
    let state: Arc<ServerState> = Arc::new(ServerState::with_tier("test"));
    router(state).layer(from_fn_with_state(auth, auth_middleware))
}

/// 发送一个GET请求到指定URI,可选携带Authorization header。
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

/// 1)未携带Authorization header请求/api/v1/alerts返回401
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

/// 2)错误token返回401
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

/// 3)正确Bearer token返回200
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

/// 4)--no-auth(enabled=false)时所有端点放行返回200
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

/// 5)/api/v1/health免鉴权返回200(即使无Authorization header)
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

/// 6)/metrics路径也免鉴权(已存在该路由)
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

/// 7)/version路径免鉴权(注意:现有routes.rs没有/version路由,仅/api/v1/version;
///    此测试用/api/v1/version验证(非白名单)应返回401。
///    白名单中的/version路径无对应路由,会返回404,验证白名单放行(非401)。
#[tokio::test]
async fn test_api_v1_version_requires_auth() {
    // /api/v1/version不在白名单,应401
    let status = send_get("/api/v1/version", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "/api/v1/version 不在白名单，无 token 应 401，实际: {}",
        status
    );
}

/// 8)token比对不应受前缀影响,Bearer test-secret-token后多空格或大小写敏感
#[tokio::test]
async fn test_token_case_sensitive() {
    // 大小写敏感:TEST-SECRET-TOKEN不等于test-secret-token
    let status = send_get("/api/v1/alerts", Some("Bearer TEST-SECRET-TOKEN")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "token 比对应大小写敏感，大写应 401，实际: {}",
        status
    );
}

/// 9)缺少Bearer前缀(仅token字符串)返回401
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

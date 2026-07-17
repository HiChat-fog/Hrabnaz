//! F4 安全加固 — 鉴权中间件集成测试
//!
//! 测试 `auth_middleware` 的 5 个核心场景：
//! - 未携带 Authorization header → 401
//! - 错误 token → 401
//! - 正确 Bearer token → 200
//! - `--no-auth` (enabled=false) 时所有端点放行 → 200
//! - 白名单路径 /api/v1/health 免鉴权 → 200
//!
//! 测试方式：用 `tower::ServiceExt::oneshot` 直接调用 axum Router，
//! 无需启动真实 TCP 监听。Router 仅 layer auth_middleware（不含 audit/rate_limit），
//! 专注验证鉴权逻辑。

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::middleware::from_fn_with_state;
use tower::ServiceExt;

use ks_server::auth::{auth_middleware, AuthToken};
use ks_server::routes::router;
use ks_server::ServerState;

/// 构建一个带 auth_middleware 的测试 Router。
fn build_app(auth: AuthToken) -> axum::Router {
    let state: Arc<ServerState> = Arc::new(ServerState::with_tier("test"));
    router(state).layer(from_fn_with_state(auth, auth_middleware))
}

/// 发送一个 GET 请求到指定 URI，可选携带 Authorization header。
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

/// 1) 未携带 Authorization header 请求 /api/v1/alerts → 401
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

/// 2) 错误 token → 401
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

/// 3) 正确 Bearer token → 200
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

/// 4) `--no-auth` (enabled=false) 时所有端点放行 → 200
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

/// 5) /api/v1/health 免鉴权 → 200（即使无 Authorization header）
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

/// 6) /metrics 路径也免鉴权（F3 已存在该路由）
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

/// 7) /version 路径免鉴权（注意：现有 routes.rs 没有 /version 路由，仅 /api/v1/version；
///    此测试用 /api/v1/version 验证（非白名单）— 应返回 401。
///    白名单中的 /version 路径无对应路由，会返回 404，验证白名单放行（非 401）。
#[tokio::test]
async fn test_api_v1_version_requires_auth() {
    // /api/v1/version 不在白名单 — 应 401
    let status = send_get("/api/v1/version", None).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "/api/v1/version 不在白名单，无 token 应 401，实际: {}",
        status
    );
}

/// 8) token 比对不应受前缀影响 — `Bearer test-secret-token` 后多空格 / 大小写敏感
#[tokio::test]
async fn test_token_case_sensitive() {
    // 大小写敏感：`TEST-SECRET-TOKEN` ≠ `test-secret-token`
    let status = send_get("/api/v1/alerts", Some("Bearer TEST-SECRET-TOKEN")).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "token 比对应大小写敏感，大写应 401，实际: {}",
        status
    );
}

/// 9) 缺少 "Bearer " 前缀（仅 token 字符串）→ 401
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

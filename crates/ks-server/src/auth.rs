//! F4 安全加固 — API 鉴权中间件
//!
//! 基于 Bearer Token 的 API 鉴权，通过 `axum::middleware::from_fn_with_state`
//! 注入到路由链。设计要点：
//!
//! - `AuthToken` 配置结构持有 `token: Option<String>` 与 `enabled: bool`
//!   - `enabled=false` 时（`--no-auth` 模式）所有请求放行
//!   - `token=None` 时启用鉴权但允许所有请求（兼容无 token 部署，仅审计）
//! - 白名单路径免鉴权：`/health`、`/api/v1/health`、`/version`、`/metrics`、`/ws/*`
//!   - 这些路径用于健康检查 / Prometheus 抓取 / WebSocket 升级，不应受 token 保护
//! - 鉴权失败统一返回 `401` + JSON `{"error":"missing or invalid token"}`
//! - Token 比对使用固定时间比较（避免短路时序侧信道）

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

/// 鉴权配置 — 由 CLI flags / 环境变量构建，通过 `from_fn_with_state` 注入中间件。
///
/// - `enabled=true` + `token=Some(t)`：所有非白名单路径要求 `Authorization: Bearer <t>`
/// - `enabled=true` + `token=None`：启用鉴权但允许任意请求（仅用于审计/观测模式）
/// - `enabled=false`：完全关闭鉴权（`--no-auth`，本地调试）
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthToken {
    /// 期望的 Bearer token 字符串；`None` 表示不校验 token（但 `enabled=true` 时仍记录鉴权路径）。
    pub token: Option<String>,
    /// 是否启用鉴权。`--no-auth` 时为 false。
    pub enabled: bool,
}

impl AuthToken {
    /// 启用鉴权 + 指定 token。
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: Some(token.into()),
            enabled: true,
        }
    }

    /// 关闭鉴权（--no-auth 模式）。
    pub fn disabled() -> Self {
        Self {
            token: None,
            enabled: false,
        }
    }
}

/// 鉴权失败响应体（JSON）。
#[derive(Serialize)]
struct AuthError {
    error: &'static str,
}

/// 白名单路径前缀 — 这些路径不要求 Authorization header。
///
/// 设计依据：
/// - `/health`、`/api/v1/health`：k8s/systemd 探针不应携带 token
/// - `/version`：版本信息非敏感
/// - `/metrics`：Prometheus 抓取（受网络层 / mTLS 保护）
/// - `/ws`：WebSocket 升级握手，token 通过 query 参数传递（`?token=...`）由 ws 处理器校验
const WHITELIST_PATHS: &[&str] = &["/health", "/api/v1/health", "/version", "/metrics"];

/// 判断请求路径是否免鉴权。
///
/// `/ws` 路径以 `starts_with` 匹配前缀（覆盖 `/ws/alerts`、`/ws/...` 等子路径），
/// 其它白名单路径精确匹配，避免 `/healthX` 绕过。
fn is_whitelisted(uri: &str) -> bool {
    if uri.starts_with("/ws") {
        return true;
    }
    // 去除 query string 后精确匹配
    let path = uri.split('?').next().unwrap_or(uri);
    WHITELIST_PATHS.contains(&path)
}

/// 固定时间字符串比较（长度不同时仍遍历较长的，避免时序侧信道）。
///
/// 注：长度信息本身会泄露 token 长度，但真实 token 长度不影响机密性。
/// 此实现保证在长度相同时不会因短路提前返回而泄露匹配前缀长度。
fn constant_time_eq(a: &str, b: &str) -> bool {
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut result: usize = ab.len() ^ bb.len();
    let max_len = ab.len().max(bb.len());
    for i in 0..max_len {
        let av = ab.get(i).copied().unwrap_or(0) as usize;
        let bv = bb.get(i).copied().unwrap_or(0) as usize;
        result |= av ^ bv;
    }
    result == 0
}

/// 鉴权中间件 — `axum::middleware::from_fn_with_state` 形态。
///
/// 调用顺序（按 layer 注册的逆序执行）：
/// 1. 检查 `enabled`，false 时直接 `next.run(req)` 放行
/// 2. 检查路径白名单，命中则放行
/// 3. 提取 `Authorization: Bearer <token>` header
/// 4. 与配置 token 固定时间比较
/// 5. 失败返回 `401 + {"error":"missing or invalid token"}`
pub async fn auth_middleware(State(auth): State<AuthToken>, req: Request, next: Next) -> Response {
    // 1. --no-auth 模式直接放行
    if !auth.enabled {
        return next.run(req).await;
    }

    // 2. 白名单路径放行
    let uri = req.uri().path().to_string();
    if is_whitelisted(&uri) {
        return next.run(req).await;
    }

    // 3. enabled=true 但 token=None：放行（仅用于审计模式）
    let expected = match &auth.token {
        Some(t) => t,
        None => return next.run(req).await,
    };

    // 4. 提取 Authorization header
    let provided = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").map(|s| s.to_string()));

    match provided {
        Some(p) if constant_time_eq(&p, expected) => next.run(req).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [("content-type", "application/json")],
            Json(AuthError {
                error: "missing or invalid token",
            }),
        )
            .into_response(),
    }
}

/// 仅供测试使用 — 验证 token 比对与白名单逻辑（无 axum 依赖）。
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq_equal() {
        assert!(constant_time_eq("abc123", "abc123"));
    }

    #[test]
    fn test_constant_time_eq_different() {
        assert!(!constant_time_eq("abc123", "abc124"));
        assert!(!constant_time_eq("abc", "abcd"));
    }

    #[test]
    fn test_whitelist_paths() {
        assert!(is_whitelisted("/health"));
        assert!(is_whitelisted("/api/v1/health"));
        assert!(is_whitelisted("/version"));
        assert!(is_whitelisted("/metrics"));
        assert!(is_whitelisted("/ws/alerts"));
        assert!(is_whitelisted("/ws"));
        // 非白名单
        assert!(!is_whitelisted("/api/v1/alerts"));
        assert!(!is_whitelisted("/healthX")); // 防前缀绕过
        assert!(!is_whitelisted("/api/v1/stats"));
        // query string 不影响白名单判断
        assert!(is_whitelisted("/metrics?foo=bar"));
        assert!(is_whitelisted("/api/v1/health?check=quick"));
    }
}

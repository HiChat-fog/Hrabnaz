//! API鉴权中间件。
//!
//! 基于Bearer Token的API鉴权,通过axum::middleware::from_fn_with_state注入到路由链。AuthToken配置结构持有token: Option<String>与enabled: bool,enabled为false时(--no-auth模式)所有请求放行,token为None时启用鉴权但允许所有请求(兼容无token部署,仅审计)。白名单路径免鉴权:/health、/api/v1/health、/version、/metrics、/ws/*,这些路径用于健康检查、Prometheus抓取、WebSocket升级,不应受token保护。鉴权失败统一返回401加JSON {"error":"missing or invalid token"}。Token比对用固定时间比较避免短路时序侧信道。

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

/// 鉴权配置,由CLI flags或环境变量构建,通过from_fn_with_state注入中间件。
///
/// enabled为true且token为Some(t)时,所有非白名单路径要求Authorization: Bearer <t>;enabled为true且token为None时,启用鉴权但允许任意请求(仅用于审计/观测模式);enabled为false时完全关闭鉴权(--no-auth,本地调试)。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthToken {
    /// 期望的Bearer token字符串,None表示不校验token(但enabled为true时仍记录鉴权路径)。
    pub token: Option<String>,
    /// 是否启用鉴权。--no-auth时为false。
    pub enabled: bool,
}

impl AuthToken {
    /// 启用鉴权并指定token。
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: Some(token.into()),
            enabled: true,
        }
    }

    /// 关闭鉴权(--no-auth模式)。
    pub fn disabled() -> Self {
        Self {
            token: None,
            enabled: false,
        }
    }
}

/// 鉴权失败响应体(JSON)。
#[derive(Serialize)]
struct AuthError {
    error: &'static str,
}

/// 白名单路径前缀,这些路径不要求Authorization header。
///
/// 设计依据:/health和/api/v1/health用于k8s/systemd探针,不应携带token;/version是版本信息非敏感;/metrics供Prometheus抓取(受网络层或mTLS保护);/ws是WebSocket升级握手,token通过query参数传递(?token=...)由ws处理器校验。
const WHITELIST_PATHS: &[&str] = &["/health", "/api/v1/health", "/version", "/metrics"];

/// 判断请求路径是否免鉴权。
///
/// /ws路径以starts_with匹配前缀(覆盖/ws/alerts、/ws/...等子路径),其它白名单路径精确匹配,避免/healthX绕过。
fn is_whitelisted(uri: &str) -> bool {
    if uri.starts_with("/ws") {
        return true;
    }
    // 去除query string后精确匹配
    let path = uri.split('?').next().unwrap_or(uri);
    WHITELIST_PATHS.contains(&path)
}

/// 固定时间字符串比较,长度不同时仍遍历较长的,避免时序侧信道。
///
/// 注:长度信息本身会泄露token长度,但真实token长度不影响机密性。此实现保证在长度相同时不会因短路提前返回而泄露匹配前缀长度。
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

/// 鉴权中间件,axum::middleware::from_fn_with_state形态。
///
/// 调用顺序(按layer注册的逆序执行):检查enabled,false时直接next.run(req)放行;检查路径白名单,命中则放行;提取Authorization: Bearer <token> header;与配置token固定时间比较;失败返回401加{"error":"missing or invalid token"}。
pub async fn auth_middleware(State(auth): State<AuthToken>, req: Request, next: Next) -> Response {
    // --no-auth模式直接放行
    if !auth.enabled {
        return next.run(req).await;
    }

    // 白名单路径放行
    let uri = req.uri().path().to_string();
    if is_whitelisted(&uri) {
        return next.run(req).await;
    }

    // enabled为true但token为None,放行(仅用于审计模式)
    let expected = match &auth.token {
        Some(t) => t,
        None => return next.run(req).await,
    };

    // 提取Authorization header
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

/// 仅供测试使用,验证token比对与白名单逻辑(无axum依赖)。
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
        // query string不影响白名单判断
        assert!(is_whitelisted("/metrics?foo=bar"));
        assert!(is_whitelisted("/api/v1/health?check=quick"));
    }
}

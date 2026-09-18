use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct AuthToken {

    pub token: Option<String>,

    pub enabled: bool,
}

// 手写 Debug 脱敏：明文 token 不能随 {:?} 日志/调试输出泄漏
impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.token {
            Some(t) => write!(f, "AuthToken {{ token: Some(<redacted:{} chars>), enabled: {} }}", t.len(), self.enabled),
            None => write!(f, "AuthToken {{ token: None, enabled: {} }}", self.enabled),
        }
    }
}

impl AuthToken {

    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: Some(token.into()),
            enabled: true,
        }
    }

    pub fn disabled() -> Self {
        Self {
            token: None,
            enabled: false,
        }
    }
}

#[derive(Serialize)]
struct AuthError {
    error: &'static str,
}

const WHITELIST_PATHS: &[&str] = &["/health", "/api/v1/health", "/version", "/metrics"];

fn is_whitelisted(uri: &str) -> bool {
    let path = uri.split('?').next().unwrap_or(uri);
    WHITELIST_PATHS.contains(&path)
}

/// WebSocket 升级前复用同一套 token 比对逻辑
pub fn validate_token(auth: &AuthToken, provided: Option<&str>) -> bool {
    match (&auth.token, provided) {
        (Some(expected), Some(p)) => constant_time_eq(p, expected),
        _ => false,
    }
}

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

pub async fn auth_middleware(State(auth): State<AuthToken>, req: Request, next: Next) -> Response {

    if !auth.enabled {
        return next.run(req).await;
    }

    let uri = req.uri().path().to_string();
    if is_whitelisted(&uri) {
        return next.run(req).await;
    }

    let expected = match &auth.token {
        Some(t) => t,
        // fail-closed：鉴权已启用但未配置 token 时拒绝（与 CLI 启动横幅承诺的行为一致），
        // 旧实现这里直接放行，导致"没配 token = 鉴权形同虚设"
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("content-type", "application/json")],
                Json(AuthError {
                    error: "auth enabled but no token configured on server",
                }),
            )
                .into_response()
        }
    };

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
        // /ws 不再走白名单前缀放行，由 ws_handler 升级前自行校验 token
        assert!(!is_whitelisted("/ws/alerts"));
        assert!(!is_whitelisted("/ws"));

        assert!(!is_whitelisted("/api/v1/alerts"));
        assert!(!is_whitelisted("/healthX"));
        assert!(!is_whitelisted("/api/v1/stats"));

        assert!(is_whitelisted("/metrics?foo=bar"));
        assert!(is_whitelisted("/api/v1/health?check=quick"));
    }

    #[test]
    fn test_validate_token() {
        let auth = AuthToken::new("secret");
        assert!(validate_token(&auth, Some("secret")));
        assert!(!validate_token(&auth, Some("wrong")));
        assert!(!validate_token(&auth, None));
        // enabled=true 且未配 token：一律拒绝（fail-closed）
        let no_token = AuthToken {
            token: None,
            enabled: true,
        };
        assert!(!validate_token(&no_token, Some("anything")));
    }

    #[test]
    fn test_debug_redacts_token() {
        let auth = AuthToken::new("super-secret-value");
        let dbg = format!("{:?}", auth);
        assert!(!dbg.contains("super-secret-value"));
        assert!(dbg.contains("<redacted"));
    }
}

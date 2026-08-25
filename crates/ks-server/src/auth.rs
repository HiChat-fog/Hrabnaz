use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthToken {

    pub token: Option<String>,

    pub enabled: bool,
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
    if uri.starts_with("/ws") {
        return true;
    }

    let path = uri.split('?').next().unwrap_or(uri);
    WHITELIST_PATHS.contains(&path)
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
        None => return next.run(req).await,
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
        assert!(is_whitelisted("/ws/alerts"));
        assert!(is_whitelisted("/ws"));

        assert!(!is_whitelisted("/api/v1/alerts"));
        assert!(!is_whitelisted("/healthX"));
        assert!(!is_whitelisted("/api/v1/stats"));

        assert!(is_whitelisted("/metrics?foo=bar"));
        assert!(is_whitelisted("/api/v1/health?check=quick"));
    }
}

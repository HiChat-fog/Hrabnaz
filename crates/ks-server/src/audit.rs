use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::{File, OpenOptions};
use tokio::sync::Mutex;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditConfig {

    pub log_path: PathBuf,

    pub enabled: bool,
}

impl AuditConfig {
    pub fn new(log_path: impl Into<PathBuf>) -> Self {
        Self {
            log_path: log_path.into(),
            enabled: true,
        }
    }

    pub fn disabled() -> Self {
        Self {
            log_path: PathBuf::new(),
            enabled: false,
        }
    }
}

#[derive(Clone)]
pub struct AuditWriter {
    inner: Arc<Mutex<File>>,
}

impl AuditWriter {

    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(false)
            .open(path)
            .await?;
        Ok(Self {
            inner: Arc::new(Mutex::new(file)),
        })
    }

    pub async fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut f = self.inner.lock().await;
        use tokio::io::AsyncWriteExt;
        f.write_all(line.as_bytes()).await?;
        f.write_all(b"\n").await?;
        f.flush().await?;
        Ok(())
    }
}

pub fn token_id(token: Option<&str>) -> String {
    match token {
        None => "none".to_string(),
        Some(t) => {
            let mut h = Sha256::new();
            h.update(t.as_bytes());
            let digest = h.finalize();
            hex_short(&digest)
        }
    }
}

fn hex_short(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(8);
    for b in bytes.iter().take(4) {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn extract_bearer(req: &Request) -> Option<String> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").map(|s| s.to_string()))
}

fn extract_client_ip(req: &Request) -> String {
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            if let Some(first) = s.split(',').next() {
                return first.trim().to_string();
            }
        }
    }

    "unknown".to_string()
}

#[derive(Serialize)]
struct AuditEntry<'a> {
    timestamp: String,
    client_ip: String,
    token_id: String,
    method: &'a str,
    path: String,
    status: u16,
    latency_ms: u64,
}

pub async fn audit_middleware(
    State(writer): State<Option<AuditWriter>>,
    req: Request,
    next: Next,
) -> Response {

    let start = Instant::now();
    let bearer = extract_bearer(&req);
    let tid = token_id(bearer.as_deref());
    let client_ip = extract_client_ip(&req);
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_default();

    let response = next.run(req).await;

    if let Some(w) = writer {
        let latency_ms = start.elapsed().as_millis() as u64;
        let status = response.status().as_u16();
        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            client_ip,
            token_id: tid,
            method: method.as_str(),
            path,
            status,
            latency_ms,
        };
        match serde_json::to_string(&entry) {
            Ok(line) => {
                if let Err(e) = w.write_line(&line).await {
                    tracing::warn!("audit log write failed: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("audit log serialize failed: {}", e);
            }
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_id_none_returns_none() {
        assert_eq!(token_id(None), "none");
    }

    #[test]
    fn test_token_id_stable_prefix() {

        let id1 = token_id(Some("secret-token-abc"));
        let id2 = token_id(Some("secret-token-abc"));
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 8);

        let id3 = token_id(Some("different-token"));
        assert_ne!(id1, id3);
    }

    #[tokio::test]
    async fn test_audit_writer_writes_lines() {
        let tmp = tempfile_path();
        let writer = AuditWriter::open(&tmp).await.expect("open audit file");
        writer.write_line(r#"{"a":1}"#).await.expect("write line 1");
        writer.write_line(r#"{"a":2}"#).await.expect("write line 2");
        drop(writer);

        let content = tokio::fs::read_to_string(&tmp).await.expect("read back");
        assert!(content.contains(r#"{"a":1}"#));
        assert!(content.contains(r#"{"a":2}"#));

        assert_eq!(content.lines().count(), 2);
        let _ = tokio::fs::remove_file(&tmp).await;
    }

    fn tempfile_path() -> PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        PathBuf::from(format!("/tmp/ks-audit-test-{}-{}.jsonl", pid, nanos))
    }
}

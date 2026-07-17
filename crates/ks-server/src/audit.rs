//! F4 安全加固 — 审计日志中间件
//!
//! 记录每个 HTTP 请求的访问日志，输出为 JSON Lines（每行一个 JSON 对象），
//! 便于 SIEM / Loki 等日志聚合系统采集。
//!
//! 记录字段：
//! - `timestamp`：ISO8601 时间戳
//! - `client_ip`：客户端 IP（来自 X-Forwarded-For 或连接地址）
//! - `token_id`：Bearer token 的 sha256 前 8 位（不可逆，保护原始 token）
//! - `method`：HTTP 方法
//! - `path`：请求路径（含 query string）
//! - `status`：HTTP 状态码
//! - `latency_ms`：处理延迟（毫秒）
//!
//! 实现要点：
//! - 异步写入：用 `tokio::sync::Mutex<tokio::fs::File>` 持有文件句柄
//! - 文件以 append 模式打开，定期 flush（每次写入后 flush，避免日志丢失）
//! - `enabled=false` 时跳过写入（仅作日志记录，不影响请求）

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

/// 审计配置 — 由 CLI flags 构建。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditConfig {
    /// 审计日志文件路径（默认 `/var/log/kernelsentinel/audit.log`）。
    pub log_path: PathBuf,
    /// 是否启用审计。`false` 时中间件直接放行，不写日志。
    pub enabled: bool,
}

impl AuditConfig {
    pub fn new(log_path: impl Into<PathBuf>) -> Self {
        Self {
            log_path: log_path.into(),
            enabled: true,
        }
    }

    /// 关闭审计。
    pub fn disabled() -> Self {
        Self {
            log_path: PathBuf::new(),
            enabled: false,
        }
    }
}

/// 异步文件写入器 — 持有 `tokio::fs::File`，多请求串行写入。
///
/// 用 `tokio::sync::Mutex` 保护文件句柄，避免并发写入导致字节交错。
/// 文件以 append 模式打开，每次 `write_line` 后调用 `flush`（审计日志优先持久化）。
#[derive(Clone)]
pub struct AuditWriter {
    inner: Arc<Mutex<File>>,
}

impl AuditWriter {
    /// 打开（或创建）审计日志文件。
    ///
    /// 父目录不存在时自动创建（如 `/var/log/kernelsentinel/`）。
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

    /// 写入一行 JSON（自动追加换行）。写入后立即 flush。
    pub async fn write_line(&self, line: &str) -> std::io::Result<()> {
        let mut f = self.inner.lock().await;
        use tokio::io::AsyncWriteExt;
        f.write_all(line.as_bytes()).await?;
        f.write_all(b"\n").await?;
        f.flush().await?;
        Ok(())
    }
}

/// 计算给定 Bearer token 的标识符（sha256 前 8 位 hex）。
///
/// 用于审计日志中记录请求方身份而不泄露原始 token。
/// - 输入 `None` → `"none"`（未携带 token）
/// - 输入 `Some(t)` → 8 位 hex 字符串
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

/// 取 4 字节 digest 转 hex 字符串（共 8 字符）。
fn hex_short(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(8);
    for b in bytes.iter().take(4) {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// 提取请求头中的 Bearer token（不验证，仅用于审计）。
fn extract_bearer(req: &Request) -> Option<String> {
    req.headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer ").map(|s| s.to_string()))
}

/// 提取客户端 IP — 优先 `X-Forwarded-For`，否则回退到空字符串。
///
/// 注：axum 的 `ConnectInfo` extension 需通过 `into_make_service_with_connect_info`
/// 才能获取，此处简化处理，仅读取 `X-Forwarded-For` 头部。
fn extract_client_ip(req: &Request) -> String {
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            if let Some(first) = s.split(',').next() {
                return first.trim().to_string();
            }
        }
    }
    // 兜底：标记为 unknown（ConnectInfo 提取需要 into_make_service_with_connect_info）
    "unknown".to_string()
}

/// 单条审计日志记录（序列化为 JSON）。
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

/// 审计中间件 — `axum::middleware::from_fn_with_state` 形态。
///
/// 流程：
/// 1. 记录起始时间 + 提取 token_id / client_ip / method / path
/// 2. 调用下游 handler，获取 response
/// 3. 计算 latency_ms，提取 status code
/// 4. 序列化为 JSON line，异步写入文件
/// 5. 写入失败仅记录 tracing::warn，不阻塞响应
pub async fn audit_middleware(
    State(writer): State<Option<AuditWriter>>,
    req: Request,
    next: Next,
) -> Response {
    // 立即开始计时 + 提取请求元数据（不消耗 body）
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

    // 调用下游
    let response = next.run(req).await;

    // 仅当 writer 存在时写日志（disabled 时由 ServerConfig 传 None）
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
        // 同一 token 应得到同一 ID（前 8 位 hex）
        let id1 = token_id(Some("secret-token-abc"));
        let id2 = token_id(Some("secret-token-abc"));
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 8);
        // 不同 token 应得到不同 ID
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
        // 每行一个 JSON + 换行
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

//! F4 安全加固 — TLS 双向认证 (mTLS)
//!
//! 基于 `rustls 0.23` + `axum-server 0.7` (tls-rustls-no-provider feature)。
//!
//! 设计要点：
//! - crypto provider 使用 `ring`（避免 aws-lc-rs 对 cmake/cc 的依赖）
//! - `TlsConfig` 持有 server_cert / server_key / 可选 client_ca
//! - `client_ca=None` 时仅启用单向 TLS（服务器出示证书，客户端可选验证）
//! - `client_ca=Some(path)` 时启用 mTLS：客户端必须出示由该 CA 签发的证书
//! - `serve_tls(app, addr, tls_config)` 用 `axum_server::bind_rustls` 启动 HTTPS
//!
//! 注：本模块的所有 `async` 函数在 `spawn_blocking` 之外执行 I/O，
//! 但 `rustls-pemfile` 解析在阻塞线程池中完成（避免阻塞 reactor）。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::Item;

/// TLS 配置 — 由 CLI flags 构建。
///
/// - `server_cert` / `server_key`：服务器证书 + 私钥（PEM 格式，必填）
/// - `client_ca`：客户端 CA 证书（PEM 格式，可选）。`Some` 时启用 mTLS。
#[derive(Clone, Debug, Default)]
pub struct TlsConfig {
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_ca: Option<PathBuf>,
}

impl TlsConfig {
    /// 从 CLI flags 构建。
    pub fn new(
        server_cert: impl Into<PathBuf>,
        server_key: impl Into<PathBuf>,
        client_ca: Option<PathBuf>,
    ) -> Self {
        Self {
            server_cert: server_cert.into(),
            server_key: server_key.into(),
            client_ca,
        }
    }

    /// 是否启用 mTLS（即客户端证书被强制验证）。
    pub fn is_mtls(&self) -> bool {
        self.client_ca.is_some()
    }
}

/// 显式安装 ring crypto provider 为默认。
///
/// 必须在首次使用 rustls 前调用（多次调用幂等，返回 Err 表示已被其它 provider 占用，忽略即可）。
/// 由于 `axum-server::tls_rustls::RustlsConfig::from_pem_file` 内部使用
/// `ServerConfig::builder()`（取默认 provider），所以必须先安装。
fn install_ring_provider() {
    // install_default() 返回 Err 表示已有 provider 被安装（可能是 aws-lc-rs 或其它），
    // 此时无需重装（重装会 panic）。安全忽略。
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// 加载 PEM 文件中的证书链（一个或多个 X.509 证书）。
fn load_certs(mut pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut pem)
        .map(|it| it.map(|c| CertificateDer::from(c.to_vec())))
        .collect::<Result<_, _>>()
        .map_err(|e| anyhow!("解析证书 PEM 失败: {}", e))?;
    if certs.is_empty() {
        return Err(anyhow!("证书文件不包含任何 X.509 证书"));
    }
    Ok(certs)
}

/// 从 PEM 字节中提取私钥（支持 PKCS#8 / PKCS#1 / Sec1 三种格式）。
fn load_private_key(mut pem: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut keys: Vec<PrivateKeyDer> = rustls_pemfile::read_all(&mut pem)
        .filter_map(|item| match item.ok()? {
            Item::Pkcs8Key(k) => Some(k.into()),
            Item::Pkcs1Key(k) => Some(k.into()),
            Item::Sec1Key(k) => Some(k.into()),
            _ => None,
        })
        .collect();
    match keys.len() {
        0 => Err(anyhow!("私钥文件不包含任何 RSA/ECDSA 私钥")),
        1 => Ok(keys.pop().unwrap()),
        n => Err(anyhow!("私钥文件包含 {} 个私钥（应仅 1 个）", n)),
    }
}

/// 加载客户端 CA 根证书到 `RootCertStore`（用于 mTLS 验证）。
fn load_client_ca_roots(pem: &[u8]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let certs = load_certs(pem)?;
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!("client_ca 文件不包含任何可解析的根证书"));
    }
    Ok(roots)
}

/// 加载 TLS 配置 — 返回 `axum_server::tls_rustls::RustlsConfig`。
///
/// 流程：
/// 1. 安装 ring crypto provider（幂等）
/// 2. 读取 server_cert / server_key PEM 文件
/// 3. 构造 `rustls::ServerConfig`：
///    - 无 client_ca：`with_no_client_auth()`（单向 TLS）
///    - 有 client_ca：`with_client_cert_verifier(...)`（mTLS，强制客户端出示证书）
/// 4. 设置 ALPN（h2 + http/1.1）
/// 5. 包装为 `RustlsConfig::from_config`
pub async fn load_tls_config(cfg: &TlsConfig) -> Result<RustlsConfig> {
    install_ring_provider();

    let cert_pem = tokio::fs::read(&cfg.server_cert)
        .await
        .with_context(|| format!("读取服务器证书失败: {}", cfg.server_cert.display()))?;
    let key_pem = tokio::fs::read(&cfg.server_key)
        .await
        .with_context(|| format!("读取服务器私钥失败: {}", cfg.server_key.display()))?;

    let certs = load_certs(&cert_pem)?;
    let key = load_private_key(&key_pem)?;

    let mut server_config = match &cfg.client_ca {
        Some(ca_path) => {
            let ca_pem = tokio::fs::read(ca_path)
                .await
                .with_context(|| format!("读取客户端 CA 失败: {}", ca_path.display()))?;
            let roots = load_client_ca_roots(&ca_pem)?;
            // 强制客户端出示证书（mandatory=true）；可选设为 allow_unknown 模式
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| anyhow!("构造客户端证书校验器失败: {}", e))?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| anyhow!("构造 mTLS ServerConfig 失败: {}", e))?
        }
        None => ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow!("构造 TLS ServerConfig 失败: {}", e))?,
    };
    // ALPN 协商：HTTP/2 优先，回退 HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

/// 用 axum_server 启动 TLS 服务器。
///
/// `addr` 形如 `"127.0.0.1:8443"` 或 `"0.0.0.0:8443"`。
/// `rustls_config` 由 `load_tls_config()` 返回。
/// `mtls` 标志仅用于日志记录，是否真正启用 mTLS 由 `rustls_config` 决定。
///
/// 调用方负责 app（Router）的构建（包括所有中间件 layer）。
pub async fn serve_tls(
    app: axum::Router,
    addr: &str,
    rustls_config: RustlsConfig,
    mtls: bool,
) -> Result<()> {
    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("TLS bind 地址解析失败: {}", addr))?;
    log::info!(
        "ks-server listening on https://{} (TLS, mTLS={})",
        socket_addr,
        mtls
    );
    println!(
        "ks-server listening on https://{} (TLS, mTLS={})",
        socket_addr, mtls
    );
    axum_server::tls_rustls::bind_rustls(socket_addr, rustls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| anyhow!("TLS 服务器退出: {}", e))?;
    Ok(())
}

/// 兼容性占位：判断路径存在性（供 CLI 预检使用）。
pub fn check_files_exist(cfg: &TlsConfig) -> Result<()> {
    if !Path::new(&cfg.server_cert).exists() {
        return Err(anyhow!("TLS 证书不存在: {}", cfg.server_cert.display()));
    }
    if !Path::new(&cfg.server_key).exists() {
        return Err(anyhow!("TLS 私钥不存在: {}", cfg.server_key.display()));
    }
    if let Some(ca) = &cfg.client_ca {
        if !Path::new(ca).exists() {
            return Err(anyhow!("客户端 CA 证书不存在: {}", ca.display()));
        }
    }
    Ok(())
}

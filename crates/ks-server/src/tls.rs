//! TLS双向认证(mTLS)。
//!
//! 基于rustls 0.23加axum-server 0.7(tls-rustls-no-provider feature)。
//!
//! 设计上crypto provider用ring(避免aws-lc-rs对cmake/cc的依赖);TlsConfig持有server_cert、server_key和可选client_ca;client_ca为None时仅启用单向TLS(服务器出示证书,客户端可选验证),为Some(path)时启用mTLS,客户端必须出示由该CA签发的证书;serve_tls用axum_server::bind_rustls启动HTTPS。
//!
//! 注:本模块所有async函数在spawn_blocking之外执行I/O,但rustls-pemfile解析在阻塞线程池中完成(避免阻塞reactor)。

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::Item;

/// TLS配置,由CLI flags构建。
///
/// server_cert和server_key是服务器证书加私钥(PEM格式,必填);client_ca是客户端CA证书(PEM格式,可选),为Some时启用mTLS。
#[derive(Clone, Debug, Default)]
pub struct TlsConfig {
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_ca: Option<PathBuf>,
}

impl TlsConfig {
    /// 从CLI flags构建。
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

    /// 是否启用mTLS(即客户端证书被强制验证)。
    pub fn is_mtls(&self) -> bool {
        self.client_ca.is_some()
    }
}

/// 显式安装ring crypto provider为默认。
///
/// 必须在首次使用rustls前调用(多次调用幂等,返回Err表示已被其它provider占用,忽略即可)。axum-server::tls_rustls::RustlsConfig::from_pem_file内部用ServerConfig::builder()(取默认provider),所以必须先安装。
fn install_ring_provider() {
    // install_default()返回Err表示已有provider被安装(可能是aws-lc-rs或其它),
    // 此时无需重装(重装会panic),安全忽略。
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// 加载PEM文件中的证书链(一个或多个X.509证书)。
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

/// 从PEM字节中提取私钥(支持PKCS#8、PKCS#1、Sec1三种格式)。
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

/// 加载客户端CA根证书到RootCertStore(用于mTLS验证)。
fn load_client_ca_roots(pem: &[u8]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let certs = load_certs(pem)?;
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!("client_ca 文件不包含任何可解析的根证书"));
    }
    Ok(roots)
}

/// 加载TLS配置,返回axum_server::tls_rustls::RustlsConfig。
///
/// 流程:安装ring crypto provider(幂等),读server_cert和server_key PEM文件,构造rustls::ServerConfig(无client_ca走with_no_client_auth()单向TLS,有client_ca走with_client_cert_verifier(...)即mTLS强制客户端出示证书),设置ALPN(h2 + http/1.1),包装为RustlsConfig::from_config。
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
                .with_context(|| format!("读取客户端CA失败: {}", ca_path.display()))?;
            let roots = load_client_ca_roots(&ca_pem)?;
            // 强制客户端出示证书(mandatory为true),可选设为allow_unknown模式
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| anyhow!("构造客户端证书校验器失败: {}", e))?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(certs, key)
                .map_err(|e| anyhow!("构造mTLS ServerConfig失败: {}", e))?
        }
        None => ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow!("构造TLS ServerConfig失败: {}", e))?,
    };
    // ALPN协商:HTTP/2优先,回退HTTP/1.1
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

/// 用axum_server启动TLS服务器。
///
/// addr形如127.0.0.1:8443或0.0.0.0:8443。rustls_config由load_tls_config()返回。mtls标志仅用于日志记录,是否真正启用mTLS由rustls_config决定。调用方负责app(Router)的构建(包括所有中间件layer)。
pub async fn serve_tls(
    app: axum::Router,
    addr: &str,
    rustls_config: RustlsConfig,
    mtls: bool,
) -> Result<()> {
    let socket_addr: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("TLS bind地址解析失败: {}", addr))?;
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

/// 兼容性占位:判断路径存在性(供CLI预检使用)。
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

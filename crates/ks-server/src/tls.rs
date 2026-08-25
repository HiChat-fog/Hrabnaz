use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pemfile::Item;

#[derive(Clone, Debug, Default)]
pub struct TlsConfig {
    pub server_cert: PathBuf,
    pub server_key: PathBuf,
    pub client_ca: Option<PathBuf>,
}

impl TlsConfig {

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

    pub fn is_mtls(&self) -> bool {
        self.client_ca.is_some()
    }
}

fn install_ring_provider() {

    let _ = rustls::crypto::ring::default_provider().install_default();
}

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

fn load_client_ca_roots(pem: &[u8]) -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let certs = load_certs(pem)?;
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(anyhow!("client_ca 文件不包含任何可解析的根证书"));
    }
    Ok(roots)
}

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

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

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

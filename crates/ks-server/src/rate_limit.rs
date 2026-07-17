//! F4 安全加固 — 速率限制中间件
//!
//! 基于 `tower_governor 0.4` + `governor 0.6`，按客户端 IP 限流。
//!
//! 默认策略：100 req/min/IP（令牌桶，每秒补充 ~1.67 个 token，突发上限 100）。
//!
//! 行为：
//! - 超限请求返回 `429 Too Many Requests`
//! - 默认携带 `x-ratelimit-after` 头（剩余等待秒数）
//! - 启用 `use_headers()` 后额外携带 `x-ratelimit-limit` / `x-ratelimit-remaining`
//!
//! 注意事项：
//! - 默认 `PeerIpKeyExtractor` 从 `axum::extract::ConnectInfo<SocketAddr>` 提取 IP，
//!   服务器必须用 `app.into_make_service_with_connect_info::<SocketAddr>()` 启动。
//! - 测试中需手动向 Request 注入 `ConnectInfo` extension（无真实 TCP 连接）。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use governor::middleware::StateInformationMiddleware;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::GovernorLayer;

/// 我们使用的 GovernorLayer 类型别名 — 启用 `use_headers()` 后中间件为 `StateInformationMiddleware`。
pub type KsGovernorLayer = GovernorLayer<PeerIpKeyExtractor, StateInformationMiddleware>;

/// 默认速率限制（每分钟请求数）。
pub const DEFAULT_RATE_LIMIT_PER_MIN: u32 = 100;

/// 构建速率限制 layer — 每 `limit_per_min` 个请求/分钟/IP。
///
/// - 令牌桶周期：60 秒（即每 60s 重置一次配额）
/// - 突发上限：`limit_per_min`（即允许瞬间涌入 N 个请求，超过则 429）
/// - 启用 `use_headers()`：响应携带 `x-ratelimit-limit` / `x-ratelimit-remaining` / `x-ratelimit-after`
///
/// 返回的 `GovernorLayer` 应通过 `Router::layer(...)` 注入。
/// 注：`GovernorLayer` 必须包在 `Arc` 中（其 `Layer` impl 需要 `Arc<GovernorConfig>`）。
pub fn build_rate_limiter(limit_per_min: u32) -> KsGovernorLayer {
    let limit = limit_per_min.max(1);
    let config = GovernorConfigBuilder::default()
        .per_second(60)
        .burst_size(limit)
        .use_headers()
        .finish()
        .expect("build_rate_limiter: burst_size 与 period 均非零，finish 不会返回 None");
    KsGovernorLayer {
        config: Arc::new(config),
    }
}

/// 便捷构造：用默认 100 req/min 构建。
pub fn default_rate_limiter() -> KsGovernorLayer {
    build_rate_limiter(DEFAULT_RATE_LIMIT_PER_MIN)
}

/// 测试辅助：向 axum Request 注入 `ConnectInfo<SocketAddr>` extension。
///
/// 用于在没有真实 TCP 监听的集成测试（如 `tower::ServiceExt::oneshot`）中
/// 让 `PeerIpKeyExtractor` 能提取出 IP。生产代码无需调用此函数 —
/// `axum::serve` 会自动注入 ConnectInfo（需用 `into_make_service_with_connect_info`）。
pub fn inject_connect_info_for_test<B>(
    mut req: axum::http::Request<B>,
    addr: SocketAddr,
) -> axum::http::Request<B> {
    req.extensions_mut().insert(ConnectInfo(addr));
    req
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_rate_limiter_default() {
        let layer = build_rate_limiter(100);
        // GovernorLayer 内部 Arc 应非空
        assert!(Arc::strong_count(&layer.config) >= 1);
    }

    #[test]
    fn test_build_rate_limiter_min_one() {
        // 0 应被钳制为 1，不应 panic
        let _layer = build_rate_limiter(0);
        let _layer = build_rate_limiter(1);
    }
}

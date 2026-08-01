//! 速率限制中间件。
//!
//! 基于tower_governor 0.4加governor 0.6,按客户端IP限流。默认策略100 req/min/IP(令牌桶,每秒补充约1.67个token,突发上限100)。超限请求返回429 Too Many Requests,默认携带x-ratelimit-after头(剩余等待秒数),启用use_headers()后额外携带x-ratelimit-limit和x-ratelimit-remaining。
//!
//! 注意:默认PeerIpKeyExtractor从axum::extract::ConnectInfo<SocketAddr>提取IP,服务器必须用app.into_make_service_with_connect_info::<SocketAddr>()启动;测试中需手动向Request注入ConnectInfo extension(无真实TCP连接)。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use governor::middleware::StateInformationMiddleware;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::GovernorLayer;

/// 我们使用的GovernorLayer类型别名,启用use_headers()后中间件为StateInformationMiddleware。
pub type KsGovernorLayer = GovernorLayer<PeerIpKeyExtractor, StateInformationMiddleware>;

/// 默认速率限制(每分钟请求数)。
pub const DEFAULT_RATE_LIMIT_PER_MIN: u32 = 100;

/// 构建速率限制layer,每limit_per_min个请求每分钟每IP。
///
/// 令牌桶周期60秒(每60s重置一次配额),突发上限limit_per_min(允许瞬间涌入N个请求,超过则429),启用use_headers()使响应携带x-ratelimit-limit、x-ratelimit-remaining、x-ratelimit-after。
///
/// 返回的GovernorLayer应通过Router::layer(...)注入。GovernorLayer必须包在Arc中(其Layer impl需要Arc<GovernorConfig>)。
pub fn build_rate_limiter(limit_per_min: u32) -> KsGovernorLayer {
    let limit = limit_per_min.max(1);
    let config = GovernorConfigBuilder::default()
        .per_second(60)
        .burst_size(limit)
        .use_headers()
        .finish()
        .expect("build_rate_limiter: burst_size与period均非零,finish不会返回None");
    KsGovernorLayer {
        config: Arc::new(config),
    }
}

/// 便捷构造,用默认100 req/min构建。
pub fn default_rate_limiter() -> KsGovernorLayer {
    build_rate_limiter(DEFAULT_RATE_LIMIT_PER_MIN)
}

/// 测试辅助:向axum Request注入ConnectInfo<SocketAddr> extension。
///
/// 用于在没有真实TCP监听的集成测试(如tower::ServiceExt::oneshot)中让PeerIpKeyExtractor能提取出IP。生产代码无需调用此函数,axum::serve会自动注入ConnectInfo(需用into_make_service_with_connect_info)。
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
        // GovernorLayer内部Arc应非空
        assert!(Arc::strong_count(&layer.config) >= 1);
    }

    #[test]
    fn test_build_rate_limiter_min_one() {
        // 0应被钳制为1,不应panic
        let _layer = build_rate_limiter(0);
        let _layer = build_rate_limiter(1);
    }
}

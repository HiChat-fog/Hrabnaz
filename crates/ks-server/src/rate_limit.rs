use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::ConnectInfo;
use governor::middleware::StateInformationMiddleware;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::key_extractor::PeerIpKeyExtractor;
use tower_governor::GovernorLayer;

pub type KsGovernorLayer = GovernorLayer<PeerIpKeyExtractor, StateInformationMiddleware>;

pub const DEFAULT_RATE_LIMIT_PER_MIN: u32 = 100;

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

pub fn default_rate_limiter() -> KsGovernorLayer {
    build_rate_limiter(DEFAULT_RATE_LIMIT_PER_MIN)
}

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

        assert!(Arc::strong_count(&layer.config) >= 1);
    }

    #[test]
    fn test_build_rate_limiter_min_one() {

        let _layer = build_rate_limiter(0);
        let _layer = build_rate_limiter(1);
    }
}

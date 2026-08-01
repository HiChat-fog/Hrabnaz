//! eBPF Perf tier事件源(Legacy 4.x和Ancient 3.10均用perfbuf)
//!
//! 包装EbpfLoader(内部EventBackend::PerfEvent处理per-CPU perfbuf轮询),实现EventSource trait。与EbpfModernSource结构对称,仅kind和description不同。

#![cfg(target_os = "linux")]

use anyhow::Result;
use async_trait::async_trait;

use crate::event_source::{EventSource, SourceKind};
use crate::loader::EbpfLoader;

/// Perf tier事件源,持有EbpfLoader(PerfEvent backend),round-robin轮询per-CPU buffers。
///
/// Legacy(4.x)和Ancient(3.10+)共用此源,两者都走perfbuf,仅kind()返回值不同(供日志和配置区分)。
pub struct EbpfPerfSource {
    loader: EbpfLoader,
    tier: SourceKind,
}

impl EbpfPerfSource {
    pub fn new(loader: EbpfLoader, tier: SourceKind) -> Self {
        debug_assert!(
            tier == SourceKind::EbpfLegacy || tier == SourceKind::EbpfAncient,
            "EbpfPerfSource 仅用于 Legacy/Ancient tier"
        );
        Self { loader, tier }
    }

    pub fn loader(&self) -> &EbpfLoader {
        &self.loader
    }
}

#[async_trait]
impl EventSource for EbpfPerfSource {
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.loader.try_next_events().map(|(_source, bytes)| bytes))
    }

    fn kind(&self) -> SourceKind {
        self.tier
    }

    fn description(&self) -> &str {
        match self.tier {
            SourceKind::EbpfLegacy => "eBPF Legacy tier (4.x perfbuf, per-CPU 轮询)",
            SourceKind::EbpfAncient => "eBPF Ancient tier (3.10+ BTF backport, perfbuf)",
            _ => unreachable!(),
        }
    }

    fn is_mock(&self) -> bool {
        false
    }
}

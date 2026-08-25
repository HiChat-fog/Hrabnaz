#![cfg(target_os = "linux")]

use anyhow::Result;
use async_trait::async_trait;

use crate::event_source::{EventSource, SourceKind};
use crate::loader::EbpfLoader;

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

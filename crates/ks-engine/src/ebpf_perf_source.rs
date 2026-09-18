#![cfg(target_os = "linux")]

use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;

use crate::event_source::{EventSource, SourceKind};
use crate::loader::EbpfLoader;

/// 忙轮询退避（与 EbpfModernSource 一致）：无事件时 50µs→2ms 指数退避，
/// 避免 legacy/ancient aya 路径在空闲时烧满单核
const BACKOFF_MAX: Duration = Duration::from_millis(2);
const BACKOFF_STEP_START: Duration = Duration::from_micros(50);

pub struct EbpfPerfSource {
    loader: EbpfLoader,
    tier: SourceKind,
    backoff: Duration,
}

impl EbpfPerfSource {
    pub fn new(loader: EbpfLoader, tier: SourceKind) -> Self {
        debug_assert!(
            tier == SourceKind::EbpfLegacy || tier == SourceKind::EbpfAncient,
            "EbpfPerfSource 仅用于 Legacy/Ancient tier"
        );
        Self {
            loader,
            tier,
            backoff: BACKOFF_STEP_START,
        }
    }

    pub fn loader(&self) -> &EbpfLoader {
        &self.loader
    }
}

#[async_trait]
impl EventSource for EbpfPerfSource {
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        let r = self.loader.try_next_events().map(|(_source, bytes)| bytes);
        if r.is_some() {
            self.backoff = BACKOFF_STEP_START;
        } else {
            tokio::time::sleep(self.backoff).await;
            self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
        }
        Ok(r)
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

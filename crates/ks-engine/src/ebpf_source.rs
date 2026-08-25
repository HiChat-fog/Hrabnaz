#![cfg(target_os = "linux")]

use anyhow::Result;
use async_trait::async_trait;
use std::io::Write;

use crate::event_source::{EventSource, SourceKind};
use crate::loader::EbpfLoader;

pub struct EbpfModernSource {
    loader: EbpfLoader,
    poll_count: u64,
    some_count: u64,
    none_count: u64,
}

impl Drop for EbpfModernSource {
    fn drop(&mut self) {
        let _ = std::fs::OpenOptions::new().create(true).append(true).open("/tmp/ks-modern-diag.log")
            .and_then(|mut f| writeln!(f,
                "[modern-drop] poll={} some={} none={}",
                self.poll_count, self.some_count, self.none_count));
    }
}

impl EbpfModernSource {
    pub fn new(loader: EbpfLoader) -> Self {
        Self { loader, poll_count: 0, some_count: 0, none_count: 0 }
    }

    pub fn loader(&self) -> &EbpfLoader {
        &self.loader
    }
}

#[async_trait]
impl EventSource for EbpfModernSource {
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        let r = self.loader.try_next_events().map(|(_source, bytes)| bytes);
        if r.is_some() { self.some_count += 1; } else { self.none_count += 1; }
        self.poll_count = self.poll_count.wrapping_add(1);
        Ok(r)
    }

    fn kind(&self) -> SourceKind {
        SourceKind::EbpfModern
    }

    fn description(&self) -> &str {
        "eBPF Modern tier (5.8+ ringbuf, 5 ringbuf 持久轮询)"
    }

    fn is_mock(&self) -> bool {
        false
    }

    fn protected_pids(&self) -> &[u32] {
        self.loader.protected_pids()
    }
}

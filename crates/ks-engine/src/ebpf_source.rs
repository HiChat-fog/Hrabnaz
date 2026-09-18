#![cfg(target_os = "linux")]

use anyhow::Result;
use async_trait::async_trait;
use std::io::Write;
use std::time::Duration;

use crate::event_source::{EventSource, SourceKind};
use crate::loader::EbpfLoader;

/// 忙轮询退避：try_next_events 无事件时立即返回 None，调用方 select 循环会 100% CPU 自旋。
/// 连续空转时按 50µs→2ms 指数退避小睡，一旦取到事件立即恢复满速
const BACKOFF_MAX: Duration = Duration::from_millis(2);
const BACKOFF_STEP_START: Duration = Duration::from_micros(50);

pub struct EbpfModernSource {
    loader: EbpfLoader,
    poll_count: u64,
    some_count: u64,
    none_count: u64,
    backoff: Duration,
}

impl Drop for EbpfModernSource {
    fn drop(&mut self) {
        // 诊断日志改为 KS_DEBUG_DIAG=1 显式开启，不再无条件写 /tmp/ks-modern-diag.log
        if std::env::var("KS_DEBUG_DIAG").as_deref() == Ok("1") {
            let _ = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/ks-modern-diag.log")
                .and_then(|mut f| {
                    writeln!(
                        f,
                        "[modern-drop] poll={} some={} none={}",
                        self.poll_count, self.some_count, self.none_count
                    )
                });
        }
    }
}

impl EbpfModernSource {
    pub fn new(loader: EbpfLoader) -> Self {
        Self {
            loader,
            poll_count: 0,
            some_count: 0,
            none_count: 0,
            backoff: BACKOFF_STEP_START,
        }
    }

    pub fn loader(&self) -> &EbpfLoader {
        &self.loader
    }
}

#[async_trait]
impl EventSource for EbpfModernSource {
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        let r = self.loader.try_next_events().map(|(_source, bytes)| bytes);
        if r.is_some() {
            self.some_count += 1;
            self.backoff = BACKOFF_STEP_START;
        } else {
            self.none_count += 1;
            // 空转退避：50µs 起步指数增长到 2ms 封顶，避免无事件时烧满单核
            tokio::time::sleep(self.backoff).await;
            self.backoff = (self.backoff * 2).min(BACKOFF_MAX);
        }
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

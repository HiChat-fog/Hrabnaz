//! eBPF Modern tier 事件源（5.8+，BPF_MAP_TYPE_RINGBUF）
//!
//! A7：包装 EbpfLoader，通过 EventSource trait 路由 eBPF 事件。
//! 替代了原 start.rs 中绕过 trait 直接调 loader.try_next_event() 的双路径逻辑，
//! 使事件源后端可热插拔（modern → legacy → ancient 在 Phase B/C 切换时不影响调用方）。

#![cfg(target_os = "linux")]

use anyhow::Result;
use async_trait::async_trait;

use crate::loader::EbpfLoader;
use crate::event_source::{EventSource, SourceKind};

/// 现代 eBPF tier 事件源：持有 EbpfLoader，round-robin 轮询 5 个 RingBuf。
///
/// 设计要点：
/// - 持有 EbpfLoader 的 ownership（loader 内部已 take_map 出 RingBuf 持久持有）
/// - next_bytes 调 loader.try_next_events()，丢弃来源标签（Phase B 可加）
/// - 不实现 Sync（RingBuf 是 Send 不 Sync），与 EventSource trait 一致
/// - Drop 时 EbpfLoader 自动 drop，rings/bpf fd 自动关闭
pub struct EbpfModernSource {
    loader: EbpfLoader,
}

impl EbpfModernSource {
    pub fn new(loader: EbpfLoader) -> Self {
        Self { loader }
    }

    /// 借用 loader（用于状态查询，不转移 ownership）。
    pub fn loader(&self) -> &EbpfLoader {
        &self.loader
    }
}

#[async_trait]
impl EventSource for EbpfModernSource {
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        // try_next_events round-robin 5 个 ringbuf，返回 (来源名, 字节)。
        // 当前丢弃来源标签；A8 之后若需按来源分流可在调用方保留。
        Ok(self.loader.try_next_events().map(|(_source, bytes)| bytes))
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
}

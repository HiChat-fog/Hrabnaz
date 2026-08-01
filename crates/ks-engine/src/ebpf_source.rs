//! eBPF Modern tier事件源(5.8+,BPF_MAP_TYPE_RINGBUF)
//!
//! 包装EbpfLoader,通过EventSource trait路由eBPF事件。替代了原start.rs中绕过trait直接调loader.try_next_event()的双路径逻辑,使事件源后端可热插拔(modern、legacy、ancient切换时不影响调用方)。

#![cfg(target_os = "linux")]

use anyhow::Result;
use async_trait::async_trait;
use std::io::Write;

use crate::event_source::{EventSource, SourceKind};
use crate::loader::EbpfLoader;

/// 现代eBPF tier事件源,持有EbpfLoader,round-robin轮询5个RingBuf。
///
/// 设计上持有EbpfLoader的ownership(loader内部已take_map出RingBuf持久持有);next_bytes调loader.try_next_events()丢弃来源标签;不实现Sync(RingBuf是Send不Sync),与EventSource trait一致;Drop时EbpfLoader自动drop,rings和bpf fd自动关闭。
pub struct EbpfModernSource {
    loader: EbpfLoader,
    /// 压测诊断:next_bytes调用计数,每20000次打印一次内核侧syscount。
    poll_count: u64,
    /// 诊断:next_bytes返回Some的次数(真正取到事件)。
    some_count: u64,
    /// 诊断:next_bytes返回None的次数(空轮询走yield_now)。
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

    /// 借用loader(用于状态查询,不转移ownership)。
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

pub mod aggregator;
pub mod baseline;
pub mod blocker;
pub mod btf_source;
pub mod chain;
pub mod cloader_source;
pub mod config;
pub mod correlation;
pub mod detector;
#[cfg(target_os = "linux")]
pub mod ebpf_perf_source;
#[cfg(target_os = "linux")]
pub mod ebpf_source;
pub mod engine;
pub mod event_source;
// 取证链/JSONL 读取与安全 syscall 封装是跨实现契约，本体居于 ks-core；
// re-export 维持 crate 内 `crate::forensic`/`crate::sys` 路径与外部 `ks_engine::forensic` 可用
pub use ks_core::forensic;
pub use ks_core::sys;
#[cfg(target_os = "linux")]
pub mod linux_map_reader;
#[cfg(target_os = "linux")]
pub mod pinned_map_reader;
pub mod loader;
pub mod ml_detector;
pub mod process_tree;
pub mod rules_integrity;
pub mod tier_detect;

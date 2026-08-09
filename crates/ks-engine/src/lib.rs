pub mod aggregator;
pub mod baseline;
pub mod blocker;
pub mod chain;
/// C loader sidecar事件源(3.10 stock内核无BTF,fork+exec ks_loader)。
///
/// 注:tokio::process跨unix平台可用,故不做cfg(target_os="linux")限制,但实际只在Linux上有意义(非Linux平台spawn ks_loader会失败)。
pub mod cloader_source;
pub mod config;
pub mod correlation;
pub mod detector;
#[cfg(target_os = "linux")]
pub mod ebpf_perf_source;
#[cfg(target_os = "linux")]
pub mod ebpf_source;
pub mod event_source;
pub mod forensic;
/// 真实BPF map读取器(通过aya::Ebpf读取map_type/max_entries)。
#[cfg(target_os = "linux")]
pub mod linux_map_reader;
pub mod loader;
pub mod ml_detector;
pub mod process_tree;
pub mod tier_detect;

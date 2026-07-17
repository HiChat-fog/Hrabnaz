pub mod aggregator;
pub mod baseline;
pub mod blocker;
pub mod chain;
/// Phase E2.2：C loader sidecar 事件源（3.10 stock 内核无 BTF，fork+exec ks_loader）。
///
/// 注：tokio::process 跨 unix 平台可用，故不做 `cfg(target_os="linux")` 限制；
/// 但实际只在 Linux 上有意义（非 Linux 平台 spawn ks_loader 会失败）。
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
/// Phase E1.2：真实 BPF map 读取器（通过 aya::Ebpf 读取 map_type/max_entries）。
#[cfg(target_os = "linux")]
pub mod linux_map_reader;
pub mod loader;
pub mod ml_detector;
pub mod process_tree;
pub mod tier_detect;

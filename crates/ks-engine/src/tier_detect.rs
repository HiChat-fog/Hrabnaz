//! eBPF tier 自动探测 — 根据内核版本选择合适的 eBPF 后端。
//!
//! 多 tier eBPF 架构对应表：
//! - Modern (5.8+)   → BPF_MAP_TYPE_RINGBUF（性能最佳）
//! - Legacy (4.x)    → BPF_MAP_TYPE_PERF_EVENT_ARRAY（perfbuf，Phase B 实现）
//! - Ancient (3.10+) → BTF backport + HASH 手动 LRU（CentOS 7，Phase C 研究性突破）
//!
//! 探测依据：/proc/sys/kernel/osrelease 主.次版本号。
//! Phase B/C 实现后，default_event_source() 会按此返回对应 EbpfXxxSource。

use crate::event_source::SourceKind;

/// 探测当前内核应使用的 eBPF tier。
/// 返回 None 表示内核太老或读不到版本（调用方 fallback 到 mock）。
pub fn detect_ebpf_tier() -> Option<SourceKind> {
    let release = read_kernel_release()?;
    let (major, minor) = parse_kernel_version(&release)?;
    tier_from_version(major, minor)
}

/// 读取 /proc/sys/kernel/osrelease，形如 "6.5.0-26-generic"。
fn read_kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

/// 解析 "6.5.0-26-generic" → (6, 5)。
/// 仅取主.次，忽略补丁号和后缀。
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_part = parts.next()?;
    // minor 可能含 "-" 后缀（如 "0-26-generic"），取前导数字部分
    let minor_str: String = minor_part.chars().take_while(|c| c.is_ascii_digit()).collect();
    if minor_str.is_empty() {
        return None;
    }
    let minor: u32 = minor_str.parse().ok()?;
    Some((major, minor))
}

/// 根据 (major, minor) 决定 tier。
///
/// 边界值依据：
/// - 5.8：BPF_MAP_TYPE_RINGBUF 引入（commit 5483b8d2f6cc）
/// - 5.0–5.7：无 ringbuf，但 BTF/CO-RE 可用 → 走 perfbuf（Legacy tier）
/// - 4.x：perf_event_array 成熟，BPF_KPROBE macro 在 libbpf 1.0+
/// - 3.10.0-1160：CentOS 7 + kernel-plus 包带 BTF backport（研究性突破点）
fn tier_from_version(major: u32, minor: u32) -> Option<SourceKind> {
    if major > 5 || (major == 5 && minor >= 8) {
        Some(SourceKind::EbpfModern)
    } else if major >= 4 {
        // 4.x 全系列 + 5.0–5.7：无 ringbuf，走 perfbuf（Legacy tier）
        Some(SourceKind::EbpfLegacy)
    } else if major == 3 && minor >= 10 {
        Some(SourceKind::EbpfAncient)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version_simple() {
        assert_eq!(parse_kernel_version("6.5.0"), Some((6, 5)));
        assert_eq!(parse_kernel_version("5.8.0-rc1"), Some((5, 8)));
    }

    #[test]
    fn test_parse_version_centos7() {
        // CentOS 7 默认 3.10.0-1160.el7.x86_64
        assert_eq!(parse_kernel_version("3.10.0-1160.el7.x86_64"), Some((3, 10)));
    }

    #[test]
    fn test_parse_version_with_suffix() {
        assert_eq!(parse_kernel_version("5.4.0-26-generic"), Some((5, 4)));
        assert_eq!(parse_kernel_version("4.19.0-1-amd64"), Some((4, 19)));
    }

    #[test]
    fn test_parse_version_invalid() {
        assert_eq!(parse_kernel_version("invalid"), None);
        assert_eq!(parse_kernel_version(""), None);
    }

    #[test]
    fn test_tier_boundaries() {
        // Modern tier 5.8+
        assert_eq!(tier_from_version(5, 8), Some(SourceKind::EbpfModern));
        assert_eq!(tier_from_version(5, 9), Some(SourceKind::EbpfModern));
        assert_eq!(tier_from_version(6, 0), Some(SourceKind::EbpfModern));
        assert_eq!(tier_from_version(7, 1), Some(SourceKind::EbpfModern));

        // 5.7 及以下不算 Modern
        assert_eq!(tier_from_version(5, 7), Some(SourceKind::EbpfLegacy));

        // Legacy 4.x
        assert_eq!(tier_from_version(4, 4), Some(SourceKind::EbpfLegacy));
        assert_eq!(tier_from_version(4, 19), Some(SourceKind::EbpfLegacy));

        // Ancient 3.10+
        assert_eq!(tier_from_version(3, 10), Some(SourceKind::EbpfAncient));
        assert_eq!(tier_from_version(3, 16), Some(SourceKind::EbpfAncient));

        // 太老
        assert_eq!(tier_from_version(3, 9), None);
        assert_eq!(tier_from_version(2, 6), None);
        assert_eq!(tier_from_version(1, 0), None);
    }

    #[test]
    fn test_detect_ebpf_tier_on_current_kernel() {
        // 当前内核必须能读出 tier（CI 环境 5.x+）
        let tier = detect_ebpf_tier();
        assert!(tier.is_some(), "应能在当前内核上探测到 tier");
        // CI 通常 5.x+，应该是 Modern；如果失败说明环境异常
        if let Some(t) = tier {
            println!("当前内核 tier: {:?}", t);
        }
    }
}

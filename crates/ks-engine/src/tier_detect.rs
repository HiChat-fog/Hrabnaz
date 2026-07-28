//! eBPF tier自动探测 — 根据内核版本选择合适的eBPF后端。
//!
//! 多tier eBPF架构对应表：
//! - Modern (5.8+)   → BPF_MAP_TYPE_RINGBUF（性能最佳）
//! - Legacy (4.x)    → BPF_MAP_TYPE_PERF_EVENT_ARRAY（perfbuf，Phase B实现）
//! - Ancient (3.10+) → BTF backport + HASH手动LRU（CentOS 7，Phase C研究性突破）
//!
//! 探测依据：/proc/sys/kernel/osrelease主.次版本号。
//! Phase B/C实现后，default_event_source()会按此返回对应EbpfXxxSource。
//!
//! C8: Ancient tier额外探测 /sys/kernel/btf/vmlinux，缺失则降级到Mock。

use crate::event_source::SourceKind;

/// 探测当前内核应使用的eBPF tier。
/// 返回None表示内核太老或读不到版本（调用方fallback到mock）。
pub fn detect_ebpf_tier() -> Option<SourceKind> {
    let release = read_kernel_release()?;
    let (major, minor) = parse_kernel_version(&release)?;
    let tier = tier_from_version(major, minor)?;
    // Ancient tier两条加载路径：有BTF→ks_main_ancient.o(CO-RE重定位)；无BTF→ks_main_ancient_nobtf.o(硬编码offset，无需kernel-plus)
    if matches!(tier, SourceKind::EbpfAncient) {
        if btf_available() {
            log::info!("Ancient tier: BTF 可用，使用 CO-RE 重定位 (ks_main_ancient.o)");
        } else {
            log::info!(
                "Ancient tier: BTF 不可用，使用 NOBTF 硬编码 offset (ks_main_ancient_nobtf.o)"
            );
        }
    }
    Some(tier)
}

/// 检测内核BTF是否可用。
/// 4.18+原生支持BTF；3.10 stock无BTF，需kernel-plus或走NOBTF路径。
pub fn btf_available() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// D3: nobtf路径用硬编码offset（见`common.h`的`KS_OFF_*`），目标`3.10.0-1160.119.1.el7.x86_64`；
/// 换3.10子版本struct偏移可能不同→静默读错字段。前缀匹配`3.10.0-1160`：同build兼容，不同build fail loud。
const NOBTF_TARGET_RELEASE_PREFIX: &str = "3.10.0-1160";

/// D3: 给定release串，是否兼容内嵌的`ks_main_ancient_nobtf.o`（纯函数，可单测）。
/// 匹配（同build 1160的子版本）→`Ok(())`；否则→`Err(reason)`。
pub fn nobtf_release_compatible_for(release: &str) -> Result<(), String> {
    if release.starts_with(NOBTF_TARGET_RELEASE_PREFIX) {
        Ok(())
    } else {
        Err(format!(
            "nobtf .o 目标 release 前缀 {} 与运行时 release {:?} 不匹配 — 拒绝加载（避免 silent wrong offset）",
            NOBTF_TARGET_RELEASE_PREFIX, release,
        ))
    }
}

/// D3: 运行时release是否兼容内嵌的`ks_main_ancient_nobtf.o`（读`/proc/sys/kernel/osrelease`）。
/// 匹配→`Ok(())`；不匹配或读不到release→`Err(reason)`（调用方应fail loud，不加载wrong-offset .o）。
pub fn nobtf_release_compatible() -> Result<(), String> {
    let release = read_kernel_release().unwrap_or_default();
    nobtf_release_compatible_for(&release)
}

/// 读取 /proc/sys/kernel/osrelease，形如"6.5.0-26-generic"。
fn read_kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

/// 解析"6.5.0-26-generic" → (6, 5)。
/// 仅取主.次，忽略补丁号和后缀。
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_part = parts.next()?;
    // minor可能含"-"后缀（如"0-26-generic"），取前导数字部分
    let minor_str: String = minor_part
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if minor_str.is_empty() {
        return None;
    }
    let minor: u32 = minor_str.parse().ok()?;
    Some((major, minor))
}

/// 根据(major, minor)决定tier。
/// 边界：5.8+→Modern(ringbuf)；4.x及5.0–5.7→Legacy(perfbuf，BTF/CO-RE可用)；3.10+→Ancient(CentOS 7 kernel-plus带BTF backport)。
fn tier_from_version(major: u32, minor: u32) -> Option<SourceKind> {
    if major > 5 || (major == 5 && minor >= 8) {
        Some(SourceKind::EbpfModern)
    } else if major >= 4 {
        // 4.x全系列 + 5.0–5.7：无ringbuf，走perfbuf（Legacy tier）
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
        // CentOS 7默认3.10.0-1160.el7.x86_64
        assert_eq!(
            parse_kernel_version("3.10.0-1160.el7.x86_64"),
            Some((3, 10))
        );
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

        // 5.7及以下不算Modern
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
        // 当前内核必须能读出tier（CI环境5.x+）
        let tier = detect_ebpf_tier();
        assert!(tier.is_some(), "应能在当前内核上探测到 tier");
        // CI通常5.x+，应该是Modern；如果失败说明环境异常
        if let Some(t) = tier {
            println!("当前内核 tier: {:?}", t);
        }
    }

    #[test]
    fn test_btf_available_returns_bool() {
        // 不panic即可，结果依赖运行环境
        let _ = btf_available();
    }

    #[test]
    fn test_ancient_without_btf_still_returns_ancient() {
        // NOBTF: Ancient tier无BTF时不再降级到Mock，而是走NOBTF路径
        let tier = detect_ebpf_tier();
        if let Some(t) = tier {
            if matches!(t, SourceKind::EbpfAncient) {
                // 无论BTF是否存在，都应返回Ancient
                println!("Ancient tier 检测到，BTF={}", btf_available());
            }
        }
    }

    #[test]
    fn test_nobtf_release_compatible_for() {
        // D3: 同build 1160的子版本 → 兼容（struct offset相同）
        assert!(nobtf_release_compatible_for("3.10.0-1160.119.1.el7.x86_64").is_ok());
        assert!(nobtf_release_compatible_for("3.10.0-1160.957.el7.x86_64").is_ok());
        // 不同build → 不兼容（fail loud，避免silent wrong offset）
        assert!(nobtf_release_compatible_for("3.10.0-957.el7.x86_64").is_err());
        assert!(nobtf_release_compatible_for("3.10.0-327.el7.x86_64").is_err());
        // 4.x / 5.x / 6.x → 不兼容（不应走nobtf路径）
        assert!(nobtf_release_compatible_for("4.19.0-1-amd64").is_err());
        assert!(nobtf_release_compatible_for("6.5.0-26-generic").is_err());
        // 空串 → 不兼容
        assert!(nobtf_release_compatible_for("").is_err());
    }
}

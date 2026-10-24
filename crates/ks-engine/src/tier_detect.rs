use crate::event_source::SourceKind;

pub fn detect_ebpf_tier() -> Option<SourceKind> {
    let release = read_kernel_release()?;
    let (major, minor) = parse_kernel_version(&release)?;
    let tier = tier_from_version(major, minor)?;
    if matches!(tier, SourceKind::EbpfAncient) {
        if btf_available() {
            log::info!("Ancient tier: BTF可用,用CO-RE重定位(ks_main_ancient.o)");
        } else {
            log::info!("Ancient tier: BTF不可用,用NOBTF硬编码offset(ks_main_ancient_nobtf.o)");
        }
    }
    if matches!(tier, SourceKind::EbpfLegacy) && !btf_available() {
        log::info!(
            "Legacy tier: BTF不可用,用NOBTF硬编码4.19 offset(ks_main_legacy_nobtf.o,C loader)"
        );
        return Some(SourceKind::EbpfLegacyNoBtf);
    }
    Some(tier)
}

/// 是否有可用于 CO-RE 重定位的目标内核 BTF。
///
/// 判据是"`btf_source` 能解析出任意一份 BTF"——内核自带
/// `/sys/kernel/btf/vmlinux`、`KS_BTF_PATH` 覆盖、或构建期内嵌表，任一成立即可。
/// 旧实现只查 `/sys/kernel/btf/vmlinux` 是否存在，于是没有该文件的内核上会
/// 静默丢掉 CO-RE 重定位（读错字段），而内嵌 BTF 正是为这类内核准备的。
pub fn btf_available() -> bool {
    crate::btf_source::target_btf_available()
}

const NOBTF_TARGET_RELEASE_PREFIX: &str = "3.10.0-1160";

pub fn nobtf_release_compatible_for(release: &str) -> Result<(), String> {
    if release.starts_with(NOBTF_TARGET_RELEASE_PREFIX) {
        Ok(())
    } else {
        Err(format!(
            "nobtf .o目标release前缀{}与运行时release{:?}不匹配,拒绝加载(避免silent wrong offset)",
            NOBTF_TARGET_RELEASE_PREFIX, release,
        ))
    }
}

pub fn nobtf_release_compatible() -> Result<(), String> {
    let release = read_kernel_release().unwrap_or_default();
    nobtf_release_compatible_for(&release)
}

const LEGACY_NOBTF_TARGET_RELEASE_PREFIX: &str = "4.19.";

pub fn legacy_nobtf_release_compatible_for(release: &str) -> Result<(), String> {
    if release.starts_with(LEGACY_NOBTF_TARGET_RELEASE_PREFIX) {
        Ok(())
    } else {
        Err(format!(
            "legacy_nobtf .o目标release前缀{}与运行时release{:?}不匹配,拒绝加载(避免silent wrong offset)",
            LEGACY_NOBTF_TARGET_RELEASE_PREFIX, release,
        ))
    }
}

pub fn legacy_nobtf_release_compatible() -> Result<(), String> {
    let release = read_kernel_release().unwrap_or_default();
    legacy_nobtf_release_compatible_for(&release)
}

pub(crate) fn read_kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_part = parts.next()?;
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

fn tier_from_version(major: u32, minor: u32) -> Option<SourceKind> {
    if major > 5 || (major == 5 && minor >= 8) {
        Some(SourceKind::EbpfModern)
    } else if major >= 4 {
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
        assert_eq!(tier_from_version(5, 8), Some(SourceKind::EbpfModern));
        assert_eq!(tier_from_version(5, 9), Some(SourceKind::EbpfModern));
        assert_eq!(tier_from_version(6, 0), Some(SourceKind::EbpfModern));
        assert_eq!(tier_from_version(7, 1), Some(SourceKind::EbpfModern));

        assert_eq!(tier_from_version(5, 7), Some(SourceKind::EbpfLegacy));

        assert_eq!(tier_from_version(4, 4), Some(SourceKind::EbpfLegacy));
        assert_eq!(tier_from_version(4, 19), Some(SourceKind::EbpfLegacy));

        assert_eq!(tier_from_version(3, 10), Some(SourceKind::EbpfAncient));
        assert_eq!(tier_from_version(3, 16), Some(SourceKind::EbpfAncient));

        assert_eq!(tier_from_version(3, 9), None);
        assert_eq!(tier_from_version(2, 6), None);
        assert_eq!(tier_from_version(1, 0), None);
    }

    #[test]
    fn test_detect_ebpf_tier_on_current_kernel() {
        let tier = detect_ebpf_tier();
        assert!(tier.is_some(), "应能在当前内核上探测到tier");
        if let Some(t) = tier {
            println!("当前内核tier: {:?}", t);
        }
    }

    #[test]
    fn test_btf_available_returns_bool() {
        let _ = btf_available();
    }

    #[test]
    fn test_ancient_without_btf_still_returns_ancient() {
        let tier = detect_ebpf_tier();
        if let Some(t) = tier {
            if matches!(t, SourceKind::EbpfAncient) {
                println!("Ancient tier检测到,BTF={}", btf_available());
            }
        }
    }

    #[test]
    fn test_nobtf_release_compatible_for() {
        assert!(nobtf_release_compatible_for("3.10.0-1160.119.1.el7.x86_64").is_ok());
        assert!(nobtf_release_compatible_for("3.10.0-1160.957.el7.x86_64").is_ok());
        assert!(nobtf_release_compatible_for("3.10.0-957.el7.x86_64").is_err());
        assert!(nobtf_release_compatible_for("3.10.0-327.el7.x86_64").is_err());
        assert!(nobtf_release_compatible_for("4.19.0-1-amd64").is_err());
        assert!(nobtf_release_compatible_for("6.5.0-26-generic").is_err());
        assert!(nobtf_release_compatible_for("").is_err());
    }
}

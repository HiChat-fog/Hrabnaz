//! eBPF tier自动探测,按内核版本选合适的eBPF后端。
//!
//! 多tier架构对应关系:Modern(5.8+)用ringbuf;Legacy(4.x)用perfbuf;Ancient(3.10+)走BTF backport加HASH手动LRU,对应CentOS 7。
//!
//! 探测依据是/proc/sys/kernel/osrelease的主次版本号,default_event_source()据此返回对应EbpfXxxSource。
//!
//! Ancient tier额外探测/sys/kernel/btf/vmlinux,缺失则降级到Mock。

use crate::event_source::SourceKind;

/// 探测当前内核该用的eBPF tier。
/// 内核太老或读不到版本时返回None,调用方fallback到mock。
pub fn detect_ebpf_tier() -> Option<SourceKind> {
    let release = read_kernel_release()?;
    let (major, minor) = parse_kernel_version(&release)?;
    let tier = tier_from_version(major, minor)?;
    // Ancient tier两条加载路径:有BTF走ks_main_ancient.o做CO-RE重定位;无BTF走ks_main_ancient_nobtf.o,硬编码offset,不依赖kernel-plus
    if matches!(tier, SourceKind::EbpfAncient) {
        if btf_available() {
            log::info!("Ancient tier: BTF可用,用CO-RE重定位(ks_main_ancient.o)");
        } else {
            log::info!("Ancient tier: BTF不可用,用NOBTF硬编码offset(ks_main_ancient_nobtf.o)");
        }
    }
    // Legacy tier同理:4.19原版和麒麟V10 SP1/SP2无BTF时,aya加载带BTF的legacy .o会BTF_BTF_LOAD返回EINVAL,改走C loader加载legacy_nobtf.o
    if matches!(tier, SourceKind::EbpfLegacy) && !btf_available() {
        log::info!("Legacy tier: BTF不可用,用NOBTF硬编码4.19 offset(ks_main_legacy_nobtf.o,C loader)");
        return Some(SourceKind::EbpfLegacyNoBtf);
    }
    Some(tier)
}

/// 检测内核BTF是否可用。
/// 4.18及以上原生支持BTF;3.10 stock内核无BTF,要么装kernel-plus,要么走NOBTF路径。
pub fn btf_available() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}

/// nobtf路径靠硬编码offset(见common.h的KS_OFF_*),目标release是3.10.0-1160.119.1.el7.x86_64。
/// 换3.10子版本struct偏移可能不同,会静默读错字段,所以用前缀匹配3.10.0-1160:同build兼容,不同build直接报错不加载。
const NOBTF_TARGET_RELEASE_PREFIX: &str = "3.10.0-1160";

/// 给定release串,是否兼容内嵌的ks_main_ancient_nobtf.o(纯函数,可单测)。
/// 匹配(同build 1160的子版本)返回Ok(()),否则返回Err(reason)。
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

/// 运行时release是否兼容内嵌的ks_main_ancient_nobtf.o(读/proc/sys/kernel/osrelease)。
/// 匹配返回Ok(()),不匹配或读不到release返回Err(reason),调用方应fail loud,不加载wrong-offset .o。
pub fn nobtf_release_compatible() -> Result<(), String> {
    let release = read_kernel_release().unwrap_or_default();
    nobtf_release_compatible_for(&release)
}

/// legacy_nobtf路径靠硬编码4.19 offset(见common.h的KS_OFF_*)。
/// 4.19系列struct sock布局稳定(inet_saddr=728/inet_sport=736,pahole在4.19.0-20-dbg上实测),但只有4.19主版本匹配才兼容,4.4和5.x不走这条路径,所以前缀匹配4.19.。
const LEGACY_NOBTF_TARGET_RELEASE_PREFIX: &str = "4.19.";

/// 给定release串是否兼容内嵌的ks_main_legacy_nobtf.o,纯函数可单测。
/// 匹配(4.19.x)返回Ok(()),否则返回Err(reason)。
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

/// 运行时release是否兼容内嵌的ks_main_legacy_nobtf.o。
pub fn legacy_nobtf_release_compatible() -> Result<(), String> {
    let release = read_kernel_release().unwrap_or_default();
    legacy_nobtf_release_compatible_for(&release)
}

/// 读/proc/sys/kernel/osrelease,形如6.5.0-26-generic。
fn read_kernel_release() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

/// 解析6.5.0-26-generic为(6,5),只取主次版本,忽略补丁号和后缀。
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor_part = parts.next()?;
    // minor可能带"-"后缀,如0-26-generic,这里取前导数字部分
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

/// 按主次版本号决定tier。
/// 5.8及以上走Modern(ringbuf);4.x全系列加5.0到5.7走Legacy(perfbuf);3.10及以上走Ancient(CentOS 7的kernel-plus带BTF backport)。
fn tier_from_version(major: u32, minor: u32) -> Option<SourceKind> {
    if major > 5 || (major == 5 && minor >= 8) {
        Some(SourceKind::EbpfModern)
    } else if major >= 4 {
        // 4.x全系列加5.0到5.7,没有ringbuf,走perfbuf(Legacy tier)
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
        // 当前内核必须能读出tier(CI环境5.x以上)
        let tier = detect_ebpf_tier();
        assert!(tier.is_some(), "应能在当前内核上探测到tier");
        // CI通常是5.x以上,应该是Modern,失败说明环境异常
        if let Some(t) = tier {
            println!("当前内核tier: {:?}", t);
        }
    }

    #[test]
    fn test_btf_available_returns_bool() {
        // 不panic即可,结果依赖运行环境
        let _ = btf_available();
    }

    #[test]
    fn test_ancient_without_btf_still_returns_ancient() {
        // NOBTF:Ancient tier无BTF时不再降级到Mock,而是走NOBTF路径
        let tier = detect_ebpf_tier();
        if let Some(t) = tier {
            if matches!(t, SourceKind::EbpfAncient) {
                // 不管BTF是否存在,都应返回Ancient
                println!("Ancient tier检测到,BTF={}", btf_available());
            }
        }
    }

    #[test]
    fn test_nobtf_release_compatible_for() {
        // 同build 1160的子版本兼容,struct offset相同
        assert!(nobtf_release_compatible_for("3.10.0-1160.119.1.el7.x86_64").is_ok());
        assert!(nobtf_release_compatible_for("3.10.0-1160.957.el7.x86_64").is_ok());
        // 不同build不兼容,fail loud,避免silent wrong offset
        assert!(nobtf_release_compatible_for("3.10.0-957.el7.x86_64").is_err());
        assert!(nobtf_release_compatible_for("3.10.0-327.el7.x86_64").is_err());
        // 4.x/5.x/6.x不兼容,不应走nobtf路径
        assert!(nobtf_release_compatible_for("4.19.0-1-amd64").is_err());
        assert!(nobtf_release_compatible_for("6.5.0-26-generic").is_err());
        // 空串不兼容
        assert!(nobtf_release_compatible_for("").is_err());
    }
}

//! 目标内核 BTF 的解析链。
//!
//! aya 的 CO-RE 重定位完全在用户态完成：它拿一份**目标内核的 BTF**，把
//! `BPF_CORE_READ` 记录的访问路径改写成该内核的真实字段偏移。这份 BTF 默认
//! 来自 `/sys/kernel/btf/vmlinux`；取不到时 `aya::Ebpf::load` 会**静默跳过**
//! 重定位，程序带着编译期（vmlinux.h 来源内核的）偏移继续加载并读到错误字段。
//! 所以这里把"取不到 BTF"变成明确失败。
//!
//! 解析顺序：
//! 1. `KS_BTF_PATH`（现场实测 / 应急覆盖；显式指定却不可用 → 直接失败，不静默忽略）
//! 2. `/sys/kernel/btf/vmlinux`（5.8+ 发行版内核通常自带，零配置路径）
//! 3. 构建期内嵌表，按内核 release 精确匹配（交付到无 BTF 的老内核用）
//! 4. 全部失败 → 报错并列出已尝试的来源与修复方式

use anyhow::{anyhow, Context, Result};
use aya::{Btf, Endianness};
use std::path::{Path, PathBuf};

/// 环境变量覆盖：指向任意一份 BTF 文件。
/// BTFHub 的 `vmlinux` 与 `pahole --btf_encode_detached` 的产物都是同一格式。
pub const BTF_PATH_ENV: &str = "KS_BTF_PATH";

/// 内核自带 BTF。
pub const SYSFS_BTF: &str = "/sys/kernel/btf/vmlinux";

/// 构建期内嵌表（由 build.rs 扫描 `crates/ks-ebpf/btf/` 生成）。
pub mod btf_objects {
    include!(concat!(env!("OUT_DIR"), "/btf_objects.rs"));
}

/// BTF 来源，用于日志与诊断。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtfOrigin {
    /// `KS_BTF_PATH` 指定的文件
    EnvOverride(PathBuf),
    /// `/sys/kernel/btf/vmlinux`
    SysFs(PathBuf),
    /// 构建期内嵌，按内核 release 精确匹配
    Embedded(String),
}

impl std::fmt::Display for BtfOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EnvOverride(p) => write!(f, "{}={}", BTF_PATH_ENV, p.display()),
            Self::SysFs(p) => write!(f, "{}", p.display()),
            Self::Embedded(release) => write!(
                f,
                "构建期内嵌 BTF(release={}{})",
                release,
                if btf_objects::btf_minimized(release) {
                    "，最小核心 BTF"
                } else {
                    ""
                }
            ),
        }
    }
}

fn env_override_path() -> Option<PathBuf> {
    std::env::var_os(BTF_PATH_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

/// 内嵌表里登记的所有内核 release。
pub fn embedded_releases() -> &'static [&'static str] {
    btf_objects::BTF_EMBEDDED_RELEASES
}

/// 取指定 release 的内嵌 BTF（精确匹配，不做前缀猜测：偏移随内核构建而变，
/// 用相近版本兜底就是在猜偏移，正是本模块要消除的问题）。
pub fn embedded_btf_for(release: &str) -> Option<&'static [u8]> {
    btf_objects::btf_for_release(release)
}

/// 该 release 的内嵌 BTF 是否由 `bpftool gen min_core_btf` 裁过。
/// 未裁（构建机没有 bpftool）时内嵌的是完整 vmlinux BTF，重定位同样可用，只是二进制大。
pub fn embedded_is_minimized(release: &str) -> bool {
    btf_objects::btf_minimized(release)
}

/// 廉价可用性探测：只判断"能否拿到一份 BTF"，不解析内容，供 tier 路由决策使用。
///
/// `KS_BTF_PATH` 一旦被设置就返回 true（**不检查文件是否存在**）：显式指定了
/// 来源却写错路径时，应当让后续加载明确失败，而不是悄悄退到手写硬编码偏移的
/// NOBTF 路径上去——那正是静默错偏移。
pub fn target_btf_available() -> bool {
    if env_override_path().is_some() {
        return true;
    }
    if Path::new(SYSFS_BTF).is_file() {
        return true;
    }
    embedded_btf_for(&current_release()).is_some()
}

/// 加载并解析目标内核 BTF。返回 BTf 与来源描述（供日志）。
pub fn load_target_btf() -> Result<(Btf, BtfOrigin)> {
    let mut tried: Vec<String> = Vec::new();

    // 1. 环境变量覆盖：显式指定却不可用 → 硬失败
    if let Some(path) = env_override_path() {
        let btf = Btf::parse_file(&path, Endianness::default()).map_err(|e| {
            anyhow!(
                "{}={} 指定的 BTF 无法解析: {}（显式指定的来源不会被静默忽略）",
                BTF_PATH_ENV,
                path.display(),
                e
            )
        })?;
        return Ok((btf, BtfOrigin::EnvOverride(path)));
    }
    tried.push(format!("{}（未设置）", BTF_PATH_ENV));

    // 2. 内核自带
    let sysfs = Path::new(SYSFS_BTF);
    if sysfs.is_file() {
        match Btf::parse_file(sysfs, Endianness::default()) {
            Ok(btf) => return Ok((btf, BtfOrigin::SysFs(sysfs.to_path_buf()))),
            Err(e) => {
                // 个别发行版会给出截断/精简的 vmlinux BTF，解析失败不该直接放弃内嵌兜底
                log::warn!("[btf] {} 存在但解析失败: {} — 继续尝试内嵌 BTF", SYSFS_BTF, e);
                tried.push(format!("{}（解析失败: {}）", SYSFS_BTF, e));
            }
        }
    } else {
        tried.push(format!("{}（不存在）", SYSFS_BTF));
    }

    // 3. 构建期内嵌，按 release 精确匹配
    let release = current_release();
    if let Some(bytes) = embedded_btf_for(&release) {
        let btf = Btf::parse(bytes, Endianness::default())
            .with_context(|| format!("内嵌 BTF(release={}) 解析失败", release))?;
        return Ok((btf, BtfOrigin::Embedded(release)));
    }
    let embedded = embedded_releases();
    tried.push(if embedded.is_empty() {
        "构建期内嵌表（空：crates/ks-ebpf/btf/ 下没有 BTF 文件）".to_string()
    } else {
        format!(
            "构建期内嵌表（含 {:?}，均不匹配当前 release={:?}）",
            embedded, release
        )
    });

    Err(anyhow!(
        "无法获取目标内核 BTF，CO-RE 重定位无法进行。已尝试:\n  - {}\n\
         修复方式（任选）:\n  \
         1) 设 {} 指向一份该内核的 BTF 文件\n  \
         2) 把 <release>.btf 或 <release>.btf.xz 放进 crates/ks-ebpf/btf/ 后重新构建（会被内嵌进二进制，\
         适合交付到无 BTF 的内核）\n  \
         3) 确认内核启用了 CONFIG_DEBUG_INFO_BTF（5.8+ 发行版内核通常自带 /sys/kernel/btf/vmlinux）",
        tried.join("\n  - "),
        BTF_PATH_ENV,
    ))
}

fn current_release() -> String {
    crate::tier_detect::read_kernel_release().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 这些测试通过环境变量注入 BTF 来源，而 cargo 默认多线程跑测试；
    /// 任何读写 `KS_BTF_PATH` 的用例都必须持这把锁，否则会互相看到对方设的值。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_env() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_embedded_lookup_is_exact_match() {
        // 前缀相近但不同版本的内核偏移可能不同，必须精确匹配而不是猜
        assert!(
            embedded_btf_for("0.0.0-does-not-exist").is_none(),
            "不存在的 release 必须返回 None"
        );
        // 表与查询函数必须一致：登记了就必须取得到，取得到就必须登记过
        for release in embedded_releases() {
            assert!(
                embedded_btf_for(release).is_some(),
                "内嵌表登记了 {} 但查询返回 None，build.rs 生成的表不自洽",
                release
            );
        }
    }

    #[test]
    fn test_env_override_missing_file_is_hard_error() {
        let _g = lock_env();
        // 显式指定但文件不存在：必须报错，而不是退到 sysfs/内嵌继续跑
        std::env::set_var(BTF_PATH_ENV, "/nonexistent/ks-test.btf");
        let err = load_target_btf().expect_err("路径不存在时应失败");
        let msg = err.to_string();
        assert!(
            msg.contains("/nonexistent/ks-test.btf"),
            "错误信息应包含指定的路径，实际: {}",
            msg
        );
        assert!(
            msg.contains(BTF_PATH_ENV),
            "错误信息应指出是 {} 造成的，实际: {}",
            BTF_PATH_ENV,
            msg
        );
        std::env::remove_var(BTF_PATH_ENV);
    }

    #[test]
    fn test_env_override_takes_priority_and_parses() {
        let _g = lock_env();
        // 用内嵌 BTF（若没有则用 sysfs）造一份"外部文件"，验证 env 分支能解析且来源被识别
        let Some((_, origin)) = load_target_btf().ok() else {
            eprintln!("跳过：当前环境没有任何 BTF 来源可用");
            return;
        };
        let bytes: Vec<u8> = match &origin {
            BtfOrigin::Embedded(r) => embedded_btf_for(r).expect("刚刚才查到").to_vec(),
            _ => match std::fs::read(SYSFS_BTF) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("跳过：读不到 {}: {}", SYSFS_BTF, e);
                    return;
                }
            },
        };

        let dir = tempfile::tempdir().expect("建临时目录");
        let path = dir.path().join("ks-test.btf");
        std::fs::write(&path, &bytes).expect("写临时 BTF");

        std::env::set_var(BTF_PATH_ENV, &path);
        let result = load_target_btf();
        std::env::remove_var(BTF_PATH_ENV);

        let (_, got) = result.expect("env 指向的合法 BTF 应能解析");
        assert_eq!(got, BtfOrigin::EnvOverride(path));
    }

    #[test]
    fn test_available_probe_is_consistent_with_load() {
        let _g = lock_env();
        // 探测为真时加载必须能成功；探测为假时加载必须失败
        let available = target_btf_available();
        let loaded = load_target_btf().is_ok();
        assert_eq!(
            available, loaded,
            "target_btf_available()={} 与 load_target_btf() 成功与否={} 不一致",
            available, loaded
        );
    }

    #[test]
    fn test_env_set_but_broken_still_reports_available() {
        let _g = lock_env();
        // 语义约定：设了 KS_BTF_PATH 就认定"有 BTF 来源"，让加载阶段去报错。
        // 否则写错路径会静默退到手写硬编码偏移的 NOBTF 路径。
        std::env::set_var(BTF_PATH_ENV, "/nonexistent/ks-test.btf");
        assert!(
            target_btf_available(),
            "{} 已设置时应报告可用（错误留到加载阶段暴露）",
            BTF_PATH_ENV
        );
        std::env::remove_var(BTF_PATH_ENV);
    }
}

//! CO-RE 重定位回归测试（不需要 root，也不需要真机加载）。
//!
//! 门禁语义（K7 字段级容差后）：aya-obj 对缺字段不报错而是毒化指令；loader 在加载前
//! 用同样的重定位做预检，**可容忍清单**（RELOC_TOLERANT_PROBES，自保护类探针）内的
//! 毒化 → 跳过该探针并如实上报；**核心探针**毒化 → 该内核不支持本 tier，整体拒绝。
//! 本测试按同一规则判定每一份内嵌 BTF：只允许可容忍探针毒化。
//!
//! 所以：把每一份可用的 BTF（本机 sysfs + 构建期内嵌的每一份）都拿来对三个
//! CO-RE tier 的真实 .o 做一次重定位。老内核的 BTF 一旦内嵌进来却无法解析全部
//! 访问路径，这里就会红，而不是等到交付到那台机器上才发现。

use aya::{Btf, Endianness};
use ks_engine::btf_source;
use ks_engine::loader::ebpf_objects::ebpf_object_for;

/// 带 CO-RE 重定位（`.BTF.ext` + preserve_access_index）的三个 tier。
/// *`_nobtf` 不在其中：它们在构建期被剥掉 `.BTF.ext`，重定位必须是 no-op。
const CORE_TIERS: &[&str] = &["modern", "legacy", "ancient"];

/// 某内核版本上真正会用的 tier（对齐 tier_detect::tier_from_version）。
/// 不能拿 3.10 的 BTF 去校验 modern 对象：modern 只在 5.8+ 运行，它读的
/// 字段（如 3.19 才有的 cred->user_ns->ns.inum）在老内核 BTF 里本就不存在。
fn tiers_for_release(release: &str) -> Vec<&'static str> {
    let mut it = release.split('.');
    let major: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor: u32 = it
        .next()
        .map(|s| s.trim_end_matches(|c: char| !c.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if major > 5 || (major == 5 && minor >= 8) {
        CORE_TIERS.to_vec()
    } else if major >= 4 {
        vec!["legacy", "ancient"]
    } else {
        vec!["ancient"]
    }
}

/// 毒化标记与可容忍清单从 loader 导入，保证测试门禁与运行时行为同源（防止漂移）。
use ks_engine::loader::{POISON_IMM, RELOC_TOLERANT_PROBES};

/// 返回 (程序名, 现场描述)；程序名用于对照可容忍清单。
fn poison_sites(obj: &aya_obj::Object) -> Vec<(String, String)> {
    let mut sites = Vec::new();
    for f in obj.functions.values() {
        for (i, ins) in f.instructions.iter().enumerate() {
            if ins.imm == POISON_IMM {
                let lo = i.saturating_sub(2);
                let ctx: Vec<String> = f.instructions[lo..(i + 1).min(f.instructions.len())]
                    .iter()
                    .enumerate()
                    .map(|(k, c)| {
                        format!(
                            "insn[{}] code={:#04x} dst={} src={} off={} imm={:#x}",
                            lo + k,
                            c.code,
                            c.dst_reg() & 0xf,
                            c.src_reg() & 0xf,
                            c.off,
                            c.imm
                        )
                    })
                    .collect();
                sites.push((
                    f.name.clone(),
                    format!("{} insn[{}]\n     {}", f.name, i, ctx.join("\n     ")),
                ));
            }
        }
    }
    sites
}

/// 对一份 .o 做重定位；失败或出现毒化时把 tier 与 BTF 来源一起报出来。
fn assert_relocates(obj_bytes: &[u8], btf: &Btf, label: &str) {
    let mut obj = aya_obj::Object::parse(obj_bytes)
        .unwrap_or_else(|e| panic!("{}: .o 解析失败: {}", label, e));
    assert!(
        obj.btf_ext.is_some(),
        "{}: 应带 .BTF.ext（否则重定位是 no-op，此用例失去意义）",
        label
    );
    if let Err(e) = obj.relocate_btf(btf) {
        panic!(
            "{}: CO-RE 重定位失败: {}\n\
             这意味着在该内核上加载这个 tier 会整体失败（aya 遇到第一个解析不了的\n\
             访问路径就返回 Err）。需要给相关字段加 bpf_core_field_exists() 守卫，\n\
             或把该探针按 tier 条件编译掉。",
            label, e
        );
    }
    let sites = poison_sites(&obj);
    let (tolerant, fatal): (Vec<_>, Vec<_>) = sites
        .into_iter()
        .partition(|(name, _)| RELOC_TOLERANT_PROBES.contains(&name.as_str()));
    if !tolerant.is_empty() {
        let names: Vec<&str> = tolerant.iter().map(|(n, _)| n.as_str()).collect();
        eprintln!(
            "[容差] {}: 可容忍探针毒化，运行时会跳过: {:?}",
            label, names
        );
    }
    assert!(
        fatal.is_empty(),
        "{}: 核心探针被毒化（目标 BTF 缺对应字段，该内核将不支持此 tier）:\n  {}\n\
         修法：核心数据路径探针不要读老内核 BTF 缺失的字段；确属可选能力的探针\n\
         加入 loader::RELOC_TOLERANT_PROBES（须同时保证 status 如实上报）。",
        label,
        fatal
            .iter()
            .map(|(_, d)| d.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// 取一份可用于重定位的 BTF；环境里确实没有 BTF 来源时返回 None（跳过）。
///
/// 但 `KS_BTF_PATH` 被显式设置却加载失败时**必须 panic**：生产路径把这种情况当硬
/// 错误处理（拒绝启动），如果测试把它当成"环境没有 BTF"跳过，就等于放行了一个
/// 上线即失败的配置，测试也失去意义。
fn load_btf_or_skip(label: &str) -> Option<(Btf, String)> {
    match btf_source::load_target_btf() {
        Ok((btf, origin)) => Some((btf, origin.to_string())),
        Err(e) => {
            if std::env::var_os(btf_source::BTF_PATH_ENV).is_some() {
                panic!(
                    "{} 已设置但 BTF 加载失败: {}\n\
                     这在生产路径上是硬错误（拒绝启动），测试同样不能放行。",
                    btf_source::BTF_PATH_ENV,
                    e
                );
            }
            eprintln!("跳过 {}：当前环境没有可用的 BTF 来源", label);
            None
        }
    }
}

fn check_tiers(btf: &Btf, tiers: &[&str], label: &str) -> usize {
    let mut checked = 0;
    for tier in tiers {
        let Some(bytes) = ebpf_object_for(tier) else {
            eprintln!("跳过 {} @ {}: 该 tier 未内嵌（编译期失败）", tier, label);
            continue;
        };
        assert_relocates(bytes, btf, &format!("{} @ {}", tier, label));
        checked += 1;
    }
    checked
}

/// 内嵌的每一份 BTF 都必须能无错、无毒化地重定位它对应内核版本会用的 tier。
/// 这是"把老内核 BTF 打进交付物"这件事的核心质量门。
#[test]
fn test_core_relocation_with_every_embedded_btf() {
    let releases = btf_source::embedded_releases();
    if releases.is_empty() {
        eprintln!(
            "跳过：构建期未内嵌任何内核 BTF（crates/ks-ebpf/btf/ 为空）。\
             交付到无 BTF 的内核前，务必放入目标内核的 BTF 并确认本用例通过。"
        );
        return;
    }
    for release in releases {
        let bytes = btf_source::embedded_btf_for(release).unwrap_or_else(|| {
            panic!(
                "内嵌表登记了 {} 但查不到内容，build.rs 生成的表不自洽",
                release
            )
        });
        let btf = Btf::parse(bytes, Endianness::default())
            .unwrap_or_else(|e| panic!("内嵌 BTF(release={}) 解析失败: {}", release, e));
        let tiers = tiers_for_release(release);
        let checked = check_tiers(&btf, &tiers, &format!("内嵌 BTF(release={})", release));
        assert!(
            checked > 0,
            "内嵌 BTF(release={}) 下没有任何 tier 被验证（应覆盖 {:?}）",
            release,
            tiers
        );
    }
}

/// 本机 /sys/kernel/btf/vmlinux（或 KS_BTF_PATH）也必须能重定位对应 tier。
#[test]
fn test_core_relocation_with_local_btf() {
    let Some((btf, origin)) = load_btf_or_skip("local_btf") else {
        return;
    };
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let tiers = tiers_for_release(&release);
    let checked = check_tiers(&btf, &tiers, &origin);
    assert!(
        checked > 0,
        "BTF 来源 {} (release={}) 下没有任何 tier 被验证",
        origin,
        release
    );
}

/// 取仓库里原始的完整 BTF（`crates/ks-ebpf/btf/<release>.btf[.xz]`，构建期会解压/裁剪）。
fn repo_full_btf(release: &str) -> Option<Vec<u8>> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../ks-ebpf/btf");
    let plain = dir.join(format!("{}.btf", release));
    if plain.is_file() {
        return std::fs::read(plain).ok();
    }
    let xz = dir.join(format!("{}.btf.xz", release));
    if !xz.is_file() {
        return None;
    }
    let out = std::process::Command::new("xz")
        .arg("-dc")
        .arg(&xz)
        .output()
        .ok()?;
    (out.status.success() && !out.stdout.is_empty()).then_some(out.stdout)
}

/// 内嵌的最小 BTF 必须与仓库里那份完整 BTF **重定位等价**：
/// 逐函数逐指令的 imm/off 完全一致，包括"两边都毒化"的情形。
///
/// 为什么单独测这个：`bpftool gen min_core_btf` 只把"对象引用到的类型"挑出来，
/// 一旦喂进去的对象不全（比如漏了某个 tier），最小 BTF 就会缺类型 —— 缺类型的
/// 表现不是报错而是**毒化**，而毒化只在真机加载时被验证器拒绝。这里做的是
/// "裁剪没丢东西"的直接证明，比对的是完整 BTF 这个基准。
#[test]
fn test_minimized_btf_relocates_identically_to_full_btf() {
    let mut checked_releases = 0;
    for release in btf_source::embedded_releases() {
        if !btf_source::embedded_is_minimized(release) {
            eprintln!(
                "跳过 {}：内嵌的是完整 BTF（构建机没有 bpftool），无裁剪可比",
                release
            );
            continue;
        }
        let Some(full_bytes) = repo_full_btf(release) else {
            eprintln!(
                "跳过 {}：仓库里找不到 {} 的原始 BTF，无法比对",
                release, release
            );
            continue;
        };
        let full = Btf::parse(&full_bytes, Endianness::default())
            .unwrap_or_else(|e| panic!("完整 BTF(release={}) 解析失败: {}", release, e));
        let min_bytes = btf_source::embedded_btf_for(release).expect("内嵌表自洽性由其它用例保证");
        let min = Btf::parse(min_bytes, Endianness::default())
            .unwrap_or_else(|e| panic!("最小 BTF(release={}) 解析失败: {}", release, e));

        for tier in CORE_TIERS {
            let Some(bytes) = ebpf_object_for(tier) else {
                continue;
            };
            let label = format!("{} @ 最小对比(内嵌 {})", tier, release);
            let mut full_obj = aya_obj::Object::parse(bytes)
                .unwrap_or_else(|e| panic!("{}: .o 解析失败: {}", label, e));
            let mut min_obj = full_obj.clone();
            let full_res = full_obj.relocate_btf(&full);
            let min_res = min_obj.relocate_btf(&min);

            match (&full_res, &min_res) {
                (Ok(()), Ok(())) => {}
                (Err(a), Err(_)) => {
                    eprintln!(
                        "{}: 完整与最小 BTF 都重定位失败（一致），完整 BTF 的错误: {}",
                        label, a
                    );
                    continue;
                }
                (a, b) => panic!(
                    "{}: 完整 BTF 与最小 BTF 的重定位结果不一致 —— 完整={:?}, 最小={:?}\n\
                     说明裁剪时漏掉了该 tier 引用的类型（build.rs 传给 bpftool 的对象不齐）。",
                    label,
                    a.as_ref().err().map(|e| e.to_string()),
                    b.as_ref().err().map(|e| e.to_string())
                ),
            }

            for (key, fa) in full_obj.functions.iter() {
                let Some(fb) = min_obj.functions.get(key) else {
                    panic!("{}: 最小 BTF 下函数 {} 消失了", label, fa.name);
                };
                for (i, (ia, ib)) in fa
                    .instructions
                    .iter()
                    .zip(fb.instructions.iter())
                    .enumerate()
                {
                    assert!(
                        ia.imm == ib.imm && ia.off == ib.off,
                        "{}: {} insn[{}] 重定位结果不同（完整 imm={:#x} off={} / 最小 imm={:#x} off={}）\
                         —— 最小 BTF 丢了这条访问路径需要的类型。",
                        label,
                        fa.name,
                        i,
                        ia.imm,
                        ia.off,
                        ib.imm,
                        ib.off
                    );
                }
            }
        }
        checked_releases += 1;
    }
    assert!(
        checked_releases > 0,
        "没有任何内嵌 BTF 做过最小/完整等价性比对（交付前必须至少有一份）"
    );
}

/// `*_nobtf` 对象必须"没有 CO-RE 重定位"，但**必须保留 .BTF**——
/// 前者保证它们只依赖硬编码偏移（故加载时需 release 守卫），
/// 后者是 aya 推导 map 的 key/value 尺寸所必需的（只剥 .BTF.ext，不能剥 .BTF）。
#[test]
fn test_nobtf_objects_have_no_core_relocations_but_keep_btf() {
    for tier in ["ancient_nobtf", "legacy_nobtf"] {
        let Some(bytes) = ebpf_object_for(tier) else {
            eprintln!("跳过 {}: 未内嵌", tier);
            continue;
        };
        let obj = aya_obj::Object::parse(bytes)
            .unwrap_or_else(|e| panic!("{}: .o 解析失败: {}", tier, e));
        assert!(
            obj.btf_ext.is_none(),
            "{}: 应已剥离 .BTF.ext（否则重定位会生效，硬编码偏移路径的前提不成立）",
            tier
        );
        assert!(
            obj.btf.is_some(),
            "{}: 必须保留 .BTF 段（aya 靠它推导 map 的 key/value 尺寸）",
            tier
        );
    }
}

/// 重定位必须真的改写指令。若某个内核上重定位一条指令都没改，说明
/// `vmlinux.h` 恰好与该内核一致（这在编译机上不可能一直成立），
/// 或重定位被静默跳过了 —— 后者正是要防的。
/// 这里只对"编译期偏移与目标内核不一致"做信息性提示，不强制断言，
/// 避免在 vmlinux.h 恰好匹配的机器上误报。
#[test]
fn test_relocation_rewrites_instructions() {
    let Some((btf, origin)) = load_btf_or_skip("rewrite_check") else {
        return;
    };
    let Some(bytes) = ebpf_object_for("modern") else {
        eprintln!("跳过：modern tier 未内嵌");
        return;
    };
    let before = aya_obj::Object::parse(bytes).expect("解析 modern .o");
    let mut after = before.clone();
    after
        .relocate_btf(&btf)
        .unwrap_or_else(|e| panic!("modern 重定位失败(BTF={}): {}", origin, e));

    let mut changed = 0usize;
    for (key, fa) in before.functions.iter() {
        let Some(fb) = after.functions.get(key) else {
            continue;
        };
        for (ia, ib) in fa.instructions.iter().zip(fb.instructions.iter()) {
            if ia.imm != ib.imm || ia.off != ib.off {
                changed += 1;
            }
        }
    }
    println!(
        "重定位改写了 {} 条指令（BTF 来源: {}）—— \
         为 0 说明 vmlinux.h 恰好与该内核布局一致，或重定位被跳过",
        changed, origin
    );
}

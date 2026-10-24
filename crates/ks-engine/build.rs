use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

// 与库内单元测试共用同一解析器（CI 断言：嵌入 .o 的 SEC 段 == 生成的注册表）
#[path = "src/probe_registry.rs"]
mod probe_registry;

/// 递归登记重跑条件：新增探针头文件无需再改这里（H-5 的"漏改 rerun 就是假绿"）
fn emit_rerun_recursive(dir: &Path) {
    println!("cargo:rerun-if-changed={}", dir.display());
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            emit_rerun_recursive(&path);
        } else {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn main() {
    emit_rerun_recursive(Path::new("../ks-ebpf/src/bpf"));
    println!("cargo:rerun-if-changed=../ks-ebpf/scripts/ks_loader.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let bpf_src_dir = manifest_dir.join("../ks-ebpf/src/bpf");
    if !bpf_src_dir.exists() {
        println!(
            "cargo:warning=eBPF源码目录不存在: {:?},跳过编译",
            bpf_src_dir
        );
        // btf_objects.rs 必须存在，否则 btf_source.rs 的 include! 编译失败
        write_btf_objects(&out_dir, &manifest_dir, &[]);
        write_ebpf_objects(&out_dir, &[], false);
        write_probe_registry(&out_dir, &BTreeMap::new());
        return;
    }

    let clang = ["clang-18", "clang-19", "clang"]
        .iter()
        .find_map(|name| which::which(name).ok())
        .expect("clang未找到,请安装: sudo apt install clang-18 llvm-18");

    println!("cargo:warning=使用clang: {:?}", clang);

    let bpf_main = bpf_src_dir.join("ks_main.bpf.c");
    if !bpf_main.exists() {
        panic!("ks_main.bpf.c不存在: {:?} - A3合并工作未完成", bpf_main);
    }

    let include_src = bpf_src_dir.to_str().unwrap().to_string();
    let include_bpf = "/usr/include/bpf".to_string();

    let tiers: &[(&str, &str, &[&str])] = &[
        ("modern", "KS_TIER_MODERN", &[]),
        ("legacy", "KS_TIER_LEGACY", &[]),
        ("ancient", "KS_TIER_ANCIENT", &[]),
        ("ancient_nobtf", "KS_TIER_ANCIENT", &["KS_NOBTF"]),
        ("legacy_nobtf", "KS_TIER_LEGACY", &["KS_NOBTF"]),
    ];

    let src_str = bpf_main.to_str().unwrap().to_string();
    let mut compiled: Vec<String> = Vec::new();

    for (suffix, tier_flag, extra_defines) in tiers {
        let output = out_dir.join(format!("ks_main_{}.o", suffix));
        let output_str = output.to_str().unwrap().to_string();
        let tier_define = format!("-D{}", tier_flag);

        let mut args: Vec<String> = vec![
            "-g".into(),
            "-O2".into(),
            "-target".into(),
            "bpf".into(),
            "-D__TARGET_ARCH_x86".into(),
            tier_define.clone(),
            "-I".into(),
            include_src.clone(),
            "-I".into(),
            include_bpf.clone(),
            "-c".into(),
            src_str.clone(),
            "-o".into(),
            output_str.clone(),
        ];
        for d in *extra_defines {
            args.push(format!("-D{}", d));
        }

        let status = Command::new(&clang).args(&args).status();

        match status {
            Ok(s) if s.success() => {
                println!(
                    "cargo:warning=eBPF ks_main_{}.o (tier={}, extra={:?}) 编译成功",
                    suffix, tier_flag, extra_defines
                );

                if *suffix == "ancient_nobtf" || *suffix == "legacy_nobtf" {
                    let objcopy = ["llvm-objcopy-18", "llvm-objcopy"]
                        .iter()
                        .find_map(|name| which::which(name).ok());
                    match objcopy {
                        Some(tool) => {
                            let strip_status = Command::new(&tool)
                                .args([
                                    "--remove-section",
                                    ".BTF.ext",
                                    "--remove-section",
                                    ".rel.BTF.ext",
                                    &output_str,
                                ])
                                .status();
                            match strip_status {
                                Ok(s) if s.success() => {
                                    println!(
                                        "cargo:warning=已自动剥离 .BTF.ext / .rel.BTF.ext段 (ks_main_{}.o)",
                                        suffix
                                    );
                                }
                                Ok(s) => {
                                    println!(
                                        "cargo:warning=剥离 .BTF.ext失败: 状态码 {:?}",
                                        s.code()
                                    );
                                }
                                Err(e) => {
                                    println!("cargo:warning=剥离 .BTF.ext失败: {}", e);
                                }
                            }
                        }
                        None => {
                            println!(
                                "cargo:warning=llvm-objcopy未安装,ks_main_{}.o需手动执行 \
                                 llvm-objcopy-18 --remove-section .BTF.ext --remove-section .rel.BTF.ext剥离",
                                suffix
                            );
                        }
                    }
                }

                compiled.push(format!("ks_main_{}.o", suffix));
            }
            Ok(s) => {
                // 编译失败不再静默跳过：交付的二进制可能缺 tier 而构建显示"成功"。
                // modern 是申报书主路径(5.8+ BTF 内核)，缺了必须 fail loud
                println!(
                    "cargo:warning=eBPF ks_main_{}.o (tier={}) 编译失败(状态码 {:?})",
                    suffix,
                    tier_flag,
                    s.code()
                );
                if *suffix == "modern" {
                    panic!("modern tier eBPF 编译失败 — 主路径不可交付。如环境无 clang，请安装 llvm/clang 后重试");
                }
                println!("cargo:warning=跳过此tier (运行时该 tier 将不可用)");
            }
            Err(e) => {
                println!(
                    "cargo:warning=eBPF ks_main_{}.o (tier={}) 编译启动失败: {}",
                    suffix, tier_flag, e
                );
                if *suffix == "modern" {
                    panic!("modern tier eBPF 无法启动编译: {} — 请检查 clang 环境", e);
                }
                println!("cargo:warning=跳过此tier (运行时该 tier 将不可用)");
            }
        }
    }

    if compiled.is_empty() {
        panic!("所有tier编译均失败,无法继续");
    }
    if !compiled.contains(&"ks_main_modern.o".to_string()) {
        println!("cargo:warning=Modern tier .o未编译成功,运行时将无法在5.8+ 内核上加载");
    }

    // ── 探针注册表：从各 tier 编译产物的 SEC 段自动枚举（单一来源）──
    // 五个 tier 的探针集合应完全一致；不一致说明条件编译把某个探针排除在某个
    // tier 之外，attach 逻辑会按"缺失即跳过"处理，但注册表必须发出同一份。
    let mut probes: BTreeMap<String, probe_registry::RawProbe> = BTreeMap::new();
    for name in &compiled {
        let obj_path = out_dir.join(name);
        let bytes = std::fs::read(&obj_path)
            .unwrap_or_else(|e| panic!("读取 {} 失败: {}", obj_path.display(), e));
        let parsed = probe_registry::parse_probe_sections(&bytes)
            .unwrap_or_else(|e| panic!("{} 探针 SEC 段解析失败: {}", name, e));
        for p in parsed {
            match probes.get(&p.name) {
                None => {
                    probes.insert(p.name.clone(), p);
                }
                Some(prev) => {
                    assert!(
                        prev == &p,
                        "tier 间探针 '{}' 元数据不一致: {:?} vs {:?}",
                        p.name,
                        prev,
                        p
                    );
                }
            }
        }
    }
    write_probe_registry(&out_dir, &probes);

    let ks_loader_built = build_static_ks_loader(&out_dir, &manifest_dir);

    // 带 CO-RE 重定位的对象（*_nobtf 已剥 .BTF.ext，喂给 bpftool 没有意义）
    let core_objects: Vec<PathBuf> = compiled
        .iter()
        .filter(|n| !n.contains("_nobtf"))
        .map(|n| out_dir.join(n))
        .collect();
    write_btf_objects(&out_dir, &manifest_dir, &core_objects);

    write_ebpf_objects(&out_dir, &compiled, ks_loader_built);
}

/// 生成 `probes_generated.rs`：loader/status 的探针清单唯一来源。
/// 条目按程序名排序，输出稳定（避免无谓的重新编译）。
fn write_probe_registry(out_dir: &Path, probes: &BTreeMap<String, probe_registry::RawProbe>) {
    let mut code = String::from(
        "// @generated by ks-engine/build.rs — 探针注册表单一来源（从 .o 的 SEC 段自动枚举），勿手改\n         pub const PROBE_REGISTRY: &[ProbeDef] = &[\n",
    );
    for p in probes.values() {
        let kind = match p.kind {
            "tracepoint" => "ProbeKind::Tracepoint",
            "kprobe" => "ProbeKind::Kprobe",
            "kretprobe" => "ProbeKind::Kretprobe",
            other => panic!("未知探针类型: {}", other),
        };
        let category = match &p.category {
            Some(c) => format!("Some({:?})", c),
            None => "None".to_string(),
        };
        code.push_str(&format!(
            "    ProbeDef {{ name: {:?}, kind: {}, category: {}, target: {:?} }},\n",
            p.name, kind, category, p.target
        ));
    }
    code.push_str("];\n");
    std::fs::write(out_dir.join("probes_generated.rs"), code)
        .expect("写入 probes_generated.rs 失败");
}

/// 扫描 crates/ks-ebpf/btf/，把目标内核 BTF 内嵌进二进制，生成 `btf_objects.rs`。
///
/// 用途：交付到没有 `/sys/kernel/btf/vmlinux` 的老内核时，aya 的 CO-RE 重定位
/// 仍需要一份该内核的 BTF，否则会静默跳过重定位并读取错误字段。
///
/// 文件名约定 `<kernel-release>.btf`，或入库形态 `<kernel-release>.btf.xz`
/// （实测可压到原始的 24%）。xz 在**构建期**解压，因此运行时不引入解压依赖。
/// 目录为空（默认交付情形）时生成空表，走 sysfs。
///
/// 解压后再用 `bpftool gen min_core_btf` 裁成"只含 `core_objects` 真正用到的类型"
/// 的最小 BTF 内嵌（实测 30.9MB → 1515 字节，重定位结果与完整 BTF 一致）：
/// 内嵌体积直接进交付单二进制，不能带着整份 vmlinux BTF 走。bpftool 缺失或失败
/// 时回退完整 BTF 并告警，不阻断构建。
fn write_btf_objects(
    out_dir: &std::path::Path,
    manifest_dir: &std::path::Path,
    core_objects: &[PathBuf],
) {
    let btf_dir = manifest_dir.join("../ks-ebpf/btf");
    let out_btf_dir = out_dir.join("btf");
    let bpftool = which::which("bpftool").ok();

    // 目录已在仓库中(.gitkeep)，所以这条 rerun-if-changed 不会因为路径不存在
    // 而导致 build script 每次重跑；往里放文件即可触发重新内嵌
    println!("cargo:rerun-if-changed={}", btf_dir.display());

    // (release, OUT_DIR 内文件名, 内嵌字节数, 是否裁过)
    let mut entries: Vec<(String, String, u64, bool)> = Vec::new();
    let mut warned_no_bpftool = false;

    let mut names: Vec<String> = std::fs::read_dir(&btf_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.path().is_file())
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    names.sort(); // 输出顺序稳定，避免无谓的重新编译

    for name in names {
        let Some(release) = name
            .strip_suffix(".btf.xz")
            .or_else(|| name.strip_suffix(".btf"))
        else {
            continue; // .gitkeep 等非 BTF 文件
        };
        if release.is_empty()
            || !release
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-_+".contains(c))
        {
            println!(
                "cargo:warning=btf/{} 的文件名不是合法的内核 release，跳过",
                name
            );
            continue;
        }
        println!("cargo:rerun-if-changed={}", btf_dir.join(&name).display());

        let dest_name = format!("{}.btf", release);
        let dest = out_btf_dir.join(&dest_name);
        if std::fs::create_dir_all(&out_btf_dir).is_err() {
            println!("cargo:warning=创建 {:?} 失败，跳过 {}", out_btf_dir, name);
            continue;
        }

        let src = btf_dir.join(&name);
        let copied = if name.ends_with(".xz") {
            decompress_xz(&src, &dest)
        } else {
            std::fs::copy(&src, &dest)
                .map(|_| ())
                .map_err(|e| format!("拷贝失败: {}", e))
        };
        if let Err(e) = copied {
            // 不阻断开发机构建（现代内核走 sysfs BTF 即可），但发布前必须确认
            // 内嵌表非空，否则交付到老内核时会退化成硬编码偏移
            println!("cargo:warning={} 未能内嵌: {}", name, e);
            continue;
        }

        let full_len = std::fs::metadata(&dest).map(|m| m.len()).unwrap_or(0);
        let mut picked = (dest_name, full_len, false);

        if !core_objects.is_empty() {
            match &bpftool {
                Some(tool) => {
                    let min_name = format!("{}.min.btf", release);
                    let min_dest = out_btf_dir.join(&min_name);
                    match minimize_btf(tool, &dest, &min_dest, core_objects) {
                        Ok(len) => {
                            println!(
                                "cargo:warning=内嵌内核 BTF {} 已裁剪为最小核心 BTF: {} → {} 字节",
                                release, full_len, len
                            );
                            picked = (min_name, len, true);
                        }
                        Err(e) => println!(
                            "cargo:warning={} 裁剪最小核心 BTF 失败({})，内嵌完整 BTF {} 字节",
                            name, e, full_len
                        ),
                    }
                }
                None => {
                    if !warned_no_bpftool {
                        warned_no_bpftool = true;
                        println!(
                            "cargo:warning=未找到 bpftool，内嵌完整内核 BTF（体积大数十 MB）。\
                             安装 bpftool(linux-tools) 可裁剪为最小核心 BTF（KB 级）"
                        );
                    }
                }
            }
        }

        entries.push((release.to_string(), picked.0, picked.1, picked.2));
    }

    let mut lines: Vec<String> = vec![
        "// AUTO-GENERATED by build.rs - 内嵌的目标内核 BTF(交付到无 BTF 老内核用)。请勿手改。"
            .into(),
        "// 来源: crates/ks-ebpf/btf/<release>.btf 或 <release>.btf.xz(构建期解压)。".into(),
        String::new(),
        "/// 已内嵌 BTF 的内核 release 列表(精确匹配,不做前缀猜测)。".into(),
    ];
    let releases: Vec<String> = entries
        .iter()
        .map(|(r, _, _, _)| format!("{:?}", r))
        .collect();
    lines.push(format!(
        "pub const BTF_EMBEDDED_RELEASES: &[&str] = &[{}];",
        releases.join(", ")
    ));
    lines.push(String::new());
    lines.push("/// 按内核 release 取内嵌 BTF。偏移随内核构建而变，故只做精确匹配。".into());
    lines.push("pub fn btf_for_release(release: &str) -> Option<&'static [u8]> {".into());
    lines.push("    match release {".into());
    for (release, dest_name, _, _) in &entries {
        lines.push(format!(
            "        {:?} => Some(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/btf/{}\"))),",
            release, dest_name
        ));
    }
    lines.push("        _ => None,".into());
    lines.push("    }".into());
    lines.push("}".into());
    lines.push(String::new());
    lines.push(
        "/// 该 release 的内嵌 BTF 是否为 bpftool 裁出的最小核心 BTF（而非完整 vmlinux BTF）。"
            .into(),
    );
    // 生成的布尔 match 会被 clippy 判成 matches! 可改写；本文件是构建产物，加 allow 免改写
    lines.push("#[allow(clippy::match_like_matches_macro)]".into());
    lines.push("pub fn btf_minimized(release: &str) -> bool {".into());
    lines.push("    match release {".into());
    for (release, _, _, minimized) in &entries {
        lines.push(format!("        {:?} => {},", release, minimized));
    }
    lines.push("        _ => false,".into());
    lines.push("    }".into());
    lines.push("}".into());

    std::fs::write(out_dir.join("btf_objects.rs"), lines.join("\n") + "\n")
        .expect("无法写入 btf_objects.rs");

    if entries.is_empty() {
        println!(
            "cargo:warning=未内嵌任何内核 BTF（crates/ks-ebpf/btf/ 为空）——\
             无 /sys/kernel/btf/vmlinux 的内核需靠 KS_BTF_PATH 指定"
        );
    } else {
        let detail: Vec<String> = entries
            .iter()
            .map(|(r, _, len, min)| {
                format!(
                    "{}={} 字节{}",
                    r,
                    len,
                    if *min {
                        "(最小核心 BTF)"
                    } else {
                        "(完整)"
                    }
                )
            })
            .collect();
        println!(
            "cargo:warning=已内嵌 {} 份内核 BTF: {}，合计 {} 字节",
            entries.len(),
            detail.join(", "),
            entries.iter().map(|(_, _, l, _)| l).sum::<u64>()
        );
    }
}

/// 用 `bpftool gen min_core_btf` 从完整 BTF 裁出只含 `objects` 引用到的类型的最小 BTF。
/// 纯文件操作，不需要 root，也不碰内核。
fn minimize_btf(
    bpftool: &std::path::Path,
    full: &std::path::Path,
    dest: &std::path::Path,
    objects: &[PathBuf],
) -> Result<u64, String> {
    let out = Command::new(bpftool)
        .arg("gen")
        .arg("min_core_btf")
        .arg(full)
        .arg(dest)
        .args(objects)
        .output()
        .map_err(|e| format!("执行 bpftool 失败: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "退出码 {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let len = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    if len == 0 {
        return Err("产物为空".into());
    }
    Ok(len)
}

/// 用系统 xz 解压。与 build.rs 已有的 clang/cc/llvm-objcopy 同样走外部工具，
/// 不新增 crate 依赖；xz 缺失只影响该份 BTF 的内嵌，不阻断构建。
fn decompress_xz(src: &std::path::Path, dest: &std::path::Path) -> Result<(), String> {
    let xz = which::which("xz").map_err(|e| format!("未找到 xz: {}", e))?;
    let out = std::process::Command::new(xz)
        .arg("-dc")
        .arg(src)
        .output()
        .map_err(|e| format!("执行 xz 失败: {}", e))?;
    if !out.status.success() {
        return Err(format!(
            "xz -dc 退出码 {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    if out.stdout.is_empty() {
        return Err("xz 解压输出为空".into());
    }
    std::fs::write(dest, &out.stdout).map_err(|e| format!("写入 {} 失败: {}", dest.display(), e))
}

fn write_ebpf_objects(out_dir: &std::path::Path, compiled: &[String], ks_loader_built: bool) {
    let mut arms: Vec<String> = Vec::new();
    let mut lines: Vec<String> = vec![
        "// AUTO-GENERATED by build.rs - 嵌入eBPF字节码(单二进制部署)。请勿手改。".into(),
        "// 仅编译成功的tier;ebpf_object_for(suffix)返回内嵌字节码,未编译tier返回None。".into(),
        "// 释放磁盘依赖(KS_EBPF_DIR仅作调试覆盖,非默认路径)。".into(),
        String::new(),
    ];
    for name in compiled {
        let suffix = name
            .strip_prefix("ks_main_")
            .and_then(|s| s.strip_suffix(".o"))
            .unwrap_or_else(|| panic!("异常.o文件名: {}", name));
        let const_name = format!("KS_MAIN_{}", suffix.to_uppercase().replace('-', "_"));
        lines.push(format!(
            "pub const {}: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{}\"));",
            const_name, name
        ));
        arms.push(format!("        {:?} => Some({}),", suffix, const_name));
    }
    if ks_loader_built {
        lines.push(String::new());
        lines.push("// 内嵌static ks_loader(nobtf路径去gcc,单二进制)".into());
        lines.push(
            "pub const KS_LOADER_STATIC: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/ks_loader\"));"
                .into(),
        );
    }
    lines.push(String::new());
    lines.push("/// 按tier后缀(modern/legacy/ancient/ancient_nobtf)返回内嵌eBPF字节码。".into());
    lines.push("/// 未编译成功的tier返回None,调用方应fail loud,不静默回退磁盘读。".into());
    lines.push("pub fn ebpf_object_for(suffix: &str) -> Option<&'static [u8]> {".into());
    lines.push("    match suffix {".into());
    lines.extend(arms);
    lines.push("        _ => None,".into());
    lines.push("    }".into());
    lines.push("}".into());
    lines.push(String::new());
    lines.push(
        "/// 返回内嵌的static ks_loader二进制;编译期未成功预编则返回None(nobtf回退KS_LOADER_PATH)。".into(),
    );
    lines.push("pub fn ks_loader_static() -> Option<&'static [u8]> {".into());
    if ks_loader_built {
        lines.push("    Some(KS_LOADER_STATIC)".into());
    } else {
        lines.push("    None".into());
    }
    lines.push("}".into());
    let body = lines.join("\n") + "\n";
    std::fs::write(out_dir.join("ebpf_objects.rs"), body).expect("无法写入ebpf_objects.rs");
}

fn build_static_ks_loader(out_dir: &std::path::Path, manifest_dir: &std::path::Path) -> bool {
    let src = manifest_dir.join("../ks-ebpf/scripts/ks_loader.c");
    if !src.exists() {
        println!(
            "cargo:warning=ks_loader.c不存在: {:?},跳过static预编(nobtf路径需KS_LOADER_PATH)",
            src
        );
        return false;
    }
    let cc = ["cc", "gcc"].iter().find_map(|n| which::which(n).ok());
    let cc = match cc {
        Some(c) => c,
        None => {
            println!("cargo:warning=未找到cc/gcc,跳过ks_loader static预编");
            return false;
        }
    };
    let out_bin = out_dir.join("ks_loader");
    let out_str = out_bin.to_str().unwrap().to_string();
    let src_str = src.to_str().unwrap().to_string();
    let status = std::process::Command::new(&cc)
        .args([
            "-static", "-O2", "-Wall", "-o", &out_str, &src_str, "-lelf", "-lzstd", "-lz",
        ])
        .status();
    match status {
        Ok(s) if s.success() => {
            println!(
                "cargo:warning=ks_loader static预编成功 ({} → {})",
                cc.display(),
                out_str
            );
            true
        }
        Ok(s) => {
            println!(
                "cargo:warning=ks_loader static预编失败(状态码 {:?}),nobtf路径将回退KS_LOADER_PATH",
                s.code()
            );
            false
        }
        Err(e) => {
            println!(
                "cargo:warning=ks_loader static预编启动失败: {},nobtf路径将回退KS_LOADER_PATH",
                e
            );
            false
        }
    }
}

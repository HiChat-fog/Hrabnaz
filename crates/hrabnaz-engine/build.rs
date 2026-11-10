use sha2::{Digest, Sha256};
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
    emit_rerun_recursive(Path::new("../hrabnaz-ebpf/src/bpf"));
    println!("cargo:rerun-if-changed=../hrabnaz-ebpf/scripts/hrabnaz_loader.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let bpf_src_dir = manifest_dir.join("../hrabnaz-ebpf/src/bpf");
    if !bpf_src_dir.exists() {
        println!(
            "cargo:warning=eBPF源码目录不存在: {:?},跳过编译",
            bpf_src_dir
        );
        // btf_objects.rs 必须存在，否则 btf_source.rs 的 include! 编译失败
        write_btf_objects(&out_dir, &manifest_dir);
        write_ebpf_objects(&out_dir, &[], false);
        write_probe_registry(&out_dir, &BTreeMap::new());
        return;
    }

    let clang = ["clang-18", "clang-19", "clang"]
        .iter()
        .find_map(|name| which::which(name).ok())
        .expect("clang未找到,请安装: sudo apt install clang-18 llvm-18");

    println!("cargo:warning=使用clang: {:?}", clang);

    let bpf_main = bpf_src_dir.join("hrabnaz_main.bpf.c");
    if !bpf_main.exists() {
        panic!("hrabnaz_main.bpf.c不存在: {:?} - A3合并工作未完成", bpf_main);
    }

    let include_src = bpf_src_dir.to_str().unwrap().to_string();
    let include_bpf = "/usr/include/bpf".to_string();

    let tiers: &[(&str, &str, &[&str])] = &[
        ("modern", "HRABNAZ_TIER_MODERN", &[]),
        ("legacy", "HRABNAZ_TIER_LEGACY", &[]),
        ("ancient", "HRABNAZ_TIER_ANCIENT", &[]),
        ("ancient_nobtf", "HRABNAZ_TIER_ANCIENT", &["HRABNAZ_NOBTF"]),
        ("legacy_nobtf", "HRABNAZ_TIER_LEGACY", &["HRABNAZ_NOBTF"]),
    ];

    let src_str = bpf_main.to_str().unwrap().to_string();
    let mut compiled: Vec<String> = Vec::new();

    for (suffix, tier_flag, extra_defines) in tiers {
        let output = out_dir.join(format!("hrabnaz_main_{}.o", suffix));
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
                    "cargo:warning=eBPF hrabnaz_main_{}.o (tier={}, extra={:?}) 编译成功",
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
                                        "cargo:warning=已自动剥离 .BTF.ext / .rel.BTF.ext段 (hrabnaz_main_{}.o)",
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
                                "cargo:warning=llvm-objcopy未安装,hrabnaz_main_{}.o需手动执行 \
                                 llvm-objcopy-18 --remove-section .BTF.ext --remove-section .rel.BTF.ext剥离",
                                suffix
                            );
                        }
                    }
                }

                compiled.push(format!("hrabnaz_main_{}.o", suffix));
            }
            Ok(s) => {
                // 编译失败不再静默跳过：交付的二进制可能缺 tier 而构建显示"成功"。
                // modern 是申报书主路径(5.8+ BTF 内核)，缺了必须 fail loud
                println!(
                    "cargo:warning=eBPF hrabnaz_main_{}.o (tier={}) 编译失败(状态码 {:?})",
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
                    "cargo:warning=eBPF hrabnaz_main_{}.o (tier={}) 编译启动失败: {}",
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
    if !compiled.contains(&"hrabnaz_main_modern.o".to_string()) {
        println!("cargo:warning=Modern tier .o未编译成功,运行时将无法在5.8+ 内核上加载");
    }

    // ── 指令数预算闸门：老内核验证器 BPF_MAXINSNS=4096 ──
    // 超限 = BPF_PROG_LOAD E2BIG → 运行时回退 mock；旧部署二进制可能仍合规，
    // 本地不会暴露，直到发布才在 3.10 静默哑火（QEMU 实测 trace_sys_exit 曾 7483 条）。
    // 这里在构建期硬失败，并打印各程序尺寸（预算表）。
    const INSNS_LIMIT: u64 = 4096;
    for name in &compiled {
        let obj_path = out_dir.join(name);
        let bytes = std::fs::read(&obj_path)
            .unwrap_or_else(|e| panic!("读取 {} 失败: {}", obj_path.display(), e));
        let mut sizes = probe_registry::program_sizes(&bytes)
            .unwrap_or_else(|e| panic!("{} 程序尺寸解析失败: {}", name, e));
        sizes.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let top: Vec<String> = sizes
            .iter()
            .take(4)
            .map(|(n, c)| format!("{n}={c}"))
            .collect();
        println!("cargo:warning={} 程序指令数 TOP: {}", name, top.join(", "));
        let over: Vec<String> = sizes
            .iter()
            .filter(|(_, c)| *c > INSNS_LIMIT)
            .map(|(n, c)| format!("{n}={c}"))
            .collect();
        if !over.is_empty() {
            panic!(
                "{} 有程序超过老内核指令上限 {}（{}）。拆分该 SEC 段为多个程序（同一 tracepoint 可挂多个），\
                 或精简逻辑后再提交。",
                name,
                INSNS_LIMIT,
                over.join(", ")
            );
        }
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

    let hrabnaz_loader_built = build_static_hrabnaz_loader(&out_dir, &manifest_dir);

    write_btf_objects(&out_dir, &manifest_dir);

    write_ebpf_objects(&out_dir, &compiled, hrabnaz_loader_built);
}

/// 生成 `probes_generated.rs`：loader/status 的探针清单唯一来源。
/// 条目按程序名排序，输出稳定（避免无谓的重新编译）。
fn write_probe_registry(out_dir: &Path, probes: &BTreeMap<String, probe_registry::RawProbe>) {
    let mut code = String::from(
        "// @generated by hrabnaz-engine/build.rs — 探针注册表单一来源（从 .o 的 SEC 段自动枚举），勿手改\n         pub const PROBE_REGISTRY: &[ProbeDef] = &[\n",
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

/// 把裁剪后的目标内核 BTF 内嵌进二进制，生成 `btf_objects.rs`。
///
/// `btf/index.tsv` 是唯一入口：`<release>\t<blob>\t<full_btf_sha256>`。
/// `btf/blobs/<sha256[0:16]>.min.btf` 由 `scripts/btf-regen.sh` 生成。
fn write_btf_objects(out_dir: &Path, manifest_dir: &Path) {
    let btf_dir = manifest_dir.join("../hrabnaz-ebpf/btf");
    let blobs_dir = btf_dir.join("blobs");
    let index_path = btf_dir.join("index.tsv");
    println!("cargo:rerun-if-changed={}", index_path.display());
    println!("cargo:rerun-if-changed={}", blobs_dir.display());

    let index = std::fs::read_to_string(&index_path).unwrap_or_default();
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in index.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 2 {
            panic!("btf/index.tsv 行格式错误: {:?}", line);
        }
        let (release, blob) = (parts[0], parts[1]);
        let path = blobs_dir.join(format!("{}.min.btf", blob));
        if !path.is_file() {
            panic!(
                "btf/index.tsv 引用了不存在的 blob: {}（release {}）",
                path.display(),
                release
            );
        }
        entries.push((release.to_string(), blob.to_string()));
    }
    entries.sort();
    entries.dedup();

    let mut blobs: Vec<String> = entries.iter().map(|(_, b)| b.clone()).collect();
    blobs.sort();
    blobs.dedup();

    for blob in &blobs {
        let path = blobs_dir.join(format!("{}.min.btf", blob));
        let bytes =
            std::fs::read(&path).unwrap_or_else(|e| panic!("读取 {} 失败: {}", path.display(), e));
        let actual = hex(&Sha256::digest(&bytes));
        if !actual.starts_with(blob.as_str()) {
            panic!("{} 的内容哈希是 {}，与文件名不一致", path.display(), actual);
        }
    }

    let mut lines = vec![
        "// AUTO-GENERATED by build.rs - 内嵌的目标内核最小 BTF。请勿手改。".to_string(),
        "// 来源: crates/hrabnaz-ebpf/btf/index.tsv 与 blobs/（scripts/btf-regen.sh 生成）。"
            .to_string(),
        String::new(),
    ];
    for (i, blob) in blobs.iter().enumerate() {
        lines.push(format!(
            "static BTF_{}: &[u8] = include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/../hrabnaz-ebpf/btf/blobs/{}.min.btf\"));",
            i, blob
        ));
    }
    lines.push(String::new());
    lines.push("/// 已内嵌 BTF 的内核 release 列表(精确匹配,不做前缀猜测)。".to_string());
    let releases: Vec<String> = entries.iter().map(|(r, _)| format!("{:?}", r)).collect();
    lines.push(format!(
        "pub const BTF_EMBEDDED_RELEASES: &[&str] = &[{}];",
        releases.join(", ")
    ));
    lines.push(String::new());
    lines.push("/// 按内核 release 取内嵌 BTF。偏移随内核构建而变，故只做精确匹配。".to_string());
    lines.push("pub fn btf_for_release(release: &str) -> Option<&'static [u8]> {".to_string());
    lines.push("    match release {".to_string());
    let blob_index: std::collections::HashMap<&str, usize> = blobs
        .iter()
        .enumerate()
        .map(|(i, b)| (b.as_str(), i))
        .collect();
    for (release, blob) in &entries {
        lines.push(format!(
            "        {:?} => Some(BTF_{}),",
            release,
            blob_index[blob.as_str()]
        ));
    }
    lines.push("        _ => None,".to_string());
    lines.push("    }".to_string());
    lines.push("}".to_string());
    lines.push(String::new());
    lines.push("/// 内嵌表里的 BTF 都是 `bpftool gen min_core_btf` 的产物。".to_string());
    lines.push("#[allow(clippy::match_like_matches_macro)]".to_string());
    lines.push("pub fn btf_minimized(release: &str) -> bool {".to_string());
    lines.push("    match release {".to_string());
    for (release, _) in &entries {
        lines.push(format!("        {:?} => true,", release));
    }
    lines.push("        _ => false,".to_string());
    lines.push("    }".to_string());
    lines.push("}".to_string());

    std::fs::write(out_dir.join("btf_objects.rs"), lines.join("\n") + "\n")
        .expect("无法写入 btf_objects.rs");

    let total: u64 = blobs
        .iter()
        .map(|b| {
            std::fs::metadata(blobs_dir.join(format!("{}.min.btf", b)))
                .map(|m| m.len())
                .unwrap_or(0)
        })
        .sum();
    println!(
        "cargo:warning=内嵌 {} 份内核 BTF（{} 个唯一 blob，{} 字节）",
        entries.len(),
        blobs.len(),
        total
    );

    if let Ok(rd) = std::fs::read_dir(&blobs_dir) {
        let used: std::collections::HashSet<&str> = blobs.iter().map(|b| b.as_str()).collect();
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if let Some(stem) = name.strip_suffix(".min.btf") {
                if !used.contains(stem) {
                    println!("cargo:warning=btf/blobs/{} 未被 index.tsv 引用", name);
                }
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn write_ebpf_objects(out_dir: &std::path::Path, compiled: &[String], hrabnaz_loader_built: bool) {
    let mut arms: Vec<String> = Vec::new();
    let mut lines: Vec<String> = vec![
        "// AUTO-GENERATED by build.rs - 嵌入eBPF字节码(单二进制部署)。请勿手改。".into(),
        "// 仅编译成功的tier;ebpf_object_for(suffix)返回内嵌字节码,未编译tier返回None。".into(),
        "// 释放磁盘依赖(HRABNAZ_EBPF_DIR仅作调试覆盖,非默认路径)。".into(),
        String::new(),
    ];
    for name in compiled {
        let suffix = name
            .strip_prefix("hrabnaz_main_")
            .and_then(|s| s.strip_suffix(".o"))
            .unwrap_or_else(|| panic!("异常.o文件名: {}", name));
        let const_name = format!("HRABNAZ_MAIN_{}", suffix.to_uppercase().replace('-', "_"));
        lines.push(format!(
            "pub const {}: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{}\"));",
            const_name, name
        ));
        arms.push(format!("        {:?} => Some({}),", suffix, const_name));
    }
    if hrabnaz_loader_built {
        lines.push(String::new());
        lines.push("// 内嵌static hrabnaz_loader(nobtf路径去gcc,单二进制)".into());
        lines.push(
            "pub const HRABNAZ_LOADER_STATIC: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/hrabnaz_loader\"));"
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
        "/// 返回内嵌的static hrabnaz_loader二进制;编译期未成功预编则返回None(nobtf回退KS_LOADER_PATH)。".into(),
    );
    lines.push("pub fn hrabnaz_loader_static() -> Option<&'static [u8]> {".into());
    if hrabnaz_loader_built {
        lines.push("    Some(HRABNAZ_LOADER_STATIC)".into());
    } else {
        lines.push("    None".into());
    }
    lines.push("}".into());
    let body = lines.join("\n") + "\n";
    std::fs::write(out_dir.join("ebpf_objects.rs"), body).expect("无法写入ebpf_objects.rs");
}

fn build_static_hrabnaz_loader(out_dir: &std::path::Path, manifest_dir: &std::path::Path) -> bool {
    let src = manifest_dir.join("../hrabnaz-ebpf/scripts/hrabnaz_loader.c");
    if !src.exists() {
        println!(
            "cargo:warning=hrabnaz_loader.c不存在: {:?},跳过static预编(nobtf路径需KS_LOADER_PATH)",
            src
        );
        return false;
    }
    let cc = ["cc", "gcc"].iter().find_map(|n| which::which(n).ok());
    let cc = match cc {
        Some(c) => c,
        None => {
            println!("cargo:warning=未找到cc/gcc,跳过hrabnaz_loader static预编");
            return false;
        }
    };
    let out_bin = out_dir.join("hrabnaz_loader");
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
                "cargo:warning=hrabnaz_loader static预编成功 ({} → {})",
                cc.display(),
                out_str
            );
            true
        }
        Ok(s) => {
            println!(
                "cargo:warning=hrabnaz_loader static预编失败(状态码 {:?}),nobtf路径将回退KS_LOADER_PATH",
                s.code()
            );
            false
        }
        Err(e) => {
            println!(
                "cargo:warning=hrabnaz_loader static预编启动失败: {},nobtf路径将回退KS_LOADER_PATH",
                e
            );
            false
        }
    }
}

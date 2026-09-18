use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_main.bpf.c");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/common.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/vmlinux.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_syscall.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_vfs.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_net.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_netflow.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_process_tree.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_container.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_lkm.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_self_protect.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_freq.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/ks_probes_smart_filter.h");
    println!("cargo:rerun-if-changed=../ks-ebpf/scripts/ks_loader.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    let bpf_src_dir = manifest_dir.join("../ks-ebpf/src/bpf");
    if !bpf_src_dir.exists() {
        println!(
            "cargo:warning=eBPF源码目录不存在: {:?},跳过编译",
            bpf_src_dir
        );
        write_ebpf_objects(&out_dir, &[], false);
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
                                    println!("cargo:warning=已自动剥离 .BTF.ext / .rel.BTF.ext段 (ks_main_ancient_nobtf.o)");
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
                            println!("cargo:warning=llvm-objcopy未安装,ks_main_ancient_nobtf.o需手动执行llvm-objcopy-18 --remove-section .BTF.ext --remove-section .rel.BTF.ext剥离");
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
                    suffix, tier_flag, s.code()
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

    let ks_loader_built = build_static_ks_loader(&out_dir, &manifest_dir);

    write_ebpf_objects(&out_dir, &compiled, ks_loader_built);
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
    lines.push(
        "/// 按tier后缀(modern/legacy/ancient/ancient_nobtf)返回内嵌eBPF字节码。".into(),
    );
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
        .args(["-static", "-O2", "-Wall", "-o", &out_str, &src_str, "-lelf", "-lzstd", "-lz"])
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

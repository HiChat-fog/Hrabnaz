//! ks-engine build.rs: 编译eBPF C探针为字节码(.o)
//!
//! A3重构后：8个原.bpf.c已合并为单一编译单元ks_main.bpf.c。
//! ks_main.bpf.c #include了7个ks_probes_*.h头文件，产物为单一ks_main.o。
//! 共享maps(risk_scores/ip_whitelist/net_conn_history/freq_counters/infer_config)
//! 与共享events ringbuf真正跨探针生效。

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/");
    // D2: ks_loader.c改动须触发static预编重跑（否则嵌入的ks_loader二进制会过期）
    println!("cargo:rerun-if-changed=../ks-ebpf/scripts/ks_loader.c");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // eBPF源码路径: 相对于ks-engine crate
    let bpf_src_dir = manifest_dir.join("../ks-ebpf/src/bpf");
    if !bpf_src_dir.exists() {
        println!(
            "cargo:warning=eBPF 源码目录不存在: {:?}，跳过编译",
            bpf_src_dir
        );
        // 仍写出ebpf_objects.rs（空consts），保证loader.rs的include!不破裂。
        write_ebpf_objects(&out_dir, &[], false);
        return;
    }

    // 检测clang(兼容clang-18 / clang-19 / clang)
    let clang = ["clang-18", "clang-19", "clang"]
        .iter()
        .find_map(|name| which::which(name).ok())
        .expect("clang 未找到，请安装: sudo apt install clang-18 llvm-18");

    println!("cargo:warning=使用 clang: {:?}", clang);

    // A3: 只编译合并后的单一入口ks_main.bpf.c
    let bpf_main = bpf_src_dir.join("ks_main.bpf.c");
    if !bpf_main.exists() {
        panic!("ks_main.bpf.c 不存在: {:?} — A3 合并工作未完成", bpf_main);
    }

    // 头文件路径: 源码目录(vmlinux.h, common.h, ks_probes_*.h) + 系统bpf头
    let include_src = bpf_src_dir.to_str().unwrap().to_string();
    let include_bpf = "/usr/include/bpf".to_string();

    // B3: 编译4个tier-specific .o
    //   modern       — 5.8+ ringbuf
    //   legacy       — 4.x perfbuf
    //   ancient      — 3.10+ BTF backport (CO-RE, 需BTF)
    //   ancient_nobtf — 3.10+ 无BTF (硬编码offset, 无需kernel-plus)
    // 某tier编译失败时warn+跳过（不阻断Modern tier构建）
    let tiers: &[(&str, &str, &[&str])] = &[
        ("modern", "KS_TIER_MODERN", &[]),
        ("legacy", "KS_TIER_LEGACY", &[]),
        ("ancient", "KS_TIER_ANCIENT", &[]),
        ("ancient_nobtf", "KS_TIER_ANCIENT", &["KS_NOBTF"]),
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

                // Phase E1.1: ancient_nobtf tier需剥离 .BTF.ext / .rel.BTF.ext段
                // 3.10 stock内核verifier无法处理CO-RE重定位段，但保留.BTF段供aya parse_btf_maps解析map定义。
                if *suffix == "ancient_nobtf" {
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
                                    println!("cargo:warning=已自动剥离 .BTF.ext / .rel.BTF.ext 段 (ks_main_ancient_nobtf.o)");
                                }
                                Ok(s) => {
                                    println!(
                                        "cargo:warning=剥离 .BTF.ext 失败: 状态码 {:?}",
                                        s.code()
                                    );
                                }
                                Err(e) => {
                                    println!("cargo:warning=剥离 .BTF.ext 失败: {}", e);
                                }
                            }
                        }
                        None => {
                            println!("cargo:warning=llvm-objcopy 未安装，ks_main_ancient_nobtf.o 需手动执行 llvm-objcopy-18 --remove-section .BTF.ext --remove-section .rel.BTF.ext 剥离");
                        }
                    }
                }

                compiled.push(format!("ks_main_{}.o", suffix));
            }
            Ok(s) => {
                println!("cargo:warning=eBPF ks_main_{}.o (tier={}) 编译失败（状态码 {:?}），跳过此 tier",
                         suffix, tier_flag, s.code());
            }
            Err(e) => {
                println!(
                    "cargo:warning=eBPF ks_main_{}.o (tier={}) 编译启动失败: {}，跳过此 tier",
                    suffix, tier_flag, e
                );
            }
        }
    }

    if compiled.is_empty() {
        panic!("所有 tier 编译均失败，无法继续");
    }
    if !compiled.contains(&"ks_main_modern.o".to_string()) {
        println!("cargo:warning=Modern tier .o 未编译成功，运行时将无法在 5.8+ 内核上加载");
    }

    // D2: 预编static ks_loader并嵌入（nobtf路径去gcc + 单二进制）。
    let ks_loader_built = build_static_ks_loader(&out_dir, &manifest_dir);

    // 生成ebpf_objects.rs：把编译成功的各tier .o + ks_loader用include_bytes!嵌入二进制。
    write_ebpf_objects(&out_dir, &compiled, ks_loader_built);
}

/// 生成 `OUT_DIR/ebpf_objects.rs`：把 `compiled` 中列出的各tier .o用`include_bytes!`嵌入二进制。
///
/// D1单二进制部署——消除运行时从磁盘读.o的依赖（`env!("OUT_DIR")`烤死构建机路径地雷）。
/// 仅emit实际编译成功的tier；未编译的tier不生成const/match arm，
/// `ebpf_object_for`对其返回None，调用方 fail loud（不静默回退磁盘读）。
fn write_ebpf_objects(out_dir: &std::path::Path, compiled: &[String], ks_loader_built: bool) {
    let mut arms: Vec<String> = Vec::new();
    let mut lines: Vec<String> = vec![
        "// AUTO-GENERATED by build.rs — 嵌入 eBPF 字节码（D1 单二进制部署）。请勿手改。".into(),
        "// 仅编译成功的 tier；ebpf_object_for(suffix) 返回内嵌字节码，未编译 tier 返回 None。".into(),
        "// 释放磁盘依赖（KS_EBPF_DIR 仅作调试覆盖，非默认路径）。".into(),
        String::new(),
    ];
    for name in compiled {
        // name形如 "ks_main_modern.o" / "ks_main_ancient_nobtf.o"
        let suffix = name
            .strip_prefix("ks_main_")
            .and_then(|s| s.strip_suffix(".o"))
            .unwrap_or_else(|| panic!("异常 .o 文件名: {}", name));
        let const_name = format!("KS_MAIN_{}", suffix.to_uppercase().replace('-', "_"));
        lines.push(format!(
            "pub const {}: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/{}\"));",
            const_name, name
        ));
        arms.push(format!("        {:?} => Some({}),", suffix, const_name));
    }
    if ks_loader_built {
        lines.push(String::new());
        lines.push("// D2: 内嵌 static ks_loader（nobtf 路径去 gcc，单二进制）".into());
        lines.push(
            "pub const KS_LOADER_STATIC: &[u8] = include_bytes!(concat!(env!(\"OUT_DIR\"), \"/ks_loader\"));"
                .into(),
        );
    }
    lines.push(String::new());
    lines.push(
        "/// 按 tier 后缀（\"modern\"/\"legacy\"/\"ancient\"/\"ancient_nobtf\"）返回内嵌 eBPF 字节码。".into(),
    );
    lines.push("/// 未编译成功的 tier 返回 None —— 调用方应 fail loud，不静默回退磁盘读。".into());
    lines.push("pub fn ebpf_object_for(suffix: &str) -> Option<&'static [u8]> {".into());
    lines.push("    match suffix {".into());
    lines.extend(arms);
    lines.push("        _ => None,".into());
    lines.push("    }".into());
    lines.push("}".into());
    lines.push(String::new());
    lines.push(
        "/// 返回内嵌的 static ks_loader 二进制；编译期未成功预编则返回 None（nobtf 回退 KS_LOADER_PATH）。".into(),
    );
    lines.push("pub fn ks_loader_static() -> Option<&'static [u8]> {".into());
    if ks_loader_built {
        lines.push("    Some(KS_LOADER_STATIC)".into());
    } else {
        lines.push("    None".into());
    }
    lines.push("}".into());
    let body = lines.join("\n") + "\n";
    std::fs::write(out_dir.join("ebpf_objects.rs"), body).expect("无法写入 ebpf_objects.rs");
}

/// D2: 预编static ks_loader二进制（nobtf C loader）到OUT_DIR。
///
/// `gcc -static` 静态链接libelf+libz+libzstd，使ks_loader可在CentOS 7(glibc 2.17)
/// 等老内核运行（纯syscall + libelf，无NSS/dlopen，静态二进制跨glibc版本可移植）。
/// 编译失败（缺gcc/libelf.a等）则warn + 返回false，nobtf路径回退到KS_LOADER_PATH磁盘查找。
fn build_static_ks_loader(out_dir: &std::path::Path, manifest_dir: &std::path::Path) -> bool {
    let src = manifest_dir.join("../ks-ebpf/scripts/ks_loader.c");
    if !src.exists() {
        println!(
            "cargo:warning=ks_loader.c 不存在: {:?}，跳过 static 预编（nobtf 路径需 KS_LOADER_PATH）",
            src
        );
        return false;
    }
    let cc = ["cc", "gcc"].iter().find_map(|n| which::which(n).ok());
    let cc = match cc {
        Some(c) => c,
        None => {
            println!("cargo:warning=未找到 cc/gcc，跳过 ks_loader static 预编");
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
                "cargo:warning=ks_loader static 预编成功 ({} → {})",
                cc.display(),
                out_str
            );
            true
        }
        Ok(s) => {
            println!(
                "cargo:warning=ks_loader static 预编失败（状态码 {:?}），nobtf 路径将回退 KS_LOADER_PATH",
                s.code()
            );
            false
        }
        Err(e) => {
            println!(
                "cargo:warning=ks_loader static 预编启动失败: {}，nobtf 路径将回退 KS_LOADER_PATH",
                e
            );
            false
        }
    }
}

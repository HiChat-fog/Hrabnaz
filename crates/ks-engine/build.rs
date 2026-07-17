//! ks-engine build.rs: 编译 eBPF C 探针为字节码 (.o)
//!
//! A3 重构后：8 个原 .bpf.c 已合并为单一编译单元 ks_main.bpf.c。
//! ks_main.bpf.c #include 了 7 个 ks_probes_*.h 头文件，编译产物是单一 ks_main.o。
//! 共享 maps (risk_scores/ip_whitelist/net_conn_history/freq_counters/infer_config)
//! 与共享 events ringbuf 现在真正跨探针生效。

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../ks-ebpf/src/bpf/");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // eBPF 源码路径: 相对于 ks-engine crate
    let bpf_src_dir = manifest_dir.join("../ks-ebpf/src/bpf");
    if !bpf_src_dir.exists() {
        println!(
            "cargo:warning=eBPF 源码目录不存在: {:?}，跳过编译",
            bpf_src_dir
        );
        return;
    }

    // 检测 clang (兼容 clang-18 / clang-19 / clang)
    let clang = ["clang-18", "clang-19", "clang"]
        .iter()
        .find_map(|name| which::which(name).ok())
        .expect("clang 未找到，请安装: sudo apt install clang-18 llvm-18");

    println!("cargo:warning=使用 clang: {:?}", clang);

    // A3: 只编译合并后的单一入口 ks_main.bpf.c
    // 旧的 8 个 .bpf.c 已被 ks_main.bpf.c + ks_probes_*.h 替代
    let bpf_main = bpf_src_dir.join("ks_main.bpf.c");
    if !bpf_main.exists() {
        panic!("ks_main.bpf.c 不存在: {:?} — A3 合并工作未完成", bpf_main);
    }

    // 头文件路径: 源码目录 (vmlinux.h, common.h, ks_probes_*.h) + 系统 bpf 头
    let include_src = bpf_src_dir.to_str().unwrap().to_string();
    let include_bpf = "/usr/include/bpf".to_string();

    // B3: 编译 4 个 tier-specific .o
    //   modern       — 5.8+ ringbuf
    //   legacy       — 4.x perfbuf
    //   ancient      — 3.10+ BTF backport (CO-RE, 需 BTF)
    //   ancient_nobtf — 3.10+ 无 BTF (硬编码 offset, 无需 kernel-plus)
    // 某 tier 编译失败时 warn+跳过（不阻断 Modern tier 构建）
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

                // Phase E1.1: ancient_nobtf tier 需剥离 .BTF.ext / .rel.BTF.ext 段
                // 3.10 stock 内核 verifier 无法处理 CO-RE 重定位段，但保留 .BTF
                // 段供 aya parse_btf_maps 解析 map 定义。
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

    // 生成 ebpf_objects.rs（列出实际编译成功的 .o）
    let objects_list: String = compiled
        .iter()
        .map(|n| format!("    \"{}\"", n))
        .collect::<Vec<_>>()
        .join(",\n");

    std::fs::write(
        out_dir.join("ebpf_objects.rs"),
        format!(
            "/// 编译好的 eBPF 字节码文件列表 (由 build.rs 生成)\n\
             /// B3: 3 个 tier 各编译一个 .o，运行时按 tier 选择加载。\n\
             pub const EBPF_OBJECTS: &[&str] = &[\n{}\n];\n\
             pub const EBPF_OUT_DIR: &str = \"{}\";\n",
            objects_list,
            out_dir.display(),
        ),
    )
    .expect("无法写入 ebpf_objects.rs");
}

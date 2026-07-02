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
        println!("cargo:warning=eBPF 源码目录不存在: {:?}，跳过编译", bpf_src_dir);
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

    // A2: 注入 tier 条件编译宏
    // 当前 Phase A 仅实现 KS_TIER_MODERN（ringbuf 路径）
    // Phase B 将实现 KS_TIER_LEGACY（perfbuf，4.x 内核）
    // Phase C 将实现 KS_TIER_ANCIENT（3.10.0-1160+ BTF backport，HASH + 手动 LRU）
    let tier_flag = "KS_TIER_MODERN";

    let stem = "ks_main";
    let output = out_dir.join(format!("{}.o", stem));
    let output_str = output.to_str().unwrap().to_string();
    let src_str = bpf_main.to_str().unwrap().to_string();
    let tier_define = format!("-D{}", tier_flag);

    let status = Command::new(&clang)
        .args([
            "-g",
            "-O2",
            "-target",
            "bpf",
            "-D__TARGET_ARCH_x86",
            &tier_define,
            "-I", &include_src,
            "-I", &include_bpf,
            "-c", &src_str,
            "-o", &output_str,
        ])
        .status()
        .unwrap_or_else(|e| panic!("编译 {} 失败: {}", stem, e));

    if !status.success() {
        panic!("eBPF 程序 {} 编译失败（tier={}）", stem, tier_flag);
    }

    println!("cargo:warning=eBPF {} (tier={}) -> {}", stem, tier_flag, output_str);

    // A3: ebpf_objects.rs 只列单一 ks_main.o
    std::fs::write(
        out_dir.join("ebpf_objects.rs"),
        format!(
            "/// 编译好的 eBPF 字节码文件列表 (由 build.rs 生成)\n\
             /// A3 重构后：8 个原 .o 已合并为单一 ks_main.o\n\
             /// 共享 maps 现在真正跨探针生效（同一编译单元）。\n\
             pub const EBPF_OBJECTS: &[&str] = &[\n    \"ks_main.o\",\n];\n\
             pub const EBPF_OUT_DIR: &str = \"{}\";\n",
            out_dir.display(),
        ),
    )
    .expect("无法写入 ebpf_objects.rs");
}
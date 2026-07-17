//! ks-ebpf: eBPF 探针程序 (C 代码编译)
//!
//! build.rs 负责:
//! 1. 检测系统 clang/llvm
//! 2. 编译 src/bpf/*.bpf.c 为 eBPF 字节码 (.o)
//! 3. 将编译产物放在 OUT_DIR 供主程序加载

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src/bpf/");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_src_dir = PathBuf::from("src/bpf");

    // 检测 clang
    let clang = which::which("clang").expect("clang 未找到，请安装: sudo apt install clang llvm");

    // 编译每个 .bpf.c 文件
    let bpf_files: Vec<PathBuf> = std::fs::read_dir(&bpf_src_dir)
        .expect("无法读取 bpf 源码目录")
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("c") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    if bpf_files.is_empty() {
        println!("cargo:warning=src/bpf/ 目录下没有 .bpf.c 文件");
        return;
    }

    for bpf_file in &bpf_files {
        let stem = bpf_file.file_stem().unwrap().to_str().unwrap();
        let output = out_dir.join(format!("{}.o", stem));

        let status = Command::new(&clang)
            .args([
                "-g",
                "-O2",
                "-target",
                "bpf",
                "-D__TARGET_ARCH_x86",
                "-I",
                bpf_src_dir.to_str().unwrap(),
                "-c",
                bpf_file.to_str().unwrap(),
                "-o",
                output.to_str().unwrap(),
            ])
            .status()
            .unwrap_or_else(|e| panic!("编译 {} 失败: {}", stem, e));

        if !status.success() {
            panic!("eBPF 程序 {} 编译失败", stem);
        }

        println!("cargo:warning=eBPF 程序 {} 编译成功 -> {}", stem, output.display());
    }
}

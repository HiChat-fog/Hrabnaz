//! ks-engine build.rs: 编译 eBPF C 探针为字节码 (.o)
//!
//! 从 ../ks-ebpf/src/bpf/ 读取 .bpf.c 源文件，编译后放在 OUT_DIR。

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

    // 收集 .bpf.c 文件
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

    // 头文件路径: 源码目录 (vmlinux.h, common.h) + 系统 bpf 头
    let include_src = bpf_src_dir.to_str().unwrap().to_string();
    let include_bpf = "/usr/include/bpf".to_string();

    for bpf_file in &bpf_files {
        let stem = bpf_file.file_stem().unwrap().to_str().unwrap();
        let output = out_dir.join(format!("{}.o", stem));
        let output_str = output.to_str().unwrap().to_string();
        let src_str = bpf_file.to_str().unwrap().to_string();

        let status = Command::new(&clang)
            .args([
                "-g",
                "-O2",
                "-target",
                "bpf",
                "-D__TARGET_ARCH_x86",
                "-I", &include_src,
                "-I", &include_bpf,
                "-c", &src_str,
                "-o", &output_str,
            ])
            .status()
            .unwrap_or_else(|e| panic!("编译 {} 失败: {}", stem, e));

        if !status.success() {
            panic!("eBPF 程序 {} 编译失败", stem);
        }

        println!("cargo:warning=eBPF {} -> {}", stem, output_str);
    }

    // 生成 .o 文件路径常量供 loader.rs 使用
    let o_files: Vec<String> = bpf_files
        .iter()
        .map(|f| f.file_stem().unwrap().to_str().unwrap().to_string() + ".o")
        .collect();

    let o_list = o_files.join("\",\n    \"");
    std::fs::write(
        out_dir.join("ebpf_objects.rs"),
        format!(
            "/// 编译好的 eBPF 字节码文件列表 (由 build.rs 生成)\n\
             pub const EBPF_OBJECTS: &[&str] = &[\n    \"{}\",\n];\n\
             pub const EBPF_OUT_DIR: &str = \"{}\";\n",
            o_list,
            out_dir.display(),
        ),
    )
    .expect("无法写入 ebpf_objects.rs");
}
#!/bin/bash
# KernelSentinel 开发环境一键搭建脚本
# 用法: chmod +x setup_dev.sh && ./setup_dev.sh

set -euo pipefail

echo "========================================"
echo " 内核哨兵 (KernelSentinel) 开发环境搭建"
echo "========================================"

# 1. 系统依赖
echo "[1/6] 安装系统依赖..."
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    pkg-config \
    curl \
    git

# 2. Rust (如果没装)
echo "[2/6] 检查 Rust 工具链..."
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# 安装 bpf-linker (aya 需要的 eBPF 链接器)——可选步骤，失败不中断整个脚本
cargo install bpf-linker || echo "  [warn] bpf-linker 安装失败（本项目用 clang 直接编译 eBPF，可不装）"

# 3. Rust 目标平台
echo "[3/6] 添加 Rust 交叉编译目标..."
# eBPF 由 clang 直接编译（ks-engine/build.rs），无需额外 rust target

# 4. bpf 工具链
echo "[4/6] 安装 BPF 工具..."
sudo apt install -y \
    bpftool \
    linux-tools-common \
    linux-tools-$(uname -r) 2>/dev/null || echo "  (linux-tools 跳过，无伤大雅)"

# 5. 前端工具 (可选)
echo "[5/6] 安装前端工具链..."
if ! command -v npx &> /dev/null; then
    sudo npm install -g npx
fi

# 6. 验证
echo "[6/6] 验证环境..."
echo "  Rust:  $(rustc --version)"
echo "  Cargo: $(cargo --version)"
echo "  Clang: $(clang --version | head -1)"
echo "  LLVM:  $(llvm-config --version 2>/dev/null || echo 'N/A')"
echo "  bpftool: $(bpftool version 2>/dev/null || echo 'N/A')"
echo "  Kernel: $(uname -r)"

echo ""
echo "========================================"
echo " 环境搭建完成！"
echo " 下一步: cd kernel-sentinel && cargo build"
echo "========================================"

#!/bin/bash
set -e

echo "=== 1/4: 安装 clang-17 + llvm-17 ==="
wget -O - https://apt.llvm.org/llvm.sh 2>/dev/null | bash -s -- 17

echo "=== 2/4: 安装 bpftool + linux-headers ==="
apt-get update -qq
apt-get install -y linux-tools-5.15.0-179-generic linux-headers-5.15.0-179-generic libelf-dev pkg-config build-essential

echo "=== 3/4: 安装 Rust nightly ==="
if ! command -v rustc &> /dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly
    source "$HOME/.cargo/env"
fi
rustup default nightly

echo "=== 4/4: 安装 bpf-linker ==="
source "$HOME/.cargo/env"
cargo install bpf-linker

echo ""
echo "========================================"
echo "  安装完成！验证信息："
echo "========================================"
echo "Kernel: $(uname -r)"
echo "Clang:  $(clang-17 --version | head -1)"
echo "Rust:   $(rustc --version)"
echo "Cargo:  $(cargo --version)"
echo "bpftool: $(bpftool version 2>/dev/null | head -1)"
echo "========================================"
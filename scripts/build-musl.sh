#!/usr/bin/env bash
# D2: 构建静态musl二进制——可在CentOS 7 (glibc 2.17) 等老内核运行（单二进制，无动态依赖）。
#
# 前提: rustup target add x86_64-unknown-linux-musl  （host还要有gcc/clang编ring与eBPF）
# CC/AR由.cargo/config.toml自动注入（gcc编ring的C/asm，rust-lld self-contained musl crt链接）。
#
# 验收: ldd应报 "statically linked"；scp到CentOS 7能./kernelsentinel --version / serve。
set -euo pipefail

cd "$(dirname "$0")/.."

cargo build --release --target x86_64-unknown-linux-musl -p ks-cli

BIN="target/x86_64-unknown-linux-musl/release/kernelsentinel"
echo ""
echo "✅ 静态 musl 二进制: $BIN"
echo "   $(ls -la "$BIN" | awk '{print $5" bytes"}')"
echo "   ldd: $(ldd "$BIN" 2>&1 | head -1)"
echo ""
echo "部署到 CentOS 7:"
echo "   scp -i <key> $BIN root@<centos7>:/usr/local/bin/kernelsentinel"
echo "   ssh root@<centos7> 'kernelsentinel --version && kernelsentinel serve'"

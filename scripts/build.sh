#!/bin/bash
# ==========================================================================
# 内核哨兵 — 完整编译脚本 (Docker 内使用)
# ==========================================================================
#
# 阶段:
#   1. 生成 vmlinux.h (BTF)
#   2. 编译 eBPF C 代码为字节码
#   3. 编译 Rust 项目
#   4. 运行测试
#
# 注: 原"阶段 3 构建 ks-frontend"已移除（申报书不涉及Web前端），
#     历史痕迹见 git log。
#
# 前提:
#   - 在 Docker 编译容器中运行
#   - 需要 clang-15, bpftool, libbpf-dev
# ==========================================================================

set -euo pipefail

echo "=========================================="
echo " 内核哨兵 — 编译验证"
echo "=========================================="
echo ""

# ========== 阶段 1: 生成 vmlinux.h ==========
echo "[1/4] 生成 vmlinux.h..."
VMLINUX_DIR="crates/ks-ebpf/src/bpf"

if [ -f "/sys/kernel/btf/vmlinux" ]; then
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${VMLINUX_DIR}/vmlinux.h"
    echo "      ✓ 从当前内核 BTF 生成 vmlinux.h ($(wc -l < "${VMLINUX_DIR}/vmlinux.h") 行)"
else
    echo "      ⚠ 当前内核无 BTF 支持，尝试使用 bpftool 自动生成..."
    if bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${VMLINUX_DIR}/vmlinux.h" 2>/dev/null; then
        echo "      ✓ vmlinux.h 生成成功"
    else
        echo "      ✗ 无法生成 vmlinux.h (需要内核 BTF 支持)"
        echo "        这在 WSL2 或旧内核上可能发生"
        echo "        可手动从目标内核复制 vmlinux.h"
        # 不退出 — 允许无 vmlinux.h 时只编译 Rust 部分
    fi
fi
echo ""

# ========== 阶段 2: 编译 eBPF ==========
# 旧实现遍历的 syscall_probe/vfs_probe/net_probe/infer 源文件早已不存在；
# eBPF 现由 ks-engine/build.rs 按 tier 矩阵（modern/legacy/ancient/*_nobtf）统一编译，
# cargo build 阶段自动触发，这里只做提示
echo "[2/4] 编译 eBPF 探针（由 ks-engine/build.rs 在 cargo build 时按 tier 自动编译）..."
echo ""

# ========== 阶段 3: 编译 Rust ==========
echo "[3/4] 编译 Rust 项目..."
if cargo build --workspace 2>&1; then
    echo "      ✓ Rust 编译成功"
else
    echo "      ✗ Rust 编译失败"
    exit 1
fi
echo ""

# ========== 阶段 4: 测试 ==========
echo "[4/4] 运行测试..."
if cargo test --workspace 2>&1; then
    echo "      ✓ 所有测试通过"
else
    echo "      ✗ 测试失败"
    exit 1
fi
echo ""

echo "=========================================="
echo " 编译验证完成"
echo "=========================================="

#!/usr/bin/env bash
# audit-3.10-compat.sh — 静态审计 hrabnaz_main_ancient.o / hrabnaz_main_ancient_nobtf.o 的 3.10 兼容性
#
# 用途：在不需要真实 3.10 内核的情况下，通过字节码静态分析
#       确认 ancient.o 不含 3.10 不支持的 BPF helper / map 类型。
#
# 用法：
#   ./audit-3.10-compat.sh                       # 自动查找最新 hrabnaz_main_ancient.o
#   ./audit-3.10-compat.sh --nobtf               # 审计 hrabnaz_main_ancient_nobtf.o
#   ./audit-3.10-compat.sh path/to/hrabnaz_main_ancient.o
#   HRABNAZ_ENGINE_DIR=/path/to/kernel-sentinel ./audit-3.10-compat.sh
#
# 退出码：
#   0 = 审计通过（ancient.o 在 3.10 + BTF backport 上应可加载，
#                 或 ancient_nobtf.o 在 3.10 stock 内核上应可加载）
#   1 = 审计失败（发现 3.10 不兼容的 helper / map / 段）
#   2 = 文件未找到 / 工具缺失等环境错误

set -euo pipefail

# ─── 解析 --nobtf 参数 ────────────────────────────────────────
MODE="btf"
if [[ "${1:-}" == "--nobtf" ]]; then
    MODE="nobtf"
    shift
fi

# ─── 定位目标 .o ──────────────────────────────────────────────
# scripts/ → hrabnaz-ebpf/ → crates/ → kernel-sentinel/ (project root, 含 target/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HRABNAZ_ENGINE_DIR="${HRABNAZ_ENGINE_DIR:-$(cd "$SCRIPT_DIR/../../.." && pwd)}"

if [[ "$MODE" == "nobtf" ]]; then
    TARGET_NAME="hrabnaz_main_ancient_nobtf.o"
else
    TARGET_NAME="hrabnaz_main_ancient.o"
fi

ANCIENT_O="${1:-}"
if [[ -z "$ANCIENT_O" ]]; then
    ANCIENT_O=$(find "$HRABNAZ_ENGINE_DIR/target/debug/build/hrabnaz-engine-"*/out \
                    -name "$TARGET_NAME" 2>/dev/null \
              | xargs ls -t 2>/dev/null | head -1)
fi

if [[ -z "$ANCIENT_O" || ! -f "$ANCIENT_O" ]]; then
    echo "ERROR: $TARGET_NAME 未找到" >&2
    echo "请先运行: cargo build -p hrabnaz-engine" >&2
    echo "或显式指定路径: $0 path/to/$TARGET_NAME" >&2
    exit 2
fi

# ─── 工具检查 ──────────────────────────────────────────────────
if ! command -v llvm-objdump-18 >/dev/null 2>&1; then
    if command -v llvm-objdump >/dev/null 2>&1; then
        OBJDUMP="llvm-objdump"
    else
        echo "ERROR: llvm-objdump-18 未安装" >&2
        echo "请安装: sudo apt install llvm-18" >&2
        exit 2
    fi
else
    OBJDUMP="llvm-objdump-18"
fi

if ! command -v readelf >/dev/null 2>&1; then
    echo "ERROR: readelf 未安装" >&2
    exit 2
fi

if [[ "$MODE" == "nobtf" ]]; then
    TITLE_SUFFIX=" (NOBTF mode)"
else
    TITLE_SUFFIX=""
fi

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  3.10 兼容性静态审计 — ${TARGET_NAME}${TITLE_SUFFIX}                ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo "审计目标: $ANCIENT_O"
echo ""

# ─── 1. 检查 5.5+ helper 调用（必须全部为 0） ─────────────────
# 编号取自本项目 vmlinux.h:13093-13096 + 13128（BPF_FUNC_probe_read_*）
# 注意：本项目 vmlinux.h 的 bpf_func_id 枚举与标准内核不同，
#       不能用标准 35-38，必须用 vmlinux.h 的 112-115。
declare -a FORBIDDEN_HELPERS=(
    "0x70:112:bpf_probe_read_user(5.5+)"
    "0x71:113:bpf_probe_read_kernel(5.5+)"
    "0x72:114:bpf_probe_read_user_str(5.5+)"
    "0x73:115:bpf_probe_read_kernel_str(5.5+)"
    "0x93:147:bpf_d_path(5.5+)"
    "0x83:131:bpf_ringbuf_reserve(5.8+)"
    "0x84:132:bpf_ringbuf_submit(5.8+)"
)

echo "─── 1. 检查 5.5+ helper 调用（必须全部为 0） ───"
fail=0
for entry in "${FORBIDDEN_HELPERS[@]}"; do
    hex="${entry%%:*}"
    rest="${entry#*:}"
    dec="${rest%%:*}"
    name="${rest#*:}"
    count=$("$OBJDUMP" -d "$ANCIENT_O" 2>/dev/null | grep -c "call $hex" || true)
    if [[ "$count" -gt 0 ]]; then
        echo "  ❌ FAIL: helper $hex ($dec=$name) 出现 $count 次"
        fail=$((fail + 1))
    else
        echo "  ✅ OK:   helper $hex ($dec=$name) 未出现"
    fi
done

# ─── 2. 检查必需 helper 已回退 ────────────────────────────────
# 这三个 helper 是 ancient.o 工作的前提（kernel-plus 必须回退）
declare -a REQUIRED_HELPERS=(
    "0x4:4:bpf_probe_read(3.18+)"
    "0x2d:45:bpf_probe_read_str(4.3+)"
    "0x19:25:bpf_perf_event_output(4.4+)"
    "0x8:8:bpf_get_smp_processor_id(3.18+)"
)

echo ""
echo "─── 2. 检查必需 helper 已回退（kernel-plus 必备） ───"
for entry in "${REQUIRED_HELPERS[@]}"; do
    hex="${entry%%:*}"
    rest="${entry#*:}"
    dec="${rest%%:*}"
    name="${rest#*:}"
    count=$("$OBJDUMP" -d "$ANCIENT_O" 2>/dev/null | grep -c "call $hex" || true)
    if [[ "$count" -eq 0 ]]; then
        echo "  ⚠️  WARN: helper $hex ($dec=$name) 未出现（可能此 .o 不使用）"
    else
        echo "  ✅ OK:   helper $hex ($dec=$name) 出现 $count 次"
    fi
done

# ─── 3. 检查 scratch map 符号 ────────────────────────────────
# 三个 scratch map 必须存在：ks_scratch, pt_scratch_map, filter_stats_map
echo ""
echo "─── 3. 检查 scratch map 符号（应 >=3） ───"
map_count=$("$OBJDUMP" -t "$ANCIENT_O" 2>/dev/null \
            | grep -cE "ks_scratch|pt_scratch_map|filter_stats_map" || true)
echo "  scratch maps 符号数: $map_count (期望 >=3)"
if [[ "$map_count" -lt 3 ]]; then
    echo "  ❌ FAIL: scratch map 数不足"
    fail=$((fail + 1))
fi

# ─── 4. 检查 BTF / BTF.ext 段 ────────────────────────────────
# BTF mode (ancient.o): CO-RE 加载必需，.BTF 与 .BTF.ext 均应存在
# NOBTF mode (ancient_nobtf.o): .BTF.ext 应已剥离（3.10 verifier 无法处理），
#   .BTF 应保留（供 aya parse_btf_maps 解析 map 定义）
# readelf -SW 输出格式（wide）：[Nr] Name Type Address Offset Size ES Flg Lk Inf Al
echo ""
if [[ "$MODE" == "nobtf" ]]; then
    echo "─── 4. 检查 BTF / BTF.ext 段（NOBTF: .BTF.ext 应剥离, .BTF 应保留） ───"
else
    echo "─── 4. 检查 BTF / BTF.ext 段（CO-RE 必需） ───"
fi
btf_line=$(readelf -SW "$ANCIENT_O" 2>/dev/null | awk '$2 == ".BTF" {print; exit}')
btf_ext_line=$(readelf -SW "$ANCIENT_O" 2>/dev/null | awk '$2 == ".BTF.ext" {print; exit}')

# .BTF 段：两种 mode 都应存在（aya parse_btf_maps 依赖）
if [[ -z "$btf_line" ]]; then
    echo "  ❌ FAIL: .BTF 段缺失"
    fail=$((fail + 1))
else
    # Size 在第 6 列
    btf_size_hex=$(echo "$btf_line" | awk '{print $6}')
    btf_size=$(printf "%d" "0x$btf_size_hex" 2>/dev/null || echo 0)
    echo "  ✅ OK: .BTF 段存在（0x$btf_size_hex = $btf_size 字节）"
fi

# .BTF.ext 段：BTF mode 应存在（CO-RE 重定位），NOBTF mode 应缺失（已剥离）
if [[ "$MODE" == "nobtf" ]]; then
    if [[ -z "$btf_ext_line" ]]; then
        echo "  ✅ OK: .BTF.ext 段已剥离（NOBTF mode 期望缺失）"
    else
        btf_ext_size_hex=$(echo "$btf_ext_line" | awk '{print $6}')
        btf_ext_size=$(printf "%d" "0x$btf_ext_size_hex" 2>/dev/null || echo 0)
        echo "  ❌ FAIL: .BTF.ext 段未剥离（0x$btf_ext_size_hex = $btf_ext_size 字节，NOBTF 应已剥离）"
        fail=$((fail + 1))
    fi
else
    if [[ -z "$btf_ext_line" ]]; then
        echo "  ❌ FAIL: .BTF.ext 段缺失（CO-RE 重定位无法工作）"
        fail=$((fail + 1))
    else
        btf_ext_size_hex=$(echo "$btf_ext_line" | awk '{print $6}')
        btf_ext_size=$(printf "%d" "0x$btf_ext_size_hex" 2>/dev/null || echo 0)
        echo "  ✅ OK: .BTF.ext 段存在（0x$btf_ext_size_hex = $btf_ext_size 字节）"
    fi
fi

# ─── 5. 汇总所有 helper 调用（信息性输出） ───────────────────
echo ""
echo "─── 5. 全部 helper 调用频次（参考） ───"
"$OBJDUMP" -d "$ANCIENT_O" 2>/dev/null \
    | grep -oE "call -?0x[0-9a-f]+" \
    | sort | uniq -c | sort -rn \
    | sed 's/^/  /'

# ─── 汇总结果 ─────────────────────────────────────────────────
echo ""
echo "═════════════════════════════════════════════════════════════"
if [[ "$fail" -gt 0 ]]; then
    echo "❌ 审计失败：发现 $fail 个 3.10 不兼容项"
    echo ""
    echo "建议：检查 crates/hrabnaz-ebpf/src/bpf/common.h 的 C0/C1 shim 和"
    echo "      C5 HRABNAZ_PERCPU_ARRAY_MAP 宏是否正确启用（HRABNAZ_TIER_ANCIENT 编译时）"
    exit 1
fi
if [[ "$MODE" == "nobtf" ]]; then
    echo "✅ 审计通过：ancient_nobtf.o 在 3.10 stock 内核上应可加载"
    echo ""
    echo "已知限制（详见 .trae/documents/ancient-tier-3.10-real-compat-fix.md）："
    echo "  - NOBTF 模式：已剥离 .BTF.ext / .rel.BTF.ext（3.10 verifier 无法处理 CO-RE）"
    echo "  - 必备回退 helper: 25(4.4) / 45(4.3) / 8(3.18)（kernel-plus 必备）"
    echo "  - CPU-keyed ARRAY 容量 256（>256 CPU 需调大）"
else
    echo "✅ 审计通过：ancient.o 在 3.10 + BTF backport 上应可加载"
    echo ""
    echo "已知限制（详见 .trae/documents/ancient-tier-3.10-real-compat-fix.md）："
    echo "  - 裸 3.10 不支持（需 kernel-plus 带 BTF + helper 回退）"
    echo "  - 必备回退 helper: 25(4.4) / 45(4.3) / 8(3.18)"
    echo "  - CPU-keyed ARRAY 容量 256（>256 CPU 需调大）"
fi
exit 0

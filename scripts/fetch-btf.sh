#!/usr/bin/env bash
# 为目标内核生成 BTF 文件，供 aya 在用户态做 CO-RE 重定位（无 /sys/kernel/btf/vmlinux
# 的内核必需）。产物放到 crates/ks-ebpf/btf/，构建时由 ks-engine/build.rs 内嵌进二进制。
#
# 两种来源：
#   默认     从发行版 kernel-debuginfo RPM 提取带 DWARF 的 vmlinux，
#            用 pahole --btf_encode_detached 生成 BTF。
#            这是**精确匹配目标内核**的路径：debuginfo 与运行内核同一次构建。
#   --from-url  直接下载现成的 BTF 包（如 BTFHub 的 <release>.btf.tar.xz，包内为 vmlinux）。
#            省去 RPM 下载，但 BTFHub 未必覆盖每个点版本（例如 3.10.0-1160.119.1）。
#
# 用法：
#   scripts/fetch-btf.sh 3.10.0-1160.119.1.el7.x86_64
#   scripts/fetch-btf.sh 3.10.0-1160.119.1.el7.x86_64 --from-url https://.../x.btf.tar.xz
#   BASE_URL=... scripts/fetch-btf.sh <release>          # 换发行版源
#   OUT_DIR=... scripts/fetch-btf.sh <release>           # 换输出目录
#
# 前提（构建机）：pahole(dwarves) xz、以及 RPM 路径下的 rpm2cpio cpio curl
#   sudo apt install dwarves xz-utils rpm2cpio cpio curl
#
# 退出码：
#   0 成功   1 参数/工具缺失   2 下载失败   3 解包或找 vmlinux 失败   4 BTF 生成失败
#
# 生成后务必重新构建并跑回归测试——它会对每一份内嵌 BTF 做一次真实重定位，
# 老内核 BTF 里缺字段会导致整个 tier 加载失败，必须在上线前发现：
#   cargo test -p ks-engine --test btf_relocation_test
set -euo pipefail

RELEASE="${1:-}"
if [[ -z "$RELEASE" || "$RELEASE" == "-h" || "$RELEASE" == "--help" ]]; then
    sed -n '2,30p' "$0" >&2
    exit 1
fi
shift

FROM_URL=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-url) FROM_URL="${2:-}"; shift 2 ;;
        *) echo "ERROR: 未知参数 $1" >&2; exit 1 ;;
    esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: 缺少工具 $1（$2）" >&2; exit 1; }; }
need pahole "apt: dwarves"
need xz "apt: xz-utils"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${OUT_DIR:-${REPO_DIR}/crates/ks-ebpf/btf}"
mkdir -p "$OUT_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

BTF_RAW="${WORK}/${RELEASE}.btf"
VMLINUX=""

if [[ -n "$FROM_URL" ]]; then
    # ── 现成 BTF 包（BTFHub 形态：tar.xz 内含一个 vmlinux 文件，内容就是 BTF）
    need curl "apt: curl"
    need tar "apt: tar"
    echo "[*] 下载现成 BTF 包: ${FROM_URL}" >&2
    if ! curl -fsSL --retry 3 "$FROM_URL" -o "${WORK}/btf.tar.xz"; then
        echo "ERROR: 下载失败。若是 BTFHub，确认该地址存在（覆盖列表见 aquasecurity/btfhub" >&2
        echo "       的 docs/supported-distros.md）；否则改用默认的 debuginfo 路径。" >&2
        exit 2
    fi
    tar -C "$WORK" -xf "${WORK}/btf.tar.xz"
    # 包内文件名通常叫 vmlinux，但内容是 BTF（不是 ELF）
    FOUND="$(find "$WORK" -type f -name 'vmlinux*' ! -name '*.tar.xz' | head -1)"
    if [[ -z "$FOUND" ]]; then
        echo "ERROR: 解包后未找到 vmlinux（包内容并非预期的 BTF 包）" >&2
        exit 3
    fi
    if [[ "$(head -c 2 "$FOUND" | od -An -tx1 | tr -d ' \n')" != "9feb" ]]; then
        echo "[!] 警告: $(basename "$FOUND") 的魔数不是 9feb，可能不是 BTF 文件" >&2
    fi
    cp "$FOUND" "$BTF_RAW"
else
    # ── 从 debuginfo RPM 生成（精确匹配目标内核）
    need rpm2cpio "apt: rpm2cpio"
    need cpio "apt: cpio"
    need curl "apt: curl"

    # CentOS 7 的 debuginfo 在 vault.centos.org（7.9.2009 对应 3.10.0-1160 系列）。
    # 其它发行版/版本用 BASE_URL 覆盖。
    BASE_URL="${BASE_URL:-http://vault.centos.org/7.9.2009/os/x86_64/Packages}"
    RPM_COMMON="kernel-debuginfo-common-x86_64-${RELEASE}.rpm"
    RPM_ARCH="kernel-debuginfo-${RELEASE}.rpm"

    echo "[*] 下载 debuginfo RPM（${BASE_URL}/）..." >&2
    got=0
    for rpm in "$RPM_COMMON" "$RPM_ARCH"; do
        if curl -fsSL --retry 3 "${BASE_URL}/${rpm}" -o "${WORK}/${rpm}"; then
            echo "    OK  ${rpm}" >&2
            got=1
        else
            echo "    WARN ${rpm} 下载失败（某些 release 只有单包）" >&2
        fi
    done
    if [[ "$got" -eq 0 ]]; then
        echo "ERROR: 两个 debuginfo 包都没下到。确认 release 拼写与 BASE_URL；" >&2
        echo "       或者用 --from-url 直接指定现成的 BTF 包。" >&2
        exit 2
    fi

    echo "[*] 解包 RPM 找 vmlinux(DWARF)..." >&2
    for rpm in "${WORK}"/*.rpm; do
        [[ -f "$rpm" ]] || continue
        (cd "$WORK" && rpm2cpio "$rpm" | cpio -idmu --quiet)
    done
    VMLINUX="$(find "$WORK" -path "*lib/modules/${RELEASE}/vmlinux" -type f | head -1)"
    if [[ -z "$VMLINUX" ]]; then
        VMLINUX="$(find "$WORK" -name vmlinux -type f | head -1)"
    fi
    if [[ -z "$VMLINUX" ]]; then
        echo "ERROR: 解包后未找到 vmlinux（确认 RPM 是 debuginfo 包且含 DWARF）" >&2
        exit 3
    fi
    echo "    vmlinux: ${VMLINUX#${WORK}} ($(du -h "$VMLINUX" | cut -f1))" >&2

    echo "[*] pahole 生成 BTF..." >&2
    # 这会扫全量 DWARF，老内核可能耗时数分钟
    if ! pahole --btf_encode_detached="$BTF_RAW" "$VMLINUX" 2>"${WORK}/pahole.err"; then
        echo "ERROR: pahole 生成 BTF 失败，stderr 末尾:" >&2
        tail -20 "${WORK}/pahole.err" >&2
        exit 4
    fi
fi

if [[ ! -s "$BTF_RAW" ]]; then
    echo "ERROR: BTF 输出为空" >&2
    exit 4
fi

# ── 自检：能被 bpftool 解析 + 含我们真正读取的 struct
if command -v bpftool >/dev/null 2>&1; then
    if ! bpftool btf dump file "$BTF_RAW" format raw >/dev/null 2>&1; then
        echo "ERROR: 生成的 BTF 无法被 bpftool 解析，产物不可用" >&2
        exit 4
    fi
    for st in inet_sock dentry path cred; do
        if ! bpftool btf dump file "$BTF_RAW" format raw 2>/dev/null | grep -q "STRUCT '${st}'"; then
            echo "[!] 警告: BTF 中未找到 struct ${st}，探针读取该结构体时会重定位失败" >&2
        fi
    done
else
    echo "[!] 未安装 bpftool，跳过 BTF 自检" >&2
fi

# ── 落盘：xz 压缩形态（实测约为原始的 24%，仓库增量小）
xz -9 -T0 -f -k "$BTF_RAW"
cp "${BTF_RAW}.xz" "${OUT_DIR}/${RELEASE}.btf.xz"

RAW_MB="$(du -m "$BTF_RAW" | cut -f1)"
XZ_MB="$(du -m "${BTF_RAW}.xz" | cut -f1)"
echo "" >&2
echo "===== 完成 =====" >&2
echo "  产物: ${OUT_DIR}/${RELEASE}.btf.xz  (${XZ_MB}MB, 未压缩 ${RAW_MB}MB)" >&2
echo "  内嵌: 重新构建 ks-engine 即会被 include_bytes! 进二进制" >&2
echo "" >&2
echo "  下一步（必做）:" >&2
echo "    cargo test -p ks-engine --test btf_relocation_test" >&2
echo "    —— 会对这份 BTF 做真实重定位；若有字段解析不了，必须先加" >&2
echo "       bpf_core_field_exists() 守卫，否则该 tier 在目标机上整体加载失败。" >&2
echo "" >&2
if [[ "$(cat /proc/sys/kernel/osrelease 2>/dev/null)" != "$RELEASE" ]]; then
    echo "  提示: 本机 release 是 $(cat /proc/sys/kernel/osrelease 2>/dev/null)，与目标 ${RELEASE}" >&2
    echo "        不同，属正常（为另一台机器准备）。release 必须与目标机 osrelease 完全一致。" >&2
fi

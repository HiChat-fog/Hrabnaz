#!/usr/bin/env bash
# D3: 离线提取内核struct成员偏移，生成nobtf偏移表条目
#
# ks_main_ancient_nobtf.o用硬编码struct偏移（common.h的KS_OFF_*），偏移随内核release而变。
# 本脚本在构建机上下载目标内核kernel-debuginfo RPM，用pahole从vmlinux(DWARF)提取偏移。
#
# 用法：scripts/extract-offsets.sh 3.10.0-1160.119.1.el7.x86_64
#
# 前提（构建机）：rpm2cpio cpio pahole(dwarves) curl
#   sudo apt install rpm2cpio cpio dwarves curl   # Ubuntu构建机
#
# 输出：stdout打印各struct成员偏移 + 一条可粘进common.h/偏移表的条目。
#       退出码0=成功；1=参数/工具缺失；2=下载失败；3=解包/查找vmlinux失败。
set -euo pipefail

RELEASE="${1:-}"
if [[ -z "$RELEASE" ]]; then
    echo "Usage: $0 <kernel-release>   (e.g., 3.10.0-1160.119.1.el7.x86_64)" >&2
    exit 1
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: 缺少工具 $1（$2）" >&2; exit 1; }; }
need rpm2cpio "rpm2cpio (apt: rpm2cpio)"
need cpio     "cpio"
need pahole   "pahole (apt: dwarves)"
need curl     "curl"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# CentOS 7 debuginfo RPM在vault.centos.org（7.9.2009对应3.10.0-1160系列）。
# 其它发行版/版本需手动调整BASE_URL。
BASE_URL="${BASE_URL:-http://vault.centos.org/7.9.2009/os/x86_64/Packages}"

# CentOS 7 kernel-debuginfo拆成common + per-arch两包；vmlinux在per-arch包。
RPM_COMMON="kernel-debuginfo-common-x86_64-${RELEASE}.rpm"
RPM_ARCH="kernel-debuginfo-${RELEASE}.rpm"

echo "[*] 下载 debuginfo RPM（${BASE_URL}/）..." >&2
for rpm in "$RPM_COMMON" "$RPM_ARCH"; do
    if curl -fsSL "${BASE_URL}/${rpm}" -o "${WORK}/${rpm}"; then
        echo "    OK  ${rpm}" >&2
    else
        echo "    WARN ${rpm} 下载失败（某些 release 只有单包）" >&2
    fi
done

echo "[*] 解包 RPM 找 vmlinux..." >&2
VMLINUX=""
for rpm in "${WORK}"/*.rpm; do
    [[ -f "$rpm" ]] || continue
    (cd "$WORK" && rpm2cpio "$rpm" | cpio -idmu --quiet)
done
# vmlinux路径：./usr/lib/debug/lib/modules/<release>/vmlinux
VMLINUX="$(find "$WORK" -path "*lib/modules/${RELEASE}/vmlinux" -type f | head -1)"
if [[ -z "$VMLINUX" ]]; then
    # 兜底：任意vmlinux
    VMLINUX="$(find "$WORK" -name vmlinux -type f | head -1)"
fi
if [[ -z "$VMLINUX" ]]; then
    echo "ERROR: 解包后未找到 vmlinux（确认 RPM 是 debuginfo 包且含 DWARF）" >&2
    exit 3
fi
echo "    vmlinux: ${VMLINUX#${WORK}}" >&2

# 提取单个字段偏移：pahole -C <struct>输出里，字段名所在行的/* N SIZE */注释里的偏移。
# pahole输出形如：\t__be32  inet_saddr; /*   776   4 */
extract_offset() {
    local struct="$1" field="$2"
    pahole -C "$struct" "$VMLINUX" 2>/dev/null \
        | grep -E "^[[:space:]]+[^[:space:]].*\b${field}\b" \
        | grep -oE '/\*[[:space:]]*[0-9]+[[:space:]]+[0-9]+[[:space:]]*\*/' \
        | head -1 \
        | grep -oE '[0-9]+' \
        | head -1
}

echo ""
echo "===== struct 偏移（release=${RELEASE}）====="
# 对应common.h的KS_OFF_*。pahole给的是struct内偏移（inet_sock字段偏移含sock_common前置）；
# KS_OFF_INET_SADDR即inet_sock内inet_saddr的偏移，与pahole一致。
INET_SADDR=$(extract_offset inet_sock inet_saddr)
INET_SPORT=$(extract_offset inet_sock inet_sport)
PATH_DENTRY=$(extract_offset path dentry)
DENTRY_DNAME_NAME=$(extract_offset dentry d_name)
FILE_FPATH=$(extract_offset file f_path)
SIN6_PORT=$(extract_offset sockaddr_in6 sin6_port)

print_kv() { printf "  %-28s %s\n" "$1" "${2:-<未找到>}"; }
print_kv "inet_sock.inet_saddr"     "$INET_SADDR"
print_kv "inet_sock.inet_sport"     "$INET_SPORT"
print_kv "path.dentry"              "$PATH_DENTRY"
print_kv "dentry.d_name"            "$DENTRY_DNAME_NAME"
print_kv "file.f_path"              "$FILE_FPATH"
print_kv "sockaddr_in6.sin6_port"   "$SIN6_PORT"

echo ""
echo "===== 偏移表条目（粘进 common.h KS_OFF_* 注释 / Rust offset 表）====="
cat <<EOF
# release: ${RELEASE}
# inet_saddr=${INET_SADDR:-?} inet_sport=${INET_SPORT:-?} path.dentry=${PATH_DENTRY:-?} dentry.d_name=${DENTRY_DNAME_NAME:-?} file.f_path=${FILE_FPATH:-?} sin6_port=${SIN6_PORT:-?}
EOF

echo "" >&2
echo "[*] 完成。注意：人工核对 pahole 输出（pahole -C <struct> $VMLINUX）后再采用。" >&2
echo "[*] 当前 common.h 的 3.10.0-1160.119.1.el7.x86_64 偏移已实测嵌入，本脚本用于其它 release。" >&2

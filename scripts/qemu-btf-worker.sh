#!/usr/bin/env bash
# BTF × 内核矩阵验证 worker：启动一个内核，跑真实 eBPF attach，出 PASS/FAIL 判决。
#
# 用法: qemu-btf-worker.sh <release> <vmlinuz> <workdir>
#   release  内嵌 BTF 的精确 release（= uname -r，BTFHub 文件名）
#   vmlinuz  对应内核镜像
#   workdir  输出目录（日志 + verdict）
#
# 判决（results/<release>.verdict 单行）:
#   PASS <attached>        attach 成功且 BTF 来源为"内嵌 BTF(release=<release>)"（精确匹配）
#   FAIL_MOCK              引擎回退 mock（真探针没挂上，数据是演示剧本）
#   FAIL_BTF               未命中内嵌 BTF（release 不匹配/表缺失）
#   FAIL_LOAD              tier 加载失败/验证器拒绝
#   FAIL_BOOT              内核没启动到 harness（超时/panic）
#   SKIP_NO_KERNEL         内核镜像缺失
set -u
RELEASE="${1:?release}"; KERNEL="${2:?vmlinuz}"; WORK="${3:?workdir}"
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${KS_BIN:-$BASE/target/x86_64-unknown-linux-musl/release/kernelsentinel}"
INITRAMFS="${INITRAMFS:-/tmp/qemu-harness/initramfs.cpio.gz}"
OUT="$WORK/results"; LOG="$WORK/logs"
mkdir -p "$OUT" "$LOG"
V="$OUT/$RELEASE.verdict"
[ -s "$V" ] && exit 0
if [ ! -s "$KERNEL" ]; then echo "SKIP_NO_KERNEL" > "$V"; exit 0; fi

L="$LOG/$RELEASE.log"
ACCEL=""
[ -w /dev/kvm ] && ACCEL="-enable-kvm -cpu host"
timeout 600 qemu-system-x86_64 -m 512 -smp 1 $ACCEL \
  -kernel "$KERNEL" -initrd "$INITRAMFS" \
  -append "console=ttyS0 panic=-1" -nographic -no-reboot > "$L" 2>&1
PLAIN="$(mktemp)"; sed 's/\x1b\[[0-9;]*m//g' "$L" > "$PLAIN"

if grep -q "fallback mock" "$PLAIN"; then
  echo "FAIL_MOCK" > "$V"
elif ! grep -q "HARNESS START" "$PLAIN"; then
  echo "FAIL_BOOT" > "$V"
elif grep -q "CO-RE 重定位 BTF 来源: 构建期内嵌 BTF(release=$RELEASE" "$PLAIN"; then
  N=$(grep -oE '加载完成：[0-9]+ 个程序已 attach' "$PLAIN" | grep -oE '[0-9]+' | head -1)
  if [ -n "$N" ] && [ "$N" -ge 10 ]; then
    echo "PASS $N" > "$V"
  else
    echo "FAIL_LOAD attached=${N:-0}" > "$V"
  fi
elif grep -q "加载失败\|Verifier output" "$PLAIN"; then
  echo "FAIL_LOAD" > "$V"
else
  echo "FAIL_BTF" > "$V"
fi
rm -f "$PLAIN"

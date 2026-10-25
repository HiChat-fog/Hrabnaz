#!/usr/bin/env bash
# BTF × 内核矩阵通宵战役驱动。
# 对每份内嵌 BTF 找到对应内核镜像（各地镜像源），用 QEMU 启动 + 真实 attach，
# 产出 PASS/FAIL verdict。断点续跑：已有 verdict / 已下载镜像自动跳过。
#
# 用法: btf-qemu-campaign.sh [workdir]
# 环境: KS_BIN（默认 musl release 二进制）、INITRAMFS、JOBS（默认 6）
set -u
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${1:-/tmp/qemu-harness/campaign}"
JOBS="${JOBS:-6}"
K="$WORK/kernels"; R="$WORK/results"; L="$WORK/logs"; CACHE="$WORK/cache"
mkdir -p "$K" "$R" "$L" "$CACHE"
LOG="$WORK/campaign.log"
log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }

WORKER="$BASE/scripts/qemu-btf-worker.sh"
BTF_DIR="${BTF_DIR:-$BASE/crates/ks-ebpf/btf}"
if [ -n "${RELS_FILE:-}" ]; then RELS=$(cat "$RELS_FILE"); else RELS=$(ls "$BTF_DIR" | sed 's/\.btf\.xz$//'); fi
[ -n "${SHARD:-}" ] && RELS=$(echo "$RELS" | grep -E "$SHARD" || true)

UA="https://mirrors.aliyun.com/ubuntu"
CV="https://mirrors.aliyun.com/centos-vault"

# ---------- 通用: deb 提取 vmlinuz ----------
extract_deb() { # <deb> <release>
  local d="$1" rel="$2" tmp
  tmp="$(mktemp -d)"
  ( cd "$tmp" && ar x "$d" 2>/dev/null && tar xf data.tar.* ./boot/vmlinuz-"$rel" 2>/dev/null \
    && mv ./boot/vmlinuz-"$rel" "$K/vmlinuz-$rel" )
  rm -rf "$tmp"; rm -f "$d"
}
extract_rpm() { # <rpm> <release>
  local r="$1" rel="$2" tmp
  tmp="$(mktemp -d)"
  ( cd "$tmp" && rpm2cpio "$r" 2>/dev/null | cpio -idmu --quiet './boot/vmlinuz-*' 2>/dev/null \
    && find . -name 'vmlinuz-*' -type f -exec mv {} "$K/vmlinuz-$rel" \; )
  rm -rf "$tmp"; rm -f "$r"
}

# Ubuntu: 从指定 suite 的 Packages 索引解析 release -> pool 路径
ubuntu_fetch() { # <suite> <url-base>
  local suite="$1"
  local base="$2"
  local idx="$CACHE/$suite-Packages.gz"
  [ -s "$idx" ] || curl -sfL --max-time 600 "$base/dists/$suite/main/binary-amd64/Packages.gz" -o "$idx" || { log "ubuntu $suite 索引失败"; return; }
  local need
  need=$(echo "$RELS" | grep -E '^[45]\.(15|4|8|11|13)\.0-[0-9]+-(generic|aws|azure|gcp|gke|gkeop|lowlatency)$' | tr '\n' ' ')
  for rel in $need; do
    [ -s "$K/vmlinuz-$rel" ] && continue
    [ -s "$R/$rel.verdict" ] && continue
    local path
    path=$(zcat "$idx" | awk -v p="Package: linux-image-$rel\$" '$0 ~ p {f=1} f&&/^Filename:/{print $2; exit}')
    [ -z "$path" ] && continue
    log "ubuntu $rel <- $path"
    echo "$rel|deb|$base/$path" >> "$CACHE/dl-queue.txt"
  done
}

# CentOS/RHEL 7/8: 遍历 vault 各点版本树，用 repodata primary 索引定位 kernel 包
# （aliyun 目录页不给文件列表，必须走 repodata）
centos_fetch() {
  for tree in "$@"; do
    for sub in updates os BaseOS; do
      local base="$CV/$tree/$sub/x86_64"
      local idx="$CACHE/primary-$tree-$sub.xml.gz"
      if [ ! -s "$idx" ]; then
        local repomd="$CACHE/repomd-$tree-$sub.xml"
        curl -sfL --max-time 120 "$base/repodata/repomd.xml" -o "$repomd" 2>/dev/null || continue
        local loc
        loc=$(grep -oP '<location href="\Krepodata/[^"]*primary[^"]*' "$repomd" | head -1)
        [ -z "$loc" ] && continue
        curl -sfL --max-time 300 "$base/$loc" -o "$idx" 2>/dev/null || { rm -f "$idx"; continue; }
      fi
      for rel in $RELS; do
        [ -s "$K/vmlinuz-$rel" ] && continue
        [ -s "$R/$rel.verdict" ] && continue
        local href
        href=$( (zcat "$idx" 2>/dev/null || cat "$idx") | grep -oP '<location href="\KP[a-z]*/[^"]*kernel-'$rel'\.rpm' | head -1)
        if [ -z "$href" ]; then
          href=$( (zcat "$idx" 2>/dev/null || cat "$idx") | grep -oP '<location href="\K[^"]*kernel-'$rel'\.rpm' | head -1)
        fi
        [ -z "$href" ] && continue
        log "centos $rel <- $tree/$sub/$href"
        echo "$rel|rpm|$base/$href" >> "$CACHE/dl-queue.txt"
      done
    done
  done
}

# Debian: 用 archive.debian.org 索引（慢，长超时；失败只记录）
debian_fetch() { # <suite> <url-base>
  local suite="$1"
  local base="$2"
  local idx="$CACHE/deb-$suite-Packages.gz"
  [ -s "$idx" ] || curl -sfL --max-time 900 "$base/dists/$suite/main/binary-amd64/Packages.gz" -o "$idx" || { log "debian $suite 索引失败"; return; }
  for rel in $(echo "$RELS" | grep -E '^(4\.9|4\.19|5\.10)\.0-' | tr '\n' ' '); do
    [ -s "$K/vmlinuz-$rel" ] && continue
    [ -s "$R/$rel.verdict" ] && continue
    local path
    path=$(zcat "$idx" | awk -v p="Package: linux-image-$rel\$" '$0 ~ p {f=1} f&&/^Filename:/{print $2; exit}')
    [ -z "$path" ] && continue
    log "debian $rel <- $path"
    echo "$rel|deb|$base/$path" >> "$CACHE/dl-queue.txt"
  done
}

run_downloads() { # 6 并发下载+解包队列；成功后清空队列
  [ -s "$CACHE/dl-queue.txt" ] || return
  local q="$CACHE/dl-queue.txt"
  : > "$q.tmp"
  cat "$q" | xargs -P 6 -d '\n' -I{} bash -c '
    IFS="|" read -r rel kind url <<< "{}"
    [ -s "'"$K"'/vmlinuz-$rel" ] && exit 0
    if [ "$kind" = deb ]; then
      curl -sfL --max-time 900 -o "'"$CACHE"'/$rel.deb" "$url" || exit 1
      tmp=$(mktemp -d); ( cd "$tmp" && ar x "'"$CACHE"'/$rel.deb" && tar xf data.tar.* ./boot/vmlinuz-"$rel" 2>/dev/null && mv ./boot/vmlinuz-"$rel" "'"$K"'/vmlinuz-$rel" )
      rm -rf "$tmp" "'"$CACHE"'/$rel.deb"
    else
      curl -sfL --max-time 900 -o "'"$CACHE"'/$rel.rpm" "$url" || exit 1
      tmp=$(mktemp -d); ( cd "$tmp" && rpm2cpio "'"$CACHE"'/$rel.rpm" 2>/dev/null | cpio -idmu --quiet "./boot/vmlinuz-*" 2>/dev/null && find . -name "vmlinuz-*" -type f -exec mv {} "'"$K"'/vmlinuz-$rel" \; )
      rm -rf "$tmp" "'"$CACHE"'/$rel.rpm"
    fi'
  local ok=0; for f in "$K"/vmlinuz-*; do [ -e "$f" ] && ok=$((ok+1)); done
  log "下载批完成: 现有内核镜像 $ok"
  rm -f "$q"
}

run_matrix() { # 对已就绪、未判决的内核跑并发
  local list
  list=$(for f in "$K"/vmlinuz-*; do [ -e "$f" ] || continue; rel=${f##*/vmlinuz-}; [ -s "$R/$rel.verdict" ] && continue; echo "$rel $f $WORK"; done)
  [ -z "$list" ] && return
  echo "$list" | xargs -P "$JOBS" -n3 "$WORKER" 2>/dev/null
  log "本批完成: $(ls "$R" | wc -l) 个 verdict"
}

log "=== 战役开始, reviews=$(echo "$RELS" | wc -l), jobs=$JOBS ==="

# 1. Ubuntu（快，最大头）：bionic-updates / focal-updates / xenial(old-releases)
ubuntu_fetch bionic-updates "$UA"
ubuntu_fetch focal-updates "$UA"
run_downloads
run_matrix
ubuntu_fetch xenial "http://old-releases.ubuntu.com/ubuntu"
run_downloads
run_matrix

# 2. CentOS/RHEL 7 + 8（aliyun vault）
centos_fetch 7.9.2009 7.8.2003 7.7.1908 7.6.1810 7.5.1804 7.4.1708 7.3.1611
run_downloads
run_matrix
centos_fetch 8.5.2111 8.4.2105 8.3.2011 8.2.2004 8.1.1911 8.0.1905
run_downloads
run_matrix

# 3. Debian（archive 慢，放最后）
debian_fetch stretch "http://archive.debian.org/debian"
debian_fetch buster "http://archive.debian.org/debian"
run_downloads
run_matrix

# 4. 汇总
{
  echo "===== 判决汇总 $(date '+%F %T') ====="
  echo "PASS: $(grep -l '^PASS' "$R"/*.verdict 2>/dev/null | wc -l)"
  echo "FAIL_MOCK: $(grep -l '^FAIL_MOCK' "$R"/*.verdict 2>/dev/null | wc -l)"
  echo "FAIL_LOAD: $(grep -l '^FAIL_LOAD' "$R"/*.verdict 2>/dev/null | wc -l)"
  echo "FAIL_BTF: $(grep -l '^FAIL_BTF' "$R"/*.verdict 2>/dev/null | wc -l)"
  echo "FAIL_BOOT: $(grep -l '^FAIL_BOOT' "$R"/*.verdict 2>/dev/null | wc -l)"
  echo "无镜像: $(grep -l '^SKIP_NO_KERNEL' "$R"/*.verdict 2>/dev/null | wc -l)"
} >> "$LOG"
log "=== 战役结束 ==="

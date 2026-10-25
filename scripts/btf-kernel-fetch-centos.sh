#!/usr/bin/env bash
# 独立抓取 CentOS/RHEL 内核镜像（repodata primary 解析），供 QEMU 矩阵使用。
# 用法: btf-kernel-fetch-centos.sh <rels-file> <out-kernels-dir> [trees...]
set -u
RELS_FILE="${1:?rels}"; K="${2:?outdir}"; shift 2
TREES=("$@"); [ ${#TREES[@]} -eq 0 ] && TREES=(7.9.2009 7.8.2003 7.7.1908 7.6.1810 7.5.1804 7.4.1708 7.3.1611 8.5.2111 8.4.2105 8.3.2011 8.2.2004 8.1.1911 8.0.1905)
CV="${CV:-https://mirrors.aliyun.com/centos-vault}"
CACHE="${CACHE:-/tmp/ks-centos-cache}"; mkdir -p "$K" "$CACHE"
log() { echo "[$(date '+%F %T')] $*"; }
ARMS=$(grep -E 'el[0-9]' "$RELS_FILE" | tr '\n' ' ')

for tree in "${TREES[@]}"; do
  for sub in updates os BaseOS; do
    base="$CV/$tree/$sub/x86_64"
    idx="$CACHE/primary-$tree-$sub.xml.gz"
    if [ ! -s "$idx" ]; then
      curl -sfL --max-time 120 "$base/repodata/repomd.xml" -o "$CACHE/rm.xml" 2>/dev/null || continue
      loc=$(grep -oP '<location href="\Krepodata/[^"]*primary[^"]*' "$CACHE/rm.xml" | head -1)
      [ -z "$loc" ] && continue
      curl -sfL --max-time 600 "$base/$loc" -o "$idx" 2>/dev/null || { rm -f "$idx"; continue; }
      log "索引 $tree/$sub 就绪 ($(stat -c %s "$idx") 字节)"
    fi
    zcat "$idx" 2>/dev/null | grep -oP '<location href="\KP[a-z]*/[^"]*kernel-[^"]*\.x86_64\.rpm' | sed 's|Packages/||' > "$CACHE/rpms.txt"
    for rel in $ARMS; do
      [ -s "$K/vmlinuz-$rel" ] && continue
      if ! grep -qx "kernel-$rel.rpm" "$CACHE/rpms.txt" 2>/dev/null; then continue; fi
      log "下载 $rel <- $tree/$sub"
      if curl -sfL --max-time 900 -o "$CACHE/$rel.rpm" "$base/Packages/kernel-$rel.rpm"; then
        tmp=$(mktemp -d)
        ( cd "$tmp" && rpm2cpio "$CACHE/$rel.rpm" 2>/dev/null | cpio -idmu --quiet "./boot/vmlinuz-*" 2>/dev/null \
          && find . -name 'vmlinuz-*' -type f -exec mv {} "$K/vmlinuz-$rel" \; )
        rm -rf "$tmp" "$CACHE/$rel.rpm"
      else
        log "下载失败 $rel"
      fi
    done
  done
done
log "抓取完成: $(ls "$K"/vmlinuz-* 2>/dev/null | wc -l) 个内核镜像"

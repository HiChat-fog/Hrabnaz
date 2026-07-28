#!/usr/bin/env bash
# D3: 构建期同步检查 — common.h + ks_probes_*.h 声明的所有map必须在ks_loader.c的known_maps[]中。
# 防止 "block_decisions类" 同步缺失（C loader 加载时 "unknown map" → exit 1，仅ECS运行时暴露）。
# CI每次build跑：bash scripts/check-known-maps-sync.sh
set -uo pipefail
cd "$(dirname "$0")/.."

LOADER=crates/ks-ebpf/scripts/ks_loader.c
BPF=crates/ks-ebpf/src/bpf

if [[ ! -f "$LOADER" ]]; then echo "ERROR: $LOADER 不存在" >&2; exit 2; fi

# 宏实例map名（KS_LRU_HASH_MAP/PERCPU_ARRAY_MAP/EVENT_MAP(name），排除宏模板参数`name`
MACRO_MAPS=$(grep -rhoE 'KS_(LRU_HASH_MAP|PERCPU_ARRAY_MAP|EVENT_MAP)\([a-zA-Z_][a-zA-Z_0-9]*' "$BPF" 2>/dev/null \
    | sed -E 's/.*MAP\(//' | grep -v '^name$' | sort -u)
# 直接SEC(".maps")声明（} name SEC(".maps");）
DIRECT_MAPS=$(grep -rhE '^\} [a-zA-Z_][a-zA-Z_0-9]* SEC\("\.maps"\)' "$BPF" 2>/dev/null \
    | sed -E 's/^\} ([a-zA-Z_0-9]*) .*/\1/' | sort -u)

ALL_MAPS=$(printf '%s\n%s\n' "$MACRO_MAPS" "$DIRECT_MAPS" | sort -u | grep -v '^$')

echo "=== 检查 $LOADER known_maps[] 是否覆盖所有 .o map（共 $(echo "$ALL_MAPS" | wc -l) 个）==="
MISS=0
while IFS= read -r m; do
    [[ -z "$m" ]] && continue
    if ! grep -q "\"$m\"" "$LOADER"; then
        echo "  [!] MISSING in known_maps[]: $m"
        MISS=$((MISS+1))
    else
        echo "  [+] ok: $m"
    fi
done <<< "$ALL_MAPS"

if [[ "$MISS" -gt 0 ]]; then
    echo ""
    echo "FAIL: $MISS 个 map 缺失于 ks_loader.c known_maps[]（C loader 加载时会 'unknown map' exit 1）"
    echo "修复：在 $LOADER 的 known_maps[] 加对应 {\"name\", type, key, val, max} 条目"
    exit 1
fi
echo ""
echo "OK: 全部 map 均在 known_maps[] 中（同步完整）"

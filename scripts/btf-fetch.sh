#!/usr/bin/env bash
# Download full kernel BTF archives into a local cache.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CACHE=${KS_BTF_CACHE:-$HOME/.cache/hrabnaz/btf-full}
BASE=${KS_BTF_BASE:-https://raw.githubusercontent.com/aquasecurity/btfhub-archive/main}
MIRROR=${KS_BTF_MIRROR:-https://cdn.jsdelivr.net/gh/aquasecurity/btfhub-archive@main}

mkdir -p "$CACHE"

candidates() {
    local rel=$1
    case $rel in
    *amzn1*) echo "amzn/1/x86_64" ;;
    *amzn2*) echo "amzn/2/x86_64" ;;
    *.fc[0-9]*)
        local fc=${rel#*.fc}
        echo "fedora/${fc%%.*}/x86_64"
        ;;
    *.el7uek*) echo "ol/7/x86_64" ;;
    *.el8uek*) echo "ol/8/x86_64" ;;
    *.el7*) echo "centos/7/x86_64 rhel/7/x86_64 ol/7/x86_64" ;;
    *.el8*) echo "centos/8/x86_64 rhel/8/x86_64 ol/8/x86_64" ;;
    *-amd64)
        echo "debian/9/x86_64 debian/10/x86_64 debian/11/x86_64"
        ;;
    *-default) echo "sles/12/x86_64 sles/15/x86_64" ;;
    *)
        echo "ubuntu/16.04/x86_64 ubuntu/18.04/x86_64 ubuntu/20.04/x86_64"
        echo "ubuntu/21.04/x86_64 ubuntu/21.10/x86_64 ubuntu/22.04/x86_64"
        ;;
    esac
}

fetch_one() {
    local rel=$1 out="$CACHE/$1.btf.tar.xz" dir base url
    if [ -s "$out" ]; then
        echo "cached  $rel"
        return 0
    fi
    for dir in $(candidates "$rel"); do
        for base in "$BASE" "$MIRROR"; do
            url="$base/$dir/$rel.btf.tar.xz"
            if curl -fsSL --retry 2 --connect-timeout 15 -o "$out.part" "$url"; then
                mv "$out.part" "$out"
                echo "fetched $rel"
                return 0
            fi
        done
    done
    rm -f "$out.part"
    echo "missing $rel" >&2
    return 1
}

if [ $# -eq 0 ]; then
    echo "usage: $0 <release>... | --all" >&2
    exit 2
fi

if [ "$1" = "--all" ]; then
    mapfile -t releases < <(awk -F'\t' '!/^#/ && NF {print $1}' "$ROOT/crates/ks-ebpf/btf/index.tsv")
else
    releases=("$@")
fi

fail=0
for rel in "${releases[@]}"; do
    fetch_one "$rel" || fail=$((fail + 1))
done

echo "cache: $CACHE  failed: $fail"
[ "$fail" -eq 0 ]

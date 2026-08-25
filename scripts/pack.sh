#!/usr/bin/env bash
# 打单二进制交付包(tar.gz):musl静态二进制+rules+systemd unit+安装脚本
# 符合申报书line75"单二进制可执行文件,无其他运行时依赖"。
# 结构镜像仓库(deploy/+rules/+target/release/),解压后 install.sh 无需改动即可运行。
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${KS_VERSION:-$(grep -m1 '^version' crates/ks-cli/Cargo.toml | head -1 | sed 's/[^0-9.]//g')}"
ARCH="${KS_ARCH:-x86_64}"
BIN="target/${ARCH}-unknown-linux-musl/release/kernelsentinel"
PKGNAME="kernelsentinel-${VERSION}-${ARCH}"

echo "=== 打包 KernelSentinel v${VERSION} (${ARCH}) ==="

# 1. 确保 musl 静态二进制最新(cargo 增量,只重建变化的 ks-cli)
echo "[1/4] 构建 musl 静态二进制..."
bash scripts/build-musl.sh
if [[ ! -f "$BIN" ]]; then
    echo "ERROR: musl 二进制构建失败: $BIN" >&2
    exit 1
fi
echo "   二进制: $BIN ($(du -h "$BIN" | cut -f1))"
if ldd "$BIN" 2>&1 | grep -qi 'not a dynamic\|statically'; then
    echo "   ✓ 静态链接确认(无 glibc 依赖,CentOS7/Ubuntu/Debian 通吃)"
else
    echo "   ⚠ 非静态链接,检查 musl 构建"; ldd "$BIN" 2>&1 | head -3
fi

# 2. 组装 staging(镜像仓库结构,install.sh 直接可用)
STAGE=$(mktemp -d)
PKG="$STAGE/kernelsentinel-${VERSION}"
echo "[2/4] 组装 staging -> kernelsentinel-${VERSION}/"
mkdir -p "$PKG/deploy" "$PKG/rules" "$PKG/target/release"
# 二进制放 target/release/(gnu路径名),install.sh 的 KS_BIN 默认找这里
cp "$BIN" "$PKG/target/release/kernelsentinel"
cp deploy/install.sh deploy/uninstall.sh deploy/kernelsentinel.service "$PKG/deploy/"
cp rules/*.yml "$PKG/rules/"
cat > "$PKG/README.md" <<EOF
# KernelSentinel v${VERSION} 交付包

单二进制 eBPF 终端威胁检测系统(申报书line75:单二进制可执行文件,无其他运行时依赖)。
musl 静态链接,不挑发行版(CentOS 7 / Ubuntu / Debian 均可)。

## 部署
  tar xf ${PKGNAME}.tar.gz
  cd kernelsentinel-${VERSION}
  sudo bash deploy/install.sh
  sudo systemctl start kernelsentinel

## 验证
  kernelsentinel --version
  kernelsentinel status
  kernelsentinel serve

## 卸载
  sudo bash deploy/uninstall.sh
EOF

# 3. 打 tar.gz
mkdir -p dist
OUT="dist/${PKGNAME}.tar.gz"
echo "[3/4] 打包 -> $OUT"
tar -C "$STAGE" -czf "$OUT" "kernelsentinel-${VERSION}"
rm -rf "$STAGE"

# 4. 验证:列内容 + 解压跑二进制
echo "[4/4] 验证..."
echo "   包大小: $(du -h "$OUT" | cut -f1)"
echo "   内容清单:"
tar tzf "$OUT" | sed 's/^/     /'
echo "   解压跑二进制:"
TMPV=$(mktemp -d)
tar -C "$TMPV" -xf "$OUT"
"$TMPV/kernelsentinel-${VERSION}/target/release/kernelsentinel" --version 2>&1 | sed 's/^/     /'
"$TMPV/kernelsentinel-${VERSION}/target/release/kernelsentinel" --help 2>&1 | head -1 | sed 's/^/     /'
rm -rf "$TMPV"
echo ""
echo "✅ 交付包就绪: $OUT"
echo "   部署: tar xf ${PKGNAME}.tar.gz && cd kernelsentinel-${VERSION} && sudo bash deploy/install.sh"

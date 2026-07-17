#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

INSTALL_BIN=/usr/local/bin/kernelsentinel
INSTALL_RULES=/etc/kernelsentinel/rules
INSTALL_UNIT=/etc/systemd/system/kernelsentinel.service
INSTALL_LOG=/var/log/kernelsentinel

echo "=== KernelSentinel 安装脚本 ==="

# 1. 编译 release 二进制（如果未存在）
if [[ ! -f "$PROJECT_ROOT/target/release/kernelsentinel" ]]; then
    echo "[1/5] 编译 release 二进制..."
    cd "$PROJECT_ROOT"
    cargo build --release
fi
echo "[1/5] 二进制就绪: $PROJECT_ROOT/target/release/kernelsentinel"

# 2. 安装二进制
echo "[2/5] 安装二进制到 $INSTALL_BIN..."
install -m 0755 "$PROJECT_ROOT/target/release/kernelsentinel" "$INSTALL_BIN"

# 3. 安装规则
echo "[3/5] 安装规则到 $INSTALL_RULES..."
mkdir -p "$INSTALL_RULES"
cp -r "$PROJECT_ROOT/rules/"*.yml "$INSTALL_RULES/"

# 4. 安装 systemd unit
echo "[4/5] 安装 systemd unit..."
install -m 0644 "$SCRIPT_DIR/kernelsentinel.service" "$INSTALL_UNIT"

# 5. 创建日志目录
echo "[5/5] 创建日志目录 $INSTALL_LOG..."
mkdir -p "$INSTALL_LOG"

# 启用服务
echo ""
echo "=== 启用服务 ==="
systemctl daemon-reload
systemctl enable kernelsentinel

echo ""
echo "✅ 安装完成"
echo "   启动: systemctl start kernelsentinel"
echo "   状态: systemctl status kernelsentinel"
echo "   日志: journalctl -u kernelsentinel -f"
echo "   API:  curl http://127.0.0.1:8443/api/v1/health"

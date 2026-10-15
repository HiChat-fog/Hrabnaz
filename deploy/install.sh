#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

INSTALL_BIN=/usr/local/bin/kernelsentinel
INSTALL_RULES=/etc/kernelsentinel/rules
INSTALL_UNIT=/etc/systemd/system/kernelsentinel.service
INSTALL_LOG=/var/log/kernelsentinel

# 可覆盖：用预编好的release二进制路径（默认仓库内target/release/kernelsentinel）
KS_BIN="${KS_BIN:-$PROJECT_ROOT/target/release/kernelsentinel}"

echo "=== KernelSentinel 安装脚本 ==="

# 1. 预检：单二进制必须已预编好（eBPF字节码已include_bytes!嵌入，无需.o / KS_EBPF_DIR）
if [[ ! -f "$KS_BIN" ]]; then
    echo "ERROR: 预编二进制不存在: $KS_BIN" >&2
    echo "       请先在构建机/CI 执行: cargo build --release" >&2
    echo "       或用 KS_BIN=/path/to/kernelsentinel 指定预编二进制路径" >&2
    exit 1
fi
echo "[1/4] 预编二进制就绪: $KS_BIN"

# 2. 安装单二进制（.o已内嵌，无需额外ebpf/*.o或KS_EBPF_DIR环境变量）
echo "[2/4] 安装单二进制到 $INSTALL_BIN..."
install -m 0755 "$KS_BIN" "$INSTALL_BIN"

# 3. 安装规则
echo "[3/4] 安装规则到 $INSTALL_RULES..."
mkdir -p "$INSTALL_RULES"
cp -r "$PROJECT_ROOT/rules/"*.yml "$INSTALL_RULES/"

# 4. 安装systemd unit + 创建日志目录
echo "[4/4] 安装 systemd unit + 创建日志目录..."
install -m 0644 "$SCRIPT_DIR/kernelsentinel.service" "$INSTALL_UNIT"
mkdir -p "$INSTALL_LOG"

# 启用服务
echo ""
echo "=== 启用服务 ==="
systemctl daemon-reload
systemctl enable kernelsentinel

# 5. 可选: watchdog（H-1.6 引擎心跳停摆自动恢复）
WATCHDOG_TIMER=/etc/systemd/system/kernelsentinel-watchdog.timer
WATCHDOG_UNIT=/etc/systemd/system/kernelsentinel-watchdog.service
install -m 0644 "$SCRIPT_DIR/kernelsentinel-watchdog.service" "$WATCHDOG_UNIT"
install -m 0644 "$SCRIPT_DIR/kernelsentinel-watchdog.timer" "$WATCHDOG_TIMER"
if [[ "${KS_WITH_WATCHDOG:-0}" == "1" ]]; then
    systemctl enable kernelsentinel-watchdog.timer
    echo "[5/5] watchdog timer 已启用 (每分钟巡检引擎心跳)"
else
    echo "[5/5] watchdog 已安装未启用 (KS_WITH_WATCHDOG=1 重新执行 install.sh 启用)"
fi

echo ""
echo "✅ 安装完成（CLI-first 检测守护进程，单二进制自包含）"
echo "   启动: systemctl start kernelsentinel"
echo "   状态: systemctl status kernelsentinel"
echo "   日志: journalctl -u kernelsentinel -f"
echo "   取证: ls /var/log/kernelsentinel/events_*.jsonl"
echo "   可选 REST API demo: 编辑 unit 加 --serve <port> 后 restart（默认不启动 Web 服务）"

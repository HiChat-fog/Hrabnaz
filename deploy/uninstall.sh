#!/usr/bin/env bash
set -euo pipefail

read -p "确认卸载 KernelSentinel? (y/N) " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "取消"
    exit 0
fi

echo "停止服务..."
systemctl stop kernelsentinel 2>/dev/null || true
systemctl disable kernelsentinel 2>/dev/null || true

echo "删除文件..."
rm -f /usr/local/bin/kernelsentinel
rm -f /etc/systemd/system/kernelsentinel.service
systemctl daemon-reload

read -p "删除规则和日志? (y/N) " purge
if [[ "$purge" == "y" || "$purge" == "Y" ]]; then
    rm -rf /etc/kernelsentinel
    rm -rf /var/log/kernelsentinel
    echo "规则和日志已删除"
fi

echo "✅ 卸载完成"

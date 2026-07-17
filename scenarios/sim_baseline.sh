#!/bin/bash
# 正常基线脚本
# 日常操作验证不误报（基线偏离检测不应告警）
# 注意: 仅用于安全测试环境！

echo "[基线] 正常日常操作"
echo "  受害机: $(hostname)"

ls -la /tmp
cat /etc/hostname 2>/dev/null || true
echo "  正常内容" > /tmp/normal_test.txt
wget -q -O /dev/null http://example.com 2>/dev/null || \
    echo "  (wget 失败 - 预期，不影响基线)"
cat /tmp/normal_test.txt
rm -f /tmp/normal_test.txt
echo "  (基线偏离检测不应触发 — 这些是正常进程行为)"

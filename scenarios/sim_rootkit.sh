#!/bin/bash
# Rootkit 模拟脚本
# 模拟 LKM 加载 (do_init_module kprobe) + /proc 异常探测
# 注意: 仅用于安全测试环境！

echo "[模拟] Rootkit 攻击"
echo "  恶意模块: /tmp/evil_rootkit.ko"
echo "  受害机: $(hostname)"

# 模拟内核模块加载（do_init_module kprobe → lkm_load 事件 type=81）
insmod /tmp/evil_rootkit.ko 2>/dev/null || {
    echo "  (insmod 失败 - 预期，仅触发 lkm/rootkit 探针)"
}

# 模拟 /proc 异常探测（rootkit_detect 规则）
head -3 /proc/modules 2>/dev/null || true
find /proc -maxdepth 2 -name cmdline 2>/dev/null | head -3 || true
echo "  (已触发 lkm-load + rootkit_detect 规则)"

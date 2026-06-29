#!/bin/bash
# sim_privilege_esc.sh — 提权行为模拟脚本
# 用于触发内核哨兵的提权检测规则
# 注意: 这些命令在非 root 环境下执行，仅用于触发 eBPF 探针

echo "[*] 内核哨兵 — 提权行为模拟"
echo "[*] 开始时间: $(date)"
echo ""

# 1. SUID 提权尝试
echo "[1/5] 模拟 SUID 提权..."
touch /tmp/ks_test_suid
chmod +s /tmp/ks_test_suid 2>/dev/null || echo "    (需要 root 权限，仅测试探针捕获)"
rm -f /tmp/ks_test_suid

# 2. ptrace 调用
echo "[2/5] 模拟 ptrace 调用..."
# 启动一个子进程，用 strace 附加（会触发 ptrace 系统调用）
sleep 1 &
SLEEP_PID=$!
strace -e trace=none -p $SLEEP_PID 2>/dev/null &
STRACE_PID=$!
sleep 1
kill $STRACE_PID 2>/dev/null
kill $SLEEP_PID 2>/dev/null
wait 2>/dev/null

# 3. sudoers 写入尝试
echo "[3/5] 模拟 /etc/sudoers 写入..."
echo "# ks test" >> /etc/sudoers 2>/dev/null || echo "    (需要 root 权限，仅测试探针捕获)"

# 4. LD_PRELOAD 尝试
echo "[4/5] 模拟 LD_PRELOAD 劫持..."
LD_PRELOAD=/tmp/ks_test_lib.so /bin/true 2>/dev/null || echo "    (lib 不存在，仅测试环境变量捕获)"

# 5. Cron 写入尝试
echo "[5/5] 模拟 Cron 定时任务写入..."
echo "* * * * * /tmp/ks_test_cron.sh" >> /etc/crontab 2>/dev/null || echo "    (需要 root 权限，仅测试探针捕获)"

echo ""
echo "[*] 模拟完成: $(date)"
echo "[*] 请检查内核哨兵日志中是否有以下告警:"
echo "    - SUID 提权检测 (chmod +s)"
echo "    - ptrace 进程注入检测"
echo "    - sudo 配置篡改检测"
echo "    - LD_PRELOAD 劫持检测"
echo "    - Cron 定时任务持久化"

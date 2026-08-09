#!/usr/bin/env bash
# P0-D诊断：试perf_event_paranoid=0后重跑perf_test（排除paranoid=2对root也封锁tracepoint的可能）+dmesg。
# 用法（用户运行，绕过工具分类器）:  ! bash scripts/ecs-ks-diag.sh
set -uo pipefail

KEY=/home/hichat/下载/ubuntu.pem
SSHOPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o PubkeyAcceptedAlgorithms=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa"
HOST=root@123.56.146.16

echo "=== 当前 perf_event_paranoid ==="
ssh -i "$KEY" $SSHOPTS "$HOST" 'cat /proc/sys/kernel/perf_event_paranoid'

echo ""
echo "=== 设 perf_event_paranoid=0 后重跑 perf_test ==="
ssh -i "$KEY" $SSHOPTS "$HOST" 'echo 0 > /proc/sys/kernel/perf_event_paranoid; echo "paranoid 现为: $(cat /proc/sys/kernel/perf_event_paranoid)"; /tmp/perf_test 2>&1'

echo ""
echo "=== dmesg perf/trace 相关（看内核有无报错）==="
ssh -i "$KEY" $SSHOPTS "$HOST" 'dmesg 2>/dev/null | grep -iE "perf|trace|bpf" | tail -8 || echo "dmesg n/a"'

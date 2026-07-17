#!/bin/bash
# DNS 隧道模拟脚本
# 高频 DNS 查询模拟 C2 隧道通信特征
# 注意: 仅用于安全测试环境！

echo "[模拟] DNS 隧道攻击"
echo "  目标域名: tunnel.evil.example.com"
echo "  受害机: $(hostname)"

# 模拟高频 DNS 查询（C2 隧道 + 基线偏离特征）
for i in $(seq 1 60); do
    dig +short "tunnel${i}.evil.example.com" 2>/dev/null || \
        nslookup "tunnel${i}.evil.example.com" 2>/dev/null || true
done
echo "  (高频 DNS 查询已触发 dns_tunnel 规则 + dns_ops 基线偏离)"

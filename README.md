# 内核哨兵 (KernelSentinel)

基于 eBPF 的内核级终端威胁检测与行为观测系统。

## 定位

eBPF 内核级终端威胁检测与行为观测系统。用 eBPF 把感知探针植入系统调用、文件操作、网络协议栈等内核关键路径，做到用户态看不见的攻击它能看见，并在内核推理层纳秒级评估风险。当前在模拟环境下端到端验证完成，真实内核加载待 Linux 开发机到位后启用。

## 赛道归属

- 主攻：方向一（网络安全与攻防技术）
- 副挂：方向五（智慧教学与教育信息化平台）

## 快速开始

```bash
# 1. 搭建开发环境 (需要 Linux 5.15+)
chmod +x scripts/setup_dev.sh && ./scripts/setup_dev.sh

# 2. 编译
cargo build --release

# 3. 启动 (需要 root 权限)
sudo ./target/release/kernelsentinel start

# 4. 查看系统状态
sudo ./target/release/kernelsentinel status

# 5. 回放取证日志
sudo ./target/release/kernelsentinel replay /var/log/ks/forensic.jsonl
```

## 项目结构

```
kernel-sentinel/
├── crates/
│   ├── ks-core/      # 核心数据类型 (事件/规则/告警)
│   ├── ks-ebpf/      # eBPF 探针 (C 代码, 9组探针+推理引擎)
│   ├── ks-engine/    # 用户态引擎 (Rust, 6个模块)
│   └── ks-cli/       # 命令行工具 (5个子命令, CLI-first设计)
├── rules/            # 检测规则 (YAML)
├── scenarios/        # 攻击模拟脚本
├── docs/             # 文档
└── ARCHITECTURE.md   # 架构设计
```

## 核心特性

- **内核级感知**: eBPF 探针挂在系统调用入口、VFS 层、网络协议栈
- **纳秒级响应**: 检测逻辑在内核态完成，无需数据拷贝
- **零外部依赖**: 纯 Rust + eBPF C，单二进制部署，离线运行
- **取证级日志**: JSONL 格式 + 哈希链，不可篡改
- **CLI-first设计**: 面向运维人员，replay 8阶段取证回放 + 攻击链可视化 + 哈希链校验

## 测试状态

84 个测试全部通过（70 单元测试 + 6 集成测试 + 8 核心测试），0 编译警告。

## 实战价值

| 价值 | 说明 |
|------|------|
| 补盲 | 填补公安终端在内核层的监控盲区 |
| 固证 | SHA-256 哈希链取证日志，满足司法证据防篡改要求 |
| 落地 | 轻量、离线、静默，单二进制部署，适配警务终端 |
| 育人 | 内核行为观测与攻击链回放，用于信息安全教学 |

## 许可证

GPL-3.0

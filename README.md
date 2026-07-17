# KernelSentinel · 内核哨兵

用eBPF在内核态做终端威胁检测 探针挂在系统调用/VFS/网络栈/进程调度路径上 内核里维护进程树拓扑 TCP流状态机和六维频率基线 命中后写SHA-256哈希链取证日志 用户态引擎用Rust做规则匹配 跨事件关联 z-score基线偏离和攻击链还原

做这个的起因 Falco/Tetragon这类工具的感知层在用户态 从内核到规则引擎要经过几次上下文切换 短命进程和流级别行为容易漏 把感知放进内核能补这块盲区 它同时是个能拿来做信息安全教学演示的内核行为观测样例

## 构建

要 Linux 5.8+ clang 18 bpftool Rust nightly

```bash
cd kernel-sentinel
cargo build --release          # 同时编出4个tier的eBPF字节码
cargo test --workspace         # 约164个测试 不需要root
```

eBPF按4个tier编译（modern/legacy/ancient/ancient_nobtf） 运行时`tier_detect`自动挑 3.10之类没BTF的stock内核走C loader（`crates/ks-ebpf/scripts/ks_loader.c`） 不靠aya

## 跑

```bash
# 加载探针+消费ringbuf 前台运行（要root）
sudo ./target/release/kernelsentinel start

# 看配置概览（不需要root）
./target/release/kernelsentinel status

# 实时看map计数和运行实例（每秒刷新 Ctrl+C退出）
./target/release/kernelsentinel status --watch

# 起数据服务 REST+WebSocket 默认8443
sudo ./target/release/kernelsentinel start --serve 8443

# 回放取证日志（哈希链校验+攻击链还原）
./target/release/kernelsentinel replay /var/log/ks/events_*.jsonl

# 实时告警流
./target/release/kernelsentinel watch
```

systemd部署用`deploy/install.sh`（Type=notify capability限到CAP_BPF/CAP_PERFMON等几项） Docker见根目录`Dockerfile`+`docker-compose.yml`

## 目录

```
crates/
  ks-core/    事件/规则/告警类型 C与Rust内存对齐 编译期size断言
  ks-ebpf/    探针C代码+推理引擎 4tier条件编译
  ks-engine/  聚合/规则/关联/基线/攻击链/取证/ML/阻断/tier路由
  ks-server/  axum REST+WebSocket（Bearer+mTLS+限流+审计+Prometheus）
  ks-cli/     命令行入口
rules/        YAML检测规则
scenarios/    攻击模拟脚本
deploy/       systemd/install/grafana/prometheus
```

## 检测逻辑

- 规则引擎用YAML+Field枚举 字段名拼错在加载时报错 不会静默不匹配
- 跨事件关联分三种 窗口关联 序列检测 进程树关联 单事件规则查不了的组合（比如读过/etc/shadow之后外连4444）靠它
- 基线偏离 每进程六维z-score 一次性训练锁定 异常数据不会反过来把基线拉偏
- 内核态阻断 风险分到70以上直接`bpf_send_signal(SIGKILL)`（modern tier）
- 取证 JSONL+SHA-256哈希链 改任意一条记录后面全断

## 现状

- 4tier eBPF编译通过 在6.17真机上端到端跑过（事件 告警 哈希链闭环）
- 用户态引擎和12个攻击场景的e2e测试在`cargo test`里 不开root也能跑
- 还没做的 5.15/6.1两个内核的对照性能数据 内核态阻断（verdict==2→SIGKILL）只在编译层验证过 没在真机上真正杀过进程

## 许可证

GPL-3.0
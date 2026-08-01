# KernelSentinel · 内核哨兵

8.2.0242 第一版demo做好了

KernelSentinel是基于eBPF的内核态终端威胁检测系统。探针挂在系统调用、VFS、网络栈和进程调度路径上,内核里维护进程树拓扑、TCP流状态机和六维频率基线,命中后写SHA-256哈希链取证日志;用户态引擎用Rust做规则匹配、跨事件关联、z-score基线偏离和攻击链还原。

## 构建

需要Linux 5.8以上(开发机内核,用于编译eBPF)、clang 18、bpftool、Rust(stable即可,edition 2021)。

```bash
cd kernel-sentinel
cargo build --release          # 编出5个tier的eBPF字节码并内嵌进二进制
cargo test --workspace         # 167个测试,不需要root
```

部署到老内核(CentOS 7,glibc 2.17)用静态musl二进制,单文件无动态依赖,eBPF .o已内嵌:

```bash
rustup target add x86_64-unknown-linux-musl
scripts/build-musl.sh
```

eBPF按5个tier编译:modern(5.8以上ringbuf)、legacy(4.x perfbuf)、ancient(3.10 BTF backport)、ancient_nobtf(3.10无BTF)、legacy_nobtf(4.19无BTF)。运行时tier_detect自动挑,3.10之类没BTF的stock内核走C loader,即crates/ks-ebpf/scripts/ks_loader.c,不依赖aya。

## 运行

```bash
# 加载探针并消费ringbuf,前台运行,要root
sudo ./target/release/kernelsentinel start

# 看配置概览,不需要root
./target/release/kernelsentinel status

# 实时看map计数和运行实例,每秒刷新,Ctrl+C退出
./target/release/kernelsentinel status --watch

# 可选:启用REST API demo,与检测同进程
# sudo ./target/release/kernelsentinel start --serve 8443

# 回放取证日志,哈希链校验加攻击链还原
./target/release/kernelsentinel replay /var/log/ks/events_*.jsonl

# 实时告警流
./target/release/kernelsentinel watch
```

systemd部署用deploy/install.sh,Type=notify,capability限到CAP_BPF、CAP_PERFMON等几项。Docker见根目录Dockerfile和docker-compose.yml。

## 目录结构

- crates/ks-core/ 事件、规则、告警类型,C与Rust内存对齐,编译期size断言
- crates/ks-ebpf/ 探针C代码和推理引擎,5 tier条件编译
- crates/ks-engine/ 聚合、规则、关联、基线、攻击链、取证、ML、阻断、tier路由
- crates/ks-server/ axum REST加WebSocket,可选demo,Bearer加mTLS加限流加审计加Prometheus
- crates/ks-cli/ 命令行入口
- rules/ YAML检测规则
- scenarios/ 攻击模拟脚本
- deploy/ systemd、install、grafana、prometheus

## 检测逻辑

- 规则引擎用YAML加Field枚举,字段名拼错在加载时报错,不会静默不匹配
- 跨事件关联分三种:窗口关联、序列检测、进程树关联。单事件规则查不了的组合,比如读过/etc/shadow之后外连4444,靠它
- 基线偏离用每进程六维z-score,一次性训练锁定,异常数据不会反过来把基线拉偏
- 内核态阻断:风险分到70以上(verdict为2)直接bpf_send_signal(SIGKILL),仅modern tier和enforce模式,默认monitor只告警不杀
- 取证用JSONL加SHA-256哈希链,改任意一条记录后面全断

## 现状

- 5 tier eBPF编译通过,在6.17真机和5.15 Ubuntu 22.04 KVM上端到端跑过,事件、告警、哈希链闭环;3.10无BTF的CentOS 7通过C loader跑通
- 5.15上monitor模式45秒soak跑34660事件、778告警、0次SIGKILL,稳定收尾
- 用户态引擎和12个攻击场景的e2e测试在cargo test里,不开root也能跑
- 还没做的:5.15和6.1两个内核的对照性能数据;内核态阻断enforce模式(KS_ENFORCE=1)已验证能真杀进程,但冷启动分类器对高频系统进程(sshd、cron)会误判verdict为2,需配合基线建立后再用,默认monitor只告警不杀

# 

> Huginn ok Muninn
>
> fljúga hverjan dag
>
> jörmungrund yfir;
>
> óumk ek of Hugin,
>
> at hann aptr ne komi,
>
> þó sjámk meirr um Munin.
> 
> — Grímnismál, Poetic Edda

*奥丁双肩上栖息着的两只渡鸦，其名Huginn（福金）& Muninn（雾尼）*

**Hrabnaz**    ~~KernelSentinel · 内核哨兵~~

*Huginn thinks. Muninn remembers. Hrabnaz judges.*

基于 eBPF 的内核态终端威胁检测系统。探针挂在系统调用、VFS、网络栈和进程调度路径上，内核里维护进程树拓扑、TCP 流状态机和六维频率基线，命中后写 SHA-256 哈希链取证日志；用户态引擎用 Rust 做规则匹配、跨事件关联、z-score基线偏离和攻击链还原。

## 构建

需要Linux 5.8以上(开发机内核,用于编译eBPF)、clang 18、bpftool、Rust(stable即可,edition 2021)。

```bash
cd kernel-sentinel
cargo build --release          # 编出5个tier的eBPF字节码并内嵌进二进制
cargo test --workspace         # 198个测试,不需要root
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

- 5 tier eBPF 编译通过，6.17 真机（2026-07）、5.15 Ubuntu / 6.1 Debian / 3.10 CentOS 7 三台云主机端到端跑通（2026-08-13）：3.10 CentOS7 完整 Rust 链路 17650+ 事件/5092+ 告警/replay 23579 条链完整、5.15 1566 告警、6.1 62 告警，e2e-modern 全量断言 EXIT=0，详见 ks-test-evidence/perf-2026-08-13/
- 用户态引擎和 12 个攻击场景的 e2e 测试在 cargo test 里，不开 root 也能跑（198 个测试）
- 长稳已验证：8 月修复 ml_detector/baseline 表膨胀 OOM（加 LRU+淘汰守卫），RSS 1.4GB→3.9MB，误报 150万→33；三机 systemd 长稳 soak 已部署（monitor 模式）
- enforce模式(KS_ENFORCE=1)已实现多层冷启动防护:protected_pids(自身+父进程链+pid 1)硬豁免、protected_comms关键系统进程白名单(sshd/cron等,含exe_path反伪装)、KS_ENFORCE_WARMUP_SEC干跑期(默认120s,期间不主动杀)、KS_ENFORCE_KILL_THRESHOLD独立kill阈值(默认70,对齐申报书)。真机验证能SIGKILL触发进程;默认仍monitor只告警不杀
- 三机对照性能数据已采集(3.10/5.15/6.1,见 ks-test-evidence/perf-2026-08-05/):优化后用户态吞吐 1197-1977 events/s,detector_match 单事件 1.12-2.24μs,内核侧捕获 13.6-13.8万 syscall/s;瓶颈定位在用户态取事件环节,详见 docs/performance-design.md §6
- 2026-09-19 阻断闭环落地（ADR-011 设计意图）:BlockManager 决策（block_enabled 开启后的自动阻断 + REST 手动阻断）经 LinuxBpfMapReader 写入内核 block_decisions map,Modern tier 下同一 PID 下次 syscall 查表实杀（豁免名单仍生效）;C loader/mock 路径无 map 句柄,自动降级为仅记录用户态表。expire 用 CLOCK_MONOTONIC 与 bpf_ktime_get_ns 同源
- 2026-09-19 探针补发射:sys_enter 白名单 9→16 个 syscall,rename(82/264/316)/chmod(90/268) 发 FILE_RENAME(14)/FILE_CHMOD(15) 事件（filename 记新路径,勒索批量改名/持久化替换此前真机不可见）;unlink(87)/fchmod(91) 进 freq 计频（批量 rename 计入勒索频率异常）;read(0) 维持"只计频不流式"设计取舍。sys_exit 程序 2843→3489 insn,远低于 C loader 路径验证器 100 万上限;关联勒索规则同步改两步序列（写.encrypted→删,不再依赖无发射源的 FILE_READ）
- G7 真机复测通过(2026-09-19,见 ks-test-evidence/g7-2026-09-19/):Debian 12/6.1 e2e-modern EXIT=0、monitor 模式下 REST block 后受害进程被查表 SIGKILL(137)、unblock 后存活、block pid1 返回 403;CentOS 3.10.0-1160 由内嵌最小核心 BTF(1611B)驱动 CO-RE 16/16 attach,rename×527/chmod×8/freq 异常×1,3.10 上 map 写入成功但按设计不实杀(无 bpf_send_signal)。两台长稳已换装新二进制
- 2026-08 末改动已随"三真机全过"提交：智能过滤重构（文件 open/read 恒过滤、其余默认放行）、syscall_ctxs 384B 全 tier 采集 argv（含 NOBTF）、sys_exit 313(finit_module) 失败发 LKM 事件、LD_PRELOAD 规则改 regex

# 

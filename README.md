# KernelSentinel · 内核哨兵

用eBPF在内核态做终端威胁检测 探针挂在系统调用/VFS/网络栈/进程调度路径上 内核里维护进程树拓扑 TCP流状态机和六维频率基线 命中后写SHA-256哈希链取证日志 用户态引擎用Rust做规则匹配 跨事件关联 z-score基线偏离和攻击链还原

做这个的起因 Falco/Tetragon这类工具的感知层在用户态 从内核到规则引擎要经过几次上下文切换 短命进程和流级别行为容易漏 把感知放进内核能补这块盲区 它同时是个能拿来做信息安全教学演示的内核行为观测样例

## 构建

要 Linux 5.8+ clang 18 bpftool Rust nightly

```bash
cd kernel-sentinel
cargo build --release          # 同时编出4个tier的eBPF字节码
cargo test --workspace         # 约164个测试 不需要root
# 部署到老内核(CentOS 7/glibc 2.17)：静态 musl 二进制（单文件无动态依赖，eBPF .o 已内嵌）
# rustup target add x86_64-unknown-linux-musl && scripts/build-musl.sh
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

# 可选：启用 REST API demo（与检测同进程；serve 子命令按申报书为 CLI-first 声明，不绑端口）
# sudo ./target/release/kernelsentinel start --serve 8443

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
  ks-server/  axum REST+WebSocket（可选 demo，非 serve 主入口；Bearer+mTLS+限流+审计+Prometheus）
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

## 7.29update

eBPF字节码改成include_bytes!编进二进制。build.rs编译4个tier的.o后生成ebpf_objects.rs暴露常量，运行时tier_detect选内嵌字节码喂aya::Ebpf::load，不再从磁盘读.o，单二进制部署落地。install.sh相应改成只装预编二进制删掉cargo build，.o已内嵌无需额外安装。

加了CentOS 7能跑的musl静态二进制。cargo build --release --target x86_64-unknown-linux-musl出单文件无动态依赖，.cargo/config.toml里设CC_x86_64_unknown_linux_musl=gcc让ring的C/asm用gcc编再由rust-lld self-contained musl crt链接，不用装musl-gcc。scp到CentOS 7那台glibc 2.17的机器能直接跑--version和serve。

serve子命令改成CLI-first声明不绑端口，--serve留作可选REST demo，systemd ExecStart去掉--serve 8443，对齐申报书第51条。

nobtf路径在3.10无BTF时走C loader。预编static ks_loader用gcc -static链接后include_bytes!嵌进二进制，运行时释放到/tmp，ancient_nobtf.o同样内嵌释放，整个路径不依赖目标机gcc也不从磁盘读.o。ks_loader.c补了原来缺的ATTACH步骤：3.10没有BPF_LINK_CREATE，用perf_event_open拿PERF_TYPE_TRACEPOINT再PERF_EVENT_IOC_SET_BPF把程序绑到tracepoint和kprobe，kprobe经kprobe_events创建。调试踩了两个坑，CentOS 7的3.10上bpf(BPF_MAP_CREATE)在memlock rlimit默认64KB时返回EPERM而非ENOMEM，setrlimit必须放在预检之前；common.h加的block_decisions map没同步进ks_loader.c的known_maps[]表，C loader报unknown map退出，已补并加了构建期同步检查脚本防回归。

tier_detect加了nobtf release兼容检查，运行时内核release不匹配.o编译目标的3.10.0-1160就fail loud拒绝加载，避免在别的3.10子版本上用错偏移静默读错字段。

nobtf路径在3.10上加载16条探针全部通过但事件流不出来，排查发现attach阶段perf_event_open返EINVAL。最初判断是云虚机hypervisor封了perf_event_open，因为几台云服务器都带hypervisor标志且perf全失败。但本地KVM虚机也复现了同样的EINVAL，而KVM没有云厂商的hypervisor策略，说明问题不在hypervisor层。在dev机6.17内核上跑同样的测试程序返回EACCES而非EINVAL，EACCES说明内核接受了参数只是非root拒绝权限，EINVAL说明3.10内核拒绝参数本身，两者errno不同排除了参数错误的可能。装perf工具跑perf stat -e raw_syscalls:sys_enter成功计数115次，说明3.10内核能开tracepoint perf事件，测试程序失败而perf成功说明测试程序有bug。strace perf stat抓到perf的perf_event_open调用，发现perf用的是cpu=0而非cpu=-1。3.10内核的perf_event_open对PERF_TYPE_TRACEPOINT要求cpu参数为具体核号，cpu=-1返EINVAL，6.17接受cpu=-1所以dev机上没暴露这个问题。改成per-CPU循环每核开一个perf_event加SET_BPF加ENABLE，attach成功。本地KVM虚机8秒3360条事件，并行智算云32核虚机8秒1670条事件。云虚机用per-CPU修复也能跑通，说明之前hypervisor封perf的判断从头到尾是误判，真因是cpu参数。

## 许可证

GPL-3.0
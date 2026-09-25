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

基于 eBPF 的内核态终端威胁检测系统。探针挂在系统调用、VFS、网络栈和进程调度路径上，内核里维护进程树拓扑、TCP 流状态机和六维频率基线，命中后写 SHA-256 哈希链取证日志；用户态引擎做规则匹配、跨事件关联、z-score 基线偏离、攻击链还原和阻断执行。3.10～7.x 内核单二进制全覆盖，目标内核 BTF 构建期内嵌并裁剪到 KB 级。

## 构建

需要 Linux(编译 eBPF)、clang 18、bpftool、Rust stable。

```bash
cargo build --release          # 编出 5 个 tier 的 eBPF 字节码并内嵌进二进制
cargo test --workspace         # 198 个测试，不需要 root
```

部署到老内核(CentOS 7, glibc 2.17)用静态 musl 二进制，单文件无动态依赖，eBPF .o 与目标内核 BTF 已内嵌:

```bash
rustup target add x86_64-unknown-linux-musl
scripts/build-musl.sh          # dist/ 出交付 tar.gz
```

## tier 与 BTF

eBPF 按 tier 条件编译: modern(5.8+ ringbuf)、legacy(4.x perfbuf+LRU)、ancient(3.10 perfbuf)，另有 *_nobtf 档(剥掉 .BTF.ext 的硬编码偏移兜底，将随内嵌 BTF 架构正式化后退役，见未来工作)。CO-RE 重定位的目标内核 BTF 按 `KS_BTF_PATH` → `/sys/kernel/btf/vmlinux` → 构建期内嵌表(按 release 精确匹配)三级解析，取不到明确报错而不是带着错误偏移静默运行。

内嵌前用 `bpftool gen min_core_btf` 把完整 BTF 裁成只含探针引用类型的最小核心 BTF(实测 30.9MB → 1.5KB/内核)，交付单二进制约 37MB。裁剪正确性有回归测试兜底: 最小 BTF 与完整 BTF 对三个 tier 逐指令重定位比对，外加 aya 毒化(imm=0xBAD2310)检测——BTF 缺类型的表现是毒化不是报错，不查就是假绿。

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
- crates/ks-engine/ 聚合、规则、关联、基线、攻击链、取证、ML、阻断、tier路由、BTF解析
- crates/ks-server/ axum REST加WebSocket,可选demo,Bearer加mTLS加限流加审计加Prometheus
- crates/ks-cli/ 命令行入口
- rules/ YAML检测规则
- scenarios/ 攻击模拟脚本
- deploy/ systemd、install、grafana、prometheus

## 检测与阻断

- 规则引擎用YAML加Field枚举,字段名拼错在加载时报错,不会静默不匹配
- 跨事件关联分三种:窗口关联、序列检测、进程树关联。单事件规则查不了的组合,比如读过/etc/shadow之后外连4444,靠它
- 基线偏离用每进程六维z-score,一次性训练锁定,异常数据不会反过来把基线拉偏
- 阻断闭环: enforce/REST 的 block 决策经 LinuxBpfMapReader 写入内核 block_decisions map,同 PID 下次 syscall 查表实杀(bpf_send_signal, Modern tier);protected_pids(自身+父进程链+pid 1)硬豁免、protected_comms 关键进程白名单(含 exe_path 反伪装)、KS_ENFORCE_WARMUP_SEC 干跑期、KS_ENFORCE_KILL_THRESHOLD 独立 kill 阈值,默认 monitor 只告警不杀。3.10/4.19 无 bpf_send_signal(5.5+ 才有),map 写入生效但暂不实杀,见未来工作
- 探针发射面: sys_enter 白名单 16 个 syscall,rename/chmod 发 FILE_RENAME/FILE_CHMOD(勒索批量改名此前真机不可见),unlink/fchmod 进 freq 计频,read 维持"只计频不流式"
- LKM 检测: kprobe/do_init_module 主路径(CO-RE 读 mod->name,4.19 实测模块名精确命中);3.10 无该符号,回退 kretprobe/load_module,但 3.10 内核 kretprobe 不向 BPF 提供返回值(内核层限制,实测确认),该层暂空转
- kprobe 条目生命周期: 启动清扫 dead-pid 残留(p:/r: 两类),退出先关 perf fd 再删 tracefs 条目(老内核先删后关会 EBUSY),强杀场景靠下轮启动清扫
- 取证用JSONL加SHA-256哈希链,改任意一条记录后面全断

## 验证

| 内核 | tier | 结果 |
|---|---|---|
| 3.10.0-1160 (CentOS 7) | ancient + CO-RE(内嵌最小 BTF 1611B) | 16/16 attach,事件/哈希链/告警正常,rename×527/chmod×8,systemd 长稳部署 |
| 4.19.0-27 (Debian buster) | legacy | 16/16 attach,LKM 模块名精确命中,优雅退出零残留 |
| 6.1.0-13 (Debian 12) | modern | e2e-modern EXIT=0,REST block 后受害进程查表 SIGKILL(137),unblock 存活,block pid1 返回 403,systemd 长稳部署 |
| 5.15 (Ubuntu) | modern | 端到端跑通,1566 告警 |
| 7.x (开发机) | modern | 日常开发与回归 |

性能对照(3.10/5.15/6.1): 用户态吞吐 1197-1977 events/s,detector_match 1.12-2.24μs/事件,内核捕获 13.6-13.8 万 syscall/s,瓶颈定位在用户态取事件环节。数据与取证样例在 ks-test-evidence/(不随仓库分发)。

长稳: 8 月修复 ml_detector/baseline 表膨胀 OOM(加 LRU+淘汰守卫),RSS 1.4GB→3.9MB,误报 150万→33。

## 未来工作

- 架构方向:内嵌 BTF 重定位正式化,aya 上游化。3.10 真机已经证明 CO-RE 重定位完全在用户态完成,内核侧 BTF 支持根本不是必要条件，只要同一 CO-RE 对象配上目标内核的 BTF 就能在老内核跑,按内核版本硬编码偏移的 nobtf 路径没有存在必要。暂定未来落地分三步:①把本项目积累的三层 vendor 补丁整理成可提交上游的系列(老内核 BTF 清洗:kind_flag/位域结构/空枚举值名;BPF_PROG_LOAD 字段按 5.0 门控;<4.17 kprobe 条目先关 perf fd 再删的 EBUSY 修复);②补齐下限验证,vanilla 4.4/4.9(Debian 9/Ubuntu 16.04 世代)大概率可行,3.10 能跑靠的是 RHEL backport;③BTF 获取自动化(BTFHub 按 release 拉取,或 debuginfo+pahole 现场生成),最终删除 nobtf 编译档与 C loader,"每个内核版本编译一份硬编码偏移对象"的模式退役
- 非 Modern tier 实杀闭环: bpf_send_signal 要 5.5+,3.10/4.19 的 block 决策已写入内核 map 但不实杀，补一个用户态 killer(轮询 map 读出待杀 PID 后用户态 SIGKILL),让 enforce 在全 tier 闭环
- legacy 长稳: 4.19 走完功能验证但没跑过 systemd 长稳 soak,纳入长稳矩阵(本地 QEMU 即可)
- CI: GitHub Actions 跑无 root 测试套(198 测试 + BTF 等价性/毒化回归),push 即验,不让"BTF 缺类型假绿"这类问题靠人肉发现
- BTF 预埋扩容: BTFHub 覆盖的 Ubuntu 4.15/5.4、RHEL8/9 等常见企业内核,每份约十分钟接入并被等价性测试自动验证
- 单线程吞吐: 瓶颈应为取事件环节，处理层61μs/事件(理论 16400/s),实测 1200-1977/s,差约 10 倍;已试无效的是 ringbuf 加大(1MB→16MB,drop 未减)和 yield_now 替代 sleep,瓶颈在 aya 逐条 next() 的取事件结构,不在容量也不在轮询间隔。方向全部保持在单消费者架构内:每 tick 批量 drain 各 map 再统一处理(消掉逐条取的调度开销)、复用缓冲消除每事件 to_vec 拷贝、负载高时自适应 busy-poll、处理侧把 anomaly recent(1000) 全量 clone(占处理层 45%)改 per-pid 计数复用(27μs→<1μs)。 CLoader 批量版因 3.10 真机卡死回退,但 3.10 已改走 aya perfbuf,旧实现与新路径无关。
- 清理: C loader/nobtf 编译档已无真实场景,随架构方向落地考虑是否删除

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

***奥丁双肩上栖息着的两只渡鸦，其名Huginn（福金）& Muninn（雾尼）***

**Hrabnaz** · *Huginn thinks. Muninn remembers. Hrabnaz judges.*

基于 eBPF 的内核态终端威胁检测系统，为传统 Linux 服务器（3.10～7.x 内核）设计，单二进制、零依赖部署。内核侧在事件进入用户态前完成风险预判，用户态引擎做规则匹配、跨事件关联、攻击链还原与阻断执行。事件写入 SHA-256 哈希链取证日志，可回放校验。

## 构建

需要 Linux(编译 eBPF)、clang 18、bpftool、Rust stable。

```bash
cargo build --release          # 编出 5 个 tier 的 eBPF 字节码并内嵌进二进制
cargo test --workspace         # 231 个测试，不需要 root；用户态代码零 unsafe
```

部署到老内核(CentOS 7, glibc 2.17)用静态 musl 单二进制，无动态依赖，eBPF .o 与目标内核 BTF 已内嵌：

```bash
rustup target add x86_64-unknown-linux-musl
scripts/build-musl.sh          # dist/ 出交付 tar.gz
```

## 运行

```bash
# 加载探针并消费 ringbuf，前台运行，要 root
sudo ./target/release/kernelsentinel start

# 配置概览 / 运行实例与心跳，不需要 root
./target/release/kernelsentinel status
./target/release/kernelsentinel status --watch
./target/release/kernelsentinel status --json          # schema_version=1 单行快照

# 实时告警流：默认 follow，启动回显最近匹配历史；轮转/截断自动跟随
./target/release/kernelsentinel watch
./target/release/kernelsentinel watch --severity high --comm sshd
./target/release/kernelsentinel watch --rule 'SSH*' --json
./target/release/kernelsentinel watch --no-follow --max 50

# shell 补全（bash|zsh|fish|powershell|elvish）
./target/release/kernelsentinel completion bash

# 回放取证日志：哈希链校验 + 攻击链还原
./target/release/kernelsentinel replay --file /var/log/ks/events_20261016.jsonl
```

systemd 部署用 deploy/install.sh，Type=notify，capability 限到 CAP_BPF、CAP_PERFMON 等几项。

CLI 面向脚本：退出码 0 成功 / 1 运行期错误 / 2 用法错误；`status --json` 是单行快照，`watch --json` 是 JSONL；下游关闭管道时安静退出。watch 的过滤发生在告警已产生并写入取证日志之后，不改变检测、取证与阻断链路。

## tier 与 BTF

eBPF 按 tier 条件编译：modern(5.8+ ringbuf)、legacy(4.x perfbuf+LRU)、ancient(3.10 perfbuf)，另有 *_nobtf 硬编码偏移兜底档。目标内核 BTF 按 `KS_BTF_PATH` → `/sys/kernel/btf/vmlinux` → 构建期内嵌表（按 release 精确匹配）三级解析，取不到明确报错，不带错误偏移静默运行。

<details>
<summary>最小核心 BTF 裁剪</summary>

内嵌前用 `bpftool gen min_core_btf` 裁到只含探针引用类型（实测 30.9MB → 1.7~2.2KB/内核，交付单二进制约 27MB）。裁剪正确性有回归兜底：最小/完整 BTF 逐指令重定位比对 + aya 毒化(imm=0xBAD2310)检测——BTF 缺类型的表现是毒化不是报错，不查就是假绿。
</details>

## 目录结构

- crates/ks-ebpf/ 探针 C 代码与内核侧推理（5 tier 条件编译）
- crates/ks-engine/ 用户态检测引擎（规则、关联、基线、攻击链、取证、阻断）
- crates/ks-cli/ CLI 入口；crates/ks-core/ 公共事件与规则类型
- rules/ 检测规则；scenarios/ 攻击模拟；deploy/ systemd 与安装脚本

## 检测与阻断

- 规则引擎：YAML + Field 枚举，字段名拼错在加载时报错，不会静默不匹配
- 跨事件关联三类：窗口关联、序列检测、进程树关联——单事件规则查不了的组合靠它（如读过 /etc/shadow 后外连 4444）
- 基线：每进程六维 z-score，一次性训练锁定，异常数据不会反过来把基线拉偏
- 阻断闭环：裁决经 block_decisions map 下发，同 PID 下次 syscall 查表实杀（modern tier bpf_send_signal）；protected_pids / protected_comms 硬豁免、warmup 干跑期、独立 kill 阈值，默认 monitor 只告警不杀。3.10/4.19 无 bpf_send_signal，map 写入生效但暂不实杀
- 探针发射面：sys_enter 白名单 16 个 syscall；rename/chmod/unlink 进计频与事件（勒索批量改名此前真机不可见）；read 维持只计频不流式
- LKM 检测：kprobe/do_init_module 走 CO-RE 读模块名（4.19 实测精确命中）；3.10 无该符号回退 kretprobe，但 3.10 kretprobe 不提供返回值（内核层限制），该层暂空转
- kprobe 条目生命周期：启动清扫 dead-pid 残留，退出先关 perf fd 再删 tracefs 条目（老内核反序会 EBUSY），强杀靠下轮启动清扫
- 取证：JSONL + SHA-256 哈希链，改任意一条记录其后全断

## 验证

| 内核 | tier | 结果 |
|---|---|---|
| 3.10 (CentOS 7) | ancient + CO-RE | 16/16 attach，systemd 长稳 |
| 4.19 (Debian buster) | legacy | 16/16 attach |
| 6.1 (Debian 12) | modern | e2e 通过，block 闭环实测 |
| 5.15 (Ubuntu) | modern | 端到端跑通 |
| 7.x (开发机) | modern | 日常开发与回归 |

<details>
<summary>验证细节与性能数据</summary>

- 3.10：rename×527 / chmod×8 实测可见；内嵌最小 BTF（1.7KB）完成 CO-RE 重定位
- 4.19：LKM 模块名精确命中；优雅退出零残留
- 6.1：REST block 后受害进程 SIGKILL(137)、unblock 存活、block pid1 返回 403
- 5.15：端到端跑通（1566 告警）
- 性能（3.10/5.15/6.1）：用户态吞吐 1197–1977 events/s，内核捕获 13.6–13.8 万 syscall/s，瓶颈在用户态取事件环节
- 长稳：修复 ml_detector/baseline 表膨胀 OOM（LRU + 淘汰守卫），RSS 1.4GB → 3.9MB，误报 150 万 → 33
- 安全审计：运行时 unsafe 归零（libc FFI 经 nix 安全封装，事件解码纯安全字节提取）
- 数据与取证样例在 ks-test-evidence/（不随仓库分发）

</details>

<details>
<summary>路线图</summary>

- **形式化**：为检测语义与安全关键性质（取证链防篡改、豁免/阻断决策边界等）建立形式化模型，走机器可检验的证明路线，把关键保证从测试驱动提升到证明驱动
- **多尺度窗口与算法优化**：解决固定 60 秒窗口在"突发攻击"与"慢速潜伏"之间的两难——秒/分/时/天多分辨率窗口联合建模与自适应算法，让短时高频与长期低频两类行为在同一体系内各自可检出
- **Wodanaz Web 控制台**：独立选型前端框架，为检测体系构建 Web 端（Wodanaz，渡鸦之主）。接入是零兼容改动的硬约束：Wodanaz 只消费 Hrabnaz 现有公开面——取证 JSONL 哈希链、实时告警流、状态文件——Hrabnaz 不为它做任何适配，接口稳定性由前端反向验证

</details>

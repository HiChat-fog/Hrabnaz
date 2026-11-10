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

**Hrabnaz** · *Huginn thinks. Muninn remembers. Hrabnaz judges.*

# Hrabnaz

面向无法升级的Linux服务器，基于eBPF的终端威胁检测系统。单二进制覆盖3.10至7.x内核。

[![AtomGit G-Star](https://atomgit.com/HiChat-fog/Hrabnaz/star/new_badge.svg)](https://atomgit.com/HiChat-fog/Hrabnaz)

[English](../README.md)

## 工作原理

eBPF探针捕获内核入口点事件。检测状态驻留内核：进程拓扑、TCP流、行为频率、风险评分。正常行为零事件上行。

用户态引擎执行YAML规则、跨事件关联、行为基线与异常检测。每条事件写入SHA-256哈希链JSONL日志，链尾外置。

阻断在modern内核现场执行，老内核由用户态轮询补杀。默认monitor模式。

## 内核支持

| 档位 | 内核 | 通道 | CO-RE |
|---|---|---|---|
| modern | 5.8+ | ringbuf | 内嵌BTF |
| legacy | 4.10–5.7 | perfbuf | 内嵌BTF |
| ancient | 3.10–4.9 | perfbuf | 内嵌BTF |
| ancient_nobtf | 3.10–4.9 | perfbuf | 固定偏移 |
| legacy_nobtf | 4.10–5.7 | perfbuf | 固定偏移 |

发行版内核BTF在构建期裁剪内嵌，每份与完整BTF逐指令比对验证。未收录的内核在加载时明确拒绝。

## 构建

Linux、clang 18、libelf、Rust stable。

```bash
cargo build --release        # 编译全部eBPF档位，内嵌BTF
cargo test --workspace       # 无需root
```

## 运行

```bash
sudo ./target/release/hrabnaz start --rules-dir rules/
hrabnaz status
hrabnaz watch --severity high
hrabnaz replay --file /var/log/hrabnaz/events_*.jsonl
```

默认monitor模式。实杀需规则逐条声明`enforce: true`。

## 文档

- [架构文档](../ARCHITECTURE.md)

## 许可证

GPL-3.0。第三方组件：[aya](../vendor/aya)（MIT/Apache-2.0）、BTF来自[btfhub-archive](https://github.com/aquasecurity/btfhub-archive)（Apache-2.0）。

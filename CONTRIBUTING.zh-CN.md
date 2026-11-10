# 贡献指南

欢迎参与 Hrabnaz 项目。记录了关键约束与取舍，以及无内核环境下的本地验证方法。

## 一、 核心底线

1. **用户态零 `unsafe`**

   用户态代码严格禁止 `unsafe`。事件解码一律采用安全字节切片与 `nix` 封装来读取 eBPF 内存。如果某个改动非得用 `unsafe`，通常是设计有问题，请先讨论。

2. **C 与 Rust 结构体强契约**

   crates/hrabnaz-core/src/` 中带 `#[repr(C)]` 的结构体为两端共享，旁边均配有编译期 size 断言。字段两端不同步会导致直接编译失败，这是故意为之。请把两端改动合并在同一个 Commit。

3. **内核态保持极简**

   eBPF 侧只做基础的整数评分与过滤；正则、关联、基线全留在 `hrabnaz-engine`。千万别在探针里写字符串循环。

4. **默认规则不接受方言**

   默认规则只收录对所有 Linux 通用的事实。云厂商 Agent 和特定站点的环境噪声，走部署层白名单（`HRABNAZ_SENSITIVE_PATH_ALLOW`、`HRABNAZ_RULE_PROC_ALLOW`、`HRABNAZ_BASELINE_HIGHFREQ`）。把特定厂商的守护进程名硬编码进规则，一律拒绝。

5. **`enforce: true` 必须绝对精准**

   强制生效的规则只匹配明确的 comm/syscall，且必须先在 monitor 模式下证明零误报；`protected` 名单只是最后的兜底，不是放宽质量的借口。

## 二、 改动落点

| **改动类型**                   | **目标路径**                                            | **说明**                                                     |
| ------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------ |
| **新检测规则**                 | `rules/*.yml`                                           | 字段和操作符见使用手册；可能误伤正常流量的规则，必须补负样本测试 |
| **新事件源**                   | `crates/hrabnaz-ebpf/src/bpf/` `+ crates/hrabnaz-core/src/lib.rs` | `event_type` 值、`event_type_name` 映射、`#[repr(C)]` 结构体、`hrabnaz-engine/src/aggregator.rs` 解码器、size 断言——缺一不可 |
| **引擎逻辑**（关联/基线/取证） | `crates/hrabnaz-engine/src/`                                 | 惯例：单测写在同级文件，集成测试在 `crates/hrabnaz-engine/tests/` |
| **CLI 命令**                   | `crates/hrabnaz-cli/src/main.rs` `+ cmds/`                   | `--json` 单行输出是机器间契约，绝对不能破坏                  |
| **构建与 BTF**                 | `crates/hrabnaz-ebpf/btf/` `scripts/btf-*.sh`、`build.rs`    | 见下节                                                       |

## 三、 BTF 流水线

仓库仅内置最小 BTF Blob（149 个，约 322 KB），不包含 600MB+ 的完整内核 BTF。完整数据存在本地缓存中，`scripts/btf-fetch.sh` 负责从 BTFHub 拉取，`scripts/btf-regen.sh` 负责重建 `index.tsv` 与 `blobs/`，两个脚本均支持幂等执行。

**新增内核版本的步骤：**

```
scripts/btf-fetch.sh            # 下载完整 BTF 至 ~/.cache/hrabnaz/btf-full
scripts/btf-regen.sh            # 重建 index.tsv + blobs/，并校验哈希
cargo test -p hrabnaz-engine --test btf_relocation_test
```

- **重定位测试**：会把每个内嵌的最小 Blob 与完整 BTF 逐指令比对，并断言表外类型的 Aya 毒化哨兵存在。没有缓存时测试会自动跳过；有缓存时则执行完整校验。
- **版本控制**：`.btf` 或 `.btf.xz` 严禁提交进仓库（已加入 `.gitignore`）。

## 四、 无 Root 验证

工作空间共有 242 个测试（`cargo test --workspace`），**全都不需要 root**。用户态路径不依赖特定的 Linux 环境（通过 mock 事件源喂给引擎）。规则层的 ART 复现测试（`crates/hrabnaz-engine/tests/art_rule_repro.rs`）会把录制的攻击事件灌进真实规则集；每次动规则或字段提取时，这就是回归的最后防线。

**真要在内核里跑检查：**

Bash

```
sudo ./target/debug/hrabnaz start --rules-dir rules/ --log-dir /tmp/ks-try
./target/debug/hrabnaz status --watch          # 盯着探针 attach、map 增长
./target/debug/hrabnaz replay --file /tmp/ks-try/events_*.jsonl
```

## 五、 Commit 风格与 Issue

- **Commit**：一个逻辑改动一个 commit。英文祈使句，短小精悍即可（如："Harden detection and reduce log volume"）。发布打包必须从干净的 git 树出，生成产物不进库。
- **提 Issue**：请务必带上三样东西：内核版本（`uname -r`）、发行版、`hrabnaz status` 输出。
  - 测出检测问题：附带相关的取证 JSONL。
  - 遇到误报：附带该 PID 的 `baseline` 输出（统计层噪声基本都是突发频率模式，去那儿一眼就能看出来）。

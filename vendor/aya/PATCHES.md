# vendor/aya 本地补丁清单

基准：aya 0.14.0（crates.io 原版，`diff -r` 全量核对，除下列 6 处外无任何改动）。

维护策略（2026-10-24 定型）：
- **vendor fork 是产品本体的一部分，不是临时措施**。Hrabnaz 的目标内核（3.10~7.x）
  中，aya 上游只覆盖现代内核；老内核加载路径的修改上游不收，也不跟随上游升级。
- 默认不升级。仅两种情况动本目录：① cargo audit 命中 aya 安全通告时手动 cherry-pick
  修复；② 上游出现对我们目标内核的关键修复时评估移植。
- 新增补丁必须：代码处加 `HRABNAZ-PATCH(n):` 标记注释 + 在本文件登记。
- 通用性修复（与老内核无关、上游可能接受的可移植写法）可顺手提上游，机会性行为，
  不作为目标。

| # | 位置 | 一句话 |
|---|------|--------|
| 1 | src/sys/bpf.rs（map_create attr） | 无内核 BTF 时清零 btf_*_type_id |
| 2 | src/sys/bpf.rs（prog_load attr） | <5.0 内核不传 prog_btf_fd/func_info/line_info |
| 3 | src/programs/perf_attach.rs | 先关 perf fd 再删 tracefs 条目 |
| 4 | src/programs/perf_attach.rs | 强制老式 PERF_EVENT_IOC_SET_BPF |
| 5 | src/programs/perf_attach.rs | 不 disarm，保持 RAII 守卫 |
| 6 | src/bpf.rs（load_btf） | BTF 简化以过 4.18/4.19 校验器 + KS_DUMP_BTF 调试钩子（先原生、被拒再清洗重试） |
| 7 | src/sys/bpf.rs（map_create） | 带 BTF 建图失败时降级为无 BTF 重试 |
| 8 | src/bpf.rs（loader BTF） | 内核 BTF 装载失败不再致命（CO-RE 重定位在用户态） |
| 9 | src/programs/mod.rs（load_program） | 程序加载遇 BTF 错误时去掉 prog BTF 重试（Ubuntu 5.8 vmlinux BTF 损坏） |

## 逐条说明

### 1. map_create：无 BTF 时清零 btf_key/value_type_id — src/sys/bpf.rs
- **改动**：`btf_fd == 0`（内核无 BTF，如原版 3.10 无 CONFIG_DEBUG_INFO_BTF）时，
  把 `btf_key_type_id`/`btf_value_type_id`/`btf_fd` 全部置 0；上游无条件传
  `m.def` 里的非零 type id，此类内核直接 EINVAL。
- **影响内核**：所有无 BTF 的老内核（map 创建路径）。
- **可上游化**：理论上可（语义上更正确），但上游测试矩阵不含无 BTF 内核，提交意愿低。

### 2. prog_load：<5.0 不传 BPF_PROG_LOAD 的 BTF 尾部字段 — src/sys/bpf.rs
- **改动**：`prog_btf_fd`/`func_info`/`line_info` 是 5.0 才加入 attr 的字段，
  4.x 内核对 attr 尾部非零字节返回 E2BIG。按 `KernelVersion::at_least(5,0,0)`
  门控，老内核不传。CO-RE 重定位已在用户态完成，内核侧 BTF/行信息非校验必需。
- **影响内核**：全部 4.x。
- **可上游化**：这是典型的可移植兼容修复，上游有机会接受（未提）。

### 3. perf attach：先关 perf fd 再删 tracefs 条目 — src/programs/perf_attach.rs
- **改动**：删除顺序调整为先 perf fd 后 tracefs 条目。<4.17 走 debugfs 建条目
  路径的内核，条目仍被 perf event 引用时删除返回 EBUSY（实测 3.10 报
  "设备或资源忙"且静默失败），每次退出残留一批 `aya_<pid>_*` 条目。
- **影响内核**：<4.17（3.10 等 debugfs 路径）。
- **可上游化**：顺序修复对上游无害，可提。

### 4. perf attach：强制老式 PERF_EVENT_IOC_SET_BPF — src/programs/perf_attach.rs
- **改动**：绕过 `bpf(BPF_LINK_CREATE)`，统一走 ioctl 老路径。背景：5.15 KVM
  上调试 modern tier 时观察到 LINK_CREATE 路径异常；统一 SET_BPF 后
  3.10（nobtf C loader）与 5.15（modern aya）双路验证稳定。
  代价：bpf_perf_link 的 cookie 不可用（当前探针不使用 cookie）。
- **影响内核**：全部。
- **可上游化**：不可（放弃 cookie 是我们场景的取舍，非通用改进）。

### 5. perf attach：不再 disarm — src/programs/perf_attach.rs
- **改动**：上游在 attach 完成后立即关掉 ProbeEvent 的 RAII 守卫，而 PerfLink
  无 Drop 实现，条目从此无人清理。保留守卫存活：PerfLink drop 时先关 perf
  事件再删条目（依赖字段声明顺序），<4.17 上不再残留。
- **影响内核**：全部（配合补丁 3 生效）。
- **可上游化**：不可（依赖字段声明顺序的脆弱写法，上游不会以这种形态接受）。

### 8. loader：内核 BTF 装载失败不致命 — src/bpf.rs
- **改动**：上游在"对象含 CO-RE 重定位"时把内核 BTF 装载失败当致命错误；改为告警后无 BTF 继续
  （仅对非强制 BTF 的程序类型；fentry/fexit/LSM/iter 等仍报错）。
- **依据**：本库的 CO-RE 重定位是用户态用目标 BTF 完成的，内核侧对象 BTF 只提供
  func_info/line_info（调试）与 map 自省。QEMU 实测 Debian 4.19.0-20/21 因此从 FAIL 转 PASS。
- **可上游化**：可能（上游的 has_btf_relocations 判断对"用户态重定位"场景过严）。

### 9. load_program：prog BTF 降级重试 — src/programs/mod.rs
- **改动**：程序加载失败且携带 prog BTF 时，去掉 prog BTF（含 func/line info）重试一次，
  并报告第二次错误以便诊断。
- **依据**：Ubuntu 5.8.0 内核自身 vmlinux BTF 损坏（"btf_vmlinux is malformed"），
  任何携带 prog BTF 的加载都被拒；去掉后绕过该内核缺陷。
- **可上游化**：可能（容错重试）。

### 7. map_create：BTF 降级重试 — src/sys/bpf.rs
- **改动**：带 BTF 的 map 创建失败（EINVAL）时，清零 btf_fd/type_ids 重试一次。
- **原因**：Debian 4.19.0-20/21 回移的 BTF 校验更严，拒收我们对象 BTF 中的 map 类型
  （QEMU 实测 `[118] INT process_whitelist` 报 malformed）；map 的 BTF 只用于自省，
  不影响功能，降级安全。
- **可上游化**：可能（容错行为，上游或可接受为 fallback）。

### 6. load_btf：sanitize_btf_for_old_kernels — src/bpf.rs
- **改动**：`bpf_load_btf` 前对内核侧 BTF 做两类简化——① kflag 的
  STRUCT/UNION（全是带位域类型）成员表清成 vlen=0（kind_flag 是 4.20 才有的，
  老内核按"成员占满类型宽度"模型校验位域必失败）；② 空名字枚举值改指占位字符串
  （clang 对取址枚举常量的编码，新内核允许、4.18/4.19 报 Invalid name）。
  这份 BTF 只用于 map key/value 尺寸推导，CO-RE 重定位在用户态用完整目标 BTF。
  放在 load_btf（syscall 前最后一关）而非构建期，是因为 aya-obj fixup 会重建
  部分类型把 kflag 带回来。附带 `KS_DUMP_BTF=<path>` 调试钩子。
  **2026-10-25 QEMU 矩阵修正**：改为"先原生装载、被拒（EINVAL）才清洗重试一次"——
  无条件清洗会误伤部分 4.19 变体（Debian 4.19.0-20/21 拒收清洗版）；现代内核原生即通过、
  根本不会被改写（Ubuntu 5.8 的 "btf_vmlinux is malformed" 是其内核自身 BTF 损坏，与本补丁无关）。
- **影响内核**：4.18/4.19（BTF 校验器严格期）。
- **可上游化**：部分（枚举名修复可提；kflag 清 vlen=0 属激进简化，上游不会收）。

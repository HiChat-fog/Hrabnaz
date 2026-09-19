# CLoader 帧协议规范

> 适用范围：无 BTF 的 stock 内核（3.10 `3.10.0-1160` 系列 / 4.19 系列）下 `ks_loader --stream` 子进程与 Rust 父进程（`CLoaderSource`）之间的字节流协议。
> 相关代码：[`crates/ks-engine/src/cloader_source.rs`](../crates/ks-engine/src/cloader_source.rs)、[`crates/ks-engine/src/event_source.rs::try_cloader_source`](../crates/ks-engine/src/event_source.rs)、`crates/ks-ebpf/scripts/ks_loader.c`。

## 1. 设计动机

无 BTF 的 stock 内核（CentOS 7 `3.10.0-1160` 系列、Debian 4.19 系列）不带 BTF，aya（依赖 libbpf 1.0+）无法解析 `.BTF` maps 段而加载失败。NOBTF 方案绕开 aya：用独立编译的 C loader (`ks_loader.c`) 通过 libelf + raw `bpf()` syscall 加载字节码，再把 perfbuf 事件按帧格式写到 stdout，由 Rust 父进程异步读取。

该路径已超出"研究性里程碑"——3.10 CentOS 7 上已验证完整 Rust 链路（2026-08-13 三机端到端：17650+ 事件 / 5092+ 告警 / 取证 23579 条哈希链完整）。生产环境推荐带 BTF 内核走 Modern tier（aya ringbuf），nobtf 路径作为老内核兼容能力。

## 2. 帧格式

子进程 stdout 是连续的字节流，每帧格式如下：

```
+----------------+--------------------------+
| length (u32 LE)| payload (u8[length])     |
| 4 bytes        | length bytes             |
+----------------+--------------------------+
```

- `length`：4 字节 **小端序** u32，表示 payload 字节数
- `payload`：`length` 字节的事件二进制（即 `perf_buffer__poll` 拿到的 sample 数据）

**示例**：
- 4 字节 payload `[0x01,0x02,0x03,0x04]` 编码为 `04 00 00 00 01 02 03 04`
- 1024 字节 payload 编码为 `00 04 00 00 <1024 bytes>`

## 3. 心跳帧

`length == 0` 的帧为**心跳帧**（payload 段为空），用于：
- 子进程在空闲时段向父进程证明自己仍然活着
- 父进程的 `read_frame` 看到心跳帧后跳过并继续读下一帧（不返回给上层）

Rust 端实现（`cloader_source.rs` `read_frame` 内，心跳判断在长度读取后立即 `continue`——不要按旧行号查找，函数已重构）：

```rust
if length == 0 {
    continue;  // 心跳帧 — 跳过继续读下一帧
}
```

## 4. 退出码

| 退出码 | 含义 | 触发场景 |
|--------|------|----------|
| `0` | 优雅退出 | SIGINT/SIGTERM 信号到达，子进程 detach 所有 eBPF 程序、关闭 map 后退出 |
| `1` | 加载失败 | 任一 eBPF 程序 `bpf(BPF_PROG_LOAD)` 失败，或 map 创建失败 |

Rust 父进程在 stdout EOF 后通过 `child.wait().await` 检查退出码：
- `exit.success()` → `next_bytes` 返回 `Ok(None)`（优雅 EOF）
- 失败 → `next_bytes` 返回 `Err`，错误信息含退出码 + stderr 末尾 512 字节

## 5. stderr 日志格式

子进程 stderr 用于诊断信息（与 stdout 数据流隔离，不污染帧协议）：

- **加载阶段**：map 创建写 `[+] map_create '<name>' ...`；程序加载写 `[+] Loading program '<sec>' ...` + `[+] loaded fd=%d`；attach 写 `[+] attached <sec_name> on N/N CPUs (event_id=...)`（sec_name 形如 `tracepoint/raw_syscalls/sys_enter` 或 `kprobe/vfs_open`，kprobe 经 tracefs `kprobe_events` 注册 `ks_<func>`）；失败写 `[!]`/`[FAIL]` 前缀 + errno
- **运行阶段**：perfbuf `lost` 事件写 `[lost] cpu=%d count=%llu (ring overflow)`
- **verifier log**：加载失败时把 verifier log **末尾 4KB** 写到 stderr（完整 log 可能 > 2MB，截断保留尾部最相关部分）
- **退出阶段**：SIGINT/SIGTERM 到达时 detach 并退出（`exit(0)`）

Rust 端用后台 tokio task 异步预读 stderr 到环形缓冲，仅保留末尾 **512 字节**（`STDERR_TAIL_BYTES`），用于错误诊断。**不预读会阻塞**：默认管道 64KB 写满后子进程 stderr 写阻塞 → stdout 也停止 → 父进程误判挂起。

## 6. verifier log 截断策略

3.10 verifier log 可能极长（项目记录过单程序 1.8MB），完整输出会让 stderr 缓冲暴涨。`ks_loader.c` 用 `LOG_BUF_SIZE=2MB` 调 `bpf()` 拿 log，写 stderr 时只截末尾 4KB：

```c
// 伪代码
if (load_failed) {
    size_t log_len = strlen(log_buf);
    size_t tail = log_len > 4096 ? 4096 : log_len;
    fprintf(stderr, "[ks_loader] FAIL load %s: errno=%d\n", name, errno);
    fwrite(log_buf + log_len - tail, 1, tail, stderr);
    exit(1);
}
```

## 7. Rust 端解析逻辑（`read_frame` 泛型函数）

`cloader_source.rs::read_frame<R: AsyncReadExt + Unpin>` 是核心帧解析器，提取为独立函数便于单元测试：

```rust
async fn read_frame<R>(r: &mut R) -> Result<Option<Vec<u8>>>
where R: AsyncReadExt + Unpin {
    loop {
        let mut len_buf = [0u8; 4];
        match r.read_exact(&mut len_buf).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),  // 优雅 EOF
            Err(e) => return Err(e.into()),
        }
        let length = u32::from_le_bytes(len_buf) as usize;
        if length == 0 { continue; }  // 心跳帧
        let mut payload = vec![0u8; length];
        match r.read_exact(&mut payload).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(anyhow!("ks_loader stdout 在 payload 中途 EOF (期望 {} 字节)", length));
            }
            Err(e) => return Err(e.into()),
        }
        return Ok(Some(payload));
    }
}
```

**关键边界**：
- **优雅 EOF**（读完前一帧后再次 `read_exact` 返回 `UnexpectedEof`）→ `Ok(None)`
- **payload 中途 EOF**（length 声明 N 但实际读到 < N）→ `Err`，视为子进程崩溃/管道断裂（与优雅 EOF 严格区分）

## 8. 信号处理

`ks_loader --stream` 注册 SIGINT / SIGTERM handler：
1. 设置全局 `volatile sig_atomic_t stop_flag = 1`
2. perfbuf 轮询循环检查 `stop_flag`，每轮 timeout 1s（确保 ≤ 1s 内响应信号）
3. 退出循环后逐个 `bpf(BPF_PROG_DETACH)` + 关闭 map fd
4. `exit(0)`

Rust 父进程不应直接 kill 子进程 — 应发 SIGTERM 让其优雅清理。`tokio::process::Child` drop 时会发 SIGKILL，故 `CLoaderSource` 应在 drop 前 `child.start_kill()` + `wait()` 的逻辑（当前实现未做，依赖 systemd / 运维发信号）。

## 9. 路由集成

`event_source.rs::default_event_source` 在两个 NOBTF 分支优先调用 CLoaderSource（**不只 Ancient，Legacy 无 BTF 也走**，用 `ks_main_legacy_nobtf.o`）：

```rust
// Legacy + 无 BTF（4.19. 前缀守卫通过后）
if !btf_available() {
    match try_cloader_source_legacy().await { ... }   // ks_main_legacy_nobtf.o
}
// Ancient + 无 BTF（3.10.0-1160 前缀守卫通过后）
if !crate::tier_detect::btf_available() {
    match try_cloader_source().await {
        Ok((source, map_reader)) => return (Box::new(source), map_reader),
        Err(e) => log::warn!("[tier-detect] CLoaderSource 启动失败: {} — fallback aya + mock", e),
    }
}
// fallback: aya 加载路径 + Mock
```

CLoaderSource 失败时 fallback 到 aya + Mock（aya 通常也会失败，最终落到 Mock）。release 前缀守卫（ancient_nobtf 需 `3.10.0-1160`、legacy_nobtf 需 `4.19.`）不匹配时直接 bail，避免静默错误偏移。

## 10. BpfMapReader 缺失说明

`CLoaderSource` 不持有 `aya::Ebpf` 实例（map fd 在 C 子进程内），无法提供 `BpfMapReader`：

```rust
async fn try_cloader_source() -> Result<(CLoaderSource, Option<Arc<dyn BpfMapReader>>)> {
    // ...
    Ok((source, None))  // map_reader = None
}
```

后果：NOBTF 路径下 `/api/v1/stats` 端点 `map_stats` 字段为空数组。这是可接受的——nobtf 是兼容性路径，生产环境应有 BTF（走 Modern 提供完整 map 数据）。

## 11. 查找优先级（2026-08-31 按代码修正）

### `ks_loader` 二进制（2 级，非早期文档的 5 级）

| 优先级 | 来源 | 用途 |
|--------|------|------|
| 1 | 环境变量 `KS_LOADER_PATH` | 运维显式指定（文件不存在时 warn 并改用内嵌） |
| 2 | **内嵌二进制** | `build.rs` 编译期 `cc -static -O2 ks_loader.c -lelf -lzstd -lz` 预编 + `include_bytes!` 进 Rust 二进制，运行时 `release_to_temp` 释放（mode 0o500）执行 |

全部未命中时返回 `Err`（"二进制内无内嵌 ks_loader；如需外部指定，设 KS_LOADER_PATH 环境变量"）。
⚠️ 早期文档的 `which ks_loader` / `./ks_loader` / `/usr/local/bin` / scripts 源码编译逐级查找**不存在**。

### `ks_main_*_nobtf.o` 字节码（3 级，ANCIENT 与 LEGACY 各一份）

| 优先级 | 来源 | 用途 |
|--------|------|------|
| 1 | 环境变量 `KS_EBPF_DIR` + `ks_main_ancient_nobtf.o` / `ks_main_legacy_nobtf.o` | 运维显式指定目录（文件不存在时 warn 并改用内嵌） |
| 2 | `env!("OUT_DIR")` + 对应 .o | build.rs 编译期写入的绝对路径 |
| 3 | `target/{debug,release}/build/ks-engine-*/out/` + 对应 .o | 运行时 glob 查找最新一份 |

找不到时报"二进制内无内嵌 <tier> .o（编译期该 tier 未成功编译）"。

## 12. 测试覆盖

`cloader_source.rs::tests` 13 个单元测试用 `std::io::Cursor` mock 帧解析（不实际 spawn 子进程，跨平台可跑）：

| 测试名 | 验证点 |
|--------|--------|
| `test_source_kind_ancient_nobtf_str` | `SourceKind::EbpfAncientNoBtf.as_str()` 返回正确字符串 |
| `test_read_frame_simple` | 4 字节 payload 正常解码 |
| `test_read_frame_heartbeat_skipped` | 心跳帧跳过继续读下一帧 |
| `test_read_frame_multiple_heartbeats_then_payload` | 连续多心跳后真实帧（验证 loop 改写无递归栈风险） |
| `test_read_frame_eof_empty_input` | 空输入立即返回 `Ok(None)` |
| `test_read_frame_eof_after_one_frame` | 一帧后再读 → 优雅 EOF |
| `test_read_frame_payload_eof_midway_is_error` | payload 中途 EOF 返回 `Err`（与优雅 EOF 严格区分） |
| `test_read_frame_large_length` | 1024 字节 payload |
| `test_read_frame_sequential_multiple` | 连续多帧 + 心跳穿插 |
| `test_read_frame_length_uses_little_endian` | length 字段按 LE 解码 |
| `test_read_frame_two_bytes_length_field` | 512 字节 payload（边界值） |
| `test_stderr_tail_initial_empty` | stderr_buf 初始为空 |
| `test_stderr_ring_buffer_keeps_tail_only` | 写入 700 字节后仅保留末尾 512 字节 |

## 13. 调用示例

### 加载并流式输出（生产路径）

```bash
# 手动编译（一般无需——build.rs 已静态预编并内嵌进 Rust 二进制，运行时自动释放）
cc -static -O2 -Wall ks_loader.c -lelf -lzstd -lz
./ks_loader --stream ks_main_ancient_nobtf.o
# stdout 输出帧格式事件，stderr 输出诊断日志
```

### 仅加载验证（不进入轮询循环）

```bash
./ks_loader --load-only ks_main_ancient_nobtf.o
# 加载完成后立即退出码 0（13/13 加载成功）或 1（失败）
```

### Rust 端调用

```rust
use ks_engine::cloader_source::CLoaderSource;

let mut source = CLoaderSource::spawn("/usr/local/bin/ks_loader", "/path/to/ks_main_ancient_nobtf.o")?;
while let Some(payload) = source.next_bytes().await? {
    // 解码 payload 为事件结构体
}
```

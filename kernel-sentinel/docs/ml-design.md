# 内核哨兵 — 自适应 ML 检测系统设计文档 (G4.1)

> 本文档定义 KernelSentinel 的自适应机器学习/异常检测子系统。
> 实现位于 `crates/ks-engine/src/baseline.rs` 与 `crates/ks-engine/src/ml_detector.rs`。

## 1. 设计目标

- **自适应**：取代 `detector.rs` 中的硬编码打分法，根据每进程历史行为动态计算阈值。
- **抗稀释**：基线建立后不被异常数据污染，防止攻击者通过缓慢攻击拉偏基线。
- **双模型互补**：滑动窗口 z-score 适合稳定基线；EWMA 对渐变型攻击响应更快。
- **冷启动安全**：样本不足时回退固定阈值，避免误报。
- **误报可修正**：通过 `false_feedback` 闭环调整阈值，减少运维噪音。
- **低开销**：纯用户态统计计算，单次检测延迟可控（见 §8 SLO）。

## 2. 双模型架构

两个模型独立运行、并行检测，结果取并集：

```
                 DecodedEvent
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
   ┌──────────────┐       ┌──────────────┐
   │BaselineManager│       │AdaptiveDetector│
   │ z-score 滑窗  │       │  EWMA 在线学习 │
   └──────┬───────┘       └──────┬───────┘
          │                      │
          │  DeviationResult      │  AnomalyResult
          │                      │
          └─────────┬────────────┘
                    ▼
         并集告警：任一触发即告警
         severity 取两者较高者
```

- `BaselineManager`：固定 60s 窗口，周期性重算 mean/stddev，适合稳定基线。
- `AdaptiveDetector`：EWMA 指数衰减，对趋势变化响应更快，适合渐变型攻击。

## 3. BaselineManager 详解

源文件：`crates/ks-engine/src/baseline.rs`。

### 3.1 滑动窗口 z-score

- 窗口长度 `WINDOW_DURATION_NS = 60_000_000_000`（60s）。
- 每进程历史最多保留 `max_history_windows = 20` 个窗口快照 `FreqSnapshot`。
- 至少 `min_samples = 5` 个完成窗口才建立基线。
- 基线计算（`calc_baseline`）：

```
mean     = (1/n) Σ xᵢ
variance = (1/n) Σ (xᵢ - mean)²          // 总体方差
stddev   = √variance
z_score  = (current - mean) / stddev
```

- 告警阈值 `z_score_threshold = 2.0`（2σ）。
- 严重度分级：`<2 Normal | <3 Low | <4 Medium | <5 High | ≥5 Critical`。
- 固定阈值 fallback：基线未建立时，超过固定阈值即 `z=5.0`（见 §6）。

### 3.2 一次性训练锁（One-shot Training Lock）

通过 `established_pids: HashSet<u32>` 实现：

```rust
if !self.established_pids.contains(&pid) {
    let completed = history.iter().filter(|s| s.syscall_count > 1).count();
    if completed >= self.min_samples as usize {
        self.recalculate_baseline(pid, &comm, is_high_freq);
        self.established_pids.insert(pid);   // 此后永不重算
    }
}
```

基线一旦建立即冻结，后续异常样本**不会**更新 mean/stddev，防止攻击稀释。

### 3.3 内在高频进程标记

`is_inherently_high_freq` 对已知高频进程（`wget`/`curl`/`nginx`/`postgres`/`mongod` 等，见 `INHERENTLY_HIGH_FREQ` 常量数组，共 18 个 comm 子串）置位，供上层判级时参考（标记本身不自动放宽阈值）。

### 3.4 内存守卫（2026-08 OOM 修复，勿回退）

每进程数据统一受 LRU 淘汰保护，**守卫查真正膨胀的表**（8-10 修复的核心教训）：

- `freq_history`: `max_pids = 10000`，超限按 `snaps.last().timestamp_ns` 最小者淘汰至 9000，并同步清理 `baselines` + `established_pids`。
- 历史实现只查 `baselines.len()` 触发淘汰——短命进程进不了 baselines，导致淘汰永不触发，RSS 最高 1.4GB。修复后本地 8-worker loadgen RSS 稳定 3.9MB，误报 150 万 → 33。
- 教训：**加 per-PID 结构必配 LRU；60s 短跑测不出泄漏，需 ≥10 分钟 + RSS 趋势采样**。

### 3.5 输出

```rust
DeviationResult {
    pid, deviations: Vec<DimensionDeviation>,
    overall_score,                  // max_z / 5.0，clamp [0,1]
    most_deviated_dimension,
}
```

## 4. AdaptiveDetector 详解

源文件：`crates/ks-engine/src/ml_detector.rs`。基于 EWMA（指数加权移动平均）的在线学习模型。

### 4.1 EWMA 更新公式

α=0.3（新数据权重 30%，约 7 个样本后旧数据权重 <5%）。窗口满 60s 时 `commit_window` 提交：

```
diff         = current - mean_old
mean_new     = α × current + (1-α) × mean_old
variance_new = (1-α) × (variance_old + α × diff²)
z_score      = |current - mean| / √variance
```

对应实现：

```rust
state.mean     = self.alpha * val + (1.0 - self.alpha) * old_mean;
state.variance = (1.0 - self.alpha) * (state.variance + self.alpha * diff * diff);
```

状态按 `(pid, dimension)` 维度独立维护（`EwmaState { mean, variance, sample_count }`）。

### 4.2 冷启动

`sample_count < COLD_START_SAMPLES (5)` 时使用固定阈值，不依赖 EWMA 统计（见 §6）。

### 4.3 误报反馈

- `false_feedback(pid, true)` → 阈值乘数 `*= 1.1`（每次误报 +10%）。
- 后续每累积 `THRESHOLD_DECAY_INTERVAL = 100` 个正常样本，乘数衰减 `/= 1.1`，最低回到 1.0。
- 有效阈值 = `z_threshold (2.0) × threshold_multiplier`。

### 4.4 输出

```rust
AnomalyResult {
    pid, dimensions: Vec<MlDimensionAnomaly>,
    overall_score, model: AnomalyModel::Ewma | ColdStart,
}
```

## 5. 维度定义

两模型共享同一套 6 维度语义：

| 维度 | 含义 | 事件类型 | 冷启动固定阈值（/60s） |
|------|------|----------|------------------------|
| `SyscallFrequency` | 系统调用频率 | 全部 | 5000 |
| `FileOpsFrequency` | 文件操作频率 | 10–15（open/openat/read/write/unlink） | 500 |
| `NetOpsFrequency` | 网络操作频率 | 20–24（connect 等） | 100 |
| `DnsOpsFrequency` | DNS 操作频率 | 24 | 50 |
| `PtraceOpsFrequency` | ptrace 操作频率 | 30 | 3 |
| `SignalOpsFrequency` | 信号操作频率 | 31（kill 等） | 10 |

> 注：DNS（type 24）同时计入 `NetOpsFrequency` 与 `DnsOpsFrequency`。

## 6. 冷启动策略

两个模型在样本不足时回退到相同的固定阈值表（见 §5），避免冷启动期因基线缺失而漏报或大量误报。

- **BaselineManager**：`established_pids` 未收录该 pid 时，仅用固定阈值判定（超阈值 `z=5.0`）。
- **AdaptiveDetector**：`pid_sample_counts < 5` 时标记 `AnomalyModel::ColdStart`，固定阈值判定；样本充足后切 EWMA 并返回 `AnomalyModel::Ewma`。

## 7. 误报反馈闭环

仅 `AdaptiveDetector` 提供在线反馈通道（`BaselineManager` 基线冻结，不参与调整）：

```
false_feedback(pid, true)
   │
   ▼
threshold_multiplier *= 1.1        // 阈值抬升，降低灵敏度
   │
   ▼
正常样本累积 100 个
   │
   ▼
threshold_multiplier /= 1.1        // 衰减回原灵敏度（下限 1.0）
```

多次误报可叠加（如两次 → 1.21），随正常样本累积逐级衰减，实现"误报后短暂放宽、回归正常后恢复灵敏度"的自适应闭环。

## 8. 性能指标

纯用户态统计计算，每事件仅做计数器自增，窗口边界才提交统计：

| 指标 | SLO | 实测（criterion，2026-08-13） | 说明 |
|------|-----|------|-----|
| BaselineManager 单次检测 | < 10μs | 37ns detect / 104ns update+detect | `detect_deviation` 遍历 6 维，纯算术 |
| AdaptiveDetector 单次检测 | < 50μs | 68ns update+detect | `detect` 遍历 6 维 EWMA 状态 |
| 单事件更新 | < 1μs | — | `update_from_event` 仅 HashMap 计数器自增 |
| 内存（每进程） | ~1 KB | 全局受 LRU 守卫（max_pids=10000 → 淘汰至 9000） | 基线 6 维 + 历史 20 窗口快照；2026-08 OOM 修复后 RSS 1.4GB→3.9MB |

> 端到端性能（eBPF 探针、ringbuf 丢包等）见 `docs/performance-design.md`。

## 9. 测试覆盖

单元测试位于各源文件 `#[cfg(test)] mod tests`，覆盖关键路径：

**`baseline.rs`**：
- `test_baseline_building` — 5 窗口后基线建立。
- `test_deviation_detection` — 频率突增触发偏离。
- `test_no_deviation_for_normal` — 正常行为不告警。
- `test_severity` — 严重度分级边界。

**`ml_detector.rs`**：
- `test_ewma_converges_to_steady_state` — 稳态收敛、不误报。
- `test_cold_start_uses_fixed_threshold` — 冷启动走固定阈值。
- `test_ransomware_frequency_spike_detected` — 勒索软件文件操作突增。
- `test_dns_tunnel_high_freq_detected` — DNS 隧道高频检测。
- `test_false_positive_feedback_raises_threshold` — 误报反馈抬升阈值。
- `test_threshold_decay_after_normal_samples` — 100 正常样本后阈值衰减。
- `test_dual_model_complementarity` — EWMA 对渐变攻击的趋势敏感性。

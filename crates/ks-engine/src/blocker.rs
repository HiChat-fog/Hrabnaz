use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::loader::BpfMapReader;

/// 阻断决策的内核下发通道（ADR-011"用户态写 block_decisions → 内核查表实杀"闭环）。
///
/// 语义对齐内核侧 `ks_check_block()`：
/// - `expire_monotonic_ns` 必须与 `bpf_ktime_get_ns()` 同源（CLOCK_MONOTONIC），
///   `0` = 永久阻断（内核 `expire_ns==0` 即视为永久）；
/// - `reason` 编码与 `BlockReason` 1..5 对齐；
/// - 实杀只发生在 Modern tier（5.8+ 有 `bpf_send_signal`），Legacy/Ancient 仅查表标记；
///   内核侧自动豁免 protected_pids，无需下发方重复判断。
pub trait KernelBlockWriter: Send + Sync {
    fn apply_block(&self, pid: u32, expire_monotonic_ns: u64, reason: u8) -> anyhow::Result<()>;
    fn remove_block(&self, pid: u32) -> anyhow::Result<()>;
}

/// 经 `BpfMapReader`（aya 加载路径的 LinuxBpfMapReader）下发到内核 map 的适配器。
/// C loader（NOBTF）与 mock 路径没有用户态 map 句柄，走 trait 默认实现并报错。
pub struct MapWriterSink(pub Arc<dyn BpfMapReader>);

impl KernelBlockWriter for MapWriterSink {
    fn apply_block(&self, pid: u32, expire_monotonic_ns: u64, reason: u8) -> anyhow::Result<()> {
        self.0.write_block_decision(pid, expire_monotonic_ns, reason)
    }
    fn remove_block(&self, pid: u32) -> anyhow::Result<()> {
        self.0.remove_block_decision(pid)
    }
}

/// 与 `bpf_ktime_get_ns()` 同源的 CLOCK_MONOTONIC 纳秒。
/// /proc/uptime 是 boottime 口径（含 suspend），会话挂起后 TTL 会变长，故用 clock_gettime。
#[cfg(target_os = "linux")]
fn monotonic_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // clock_gettime 对合法 clockid 不返回错误
    let ok = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0;
    if !ok {
        return 0;
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + ts.tv_nsec as u64
}

#[cfg(not(target_os = "linux"))]
fn monotonic_now_ns() -> u64 {
    0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    RuleMatch = 1,
    BaselineDeviation = 2,
    MlAnomaly = 3,
    Correlation = 4,
    Manual = 5,
}

impl BlockReason {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => BlockReason::RuleMatch,
            2 => BlockReason::BaselineDeviation,
            3 => BlockReason::MlAnomaly,
            4 => BlockReason::Correlation,
            5 => BlockReason::Manual,
            _ => BlockReason::Manual,
        }
    }
}

impl std::fmt::Display for BlockReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockReason::RuleMatch => write!(f, "rule_match"),
            BlockReason::BaselineDeviation => write!(f, "baseline_deviation"),
            BlockReason::MlAnomaly => write!(f, "ml_anomaly"),
            BlockReason::Correlation => write!(f, "correlation"),
            BlockReason::Manual => write!(f, "manual"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedPid {
    pub pid: u32,
    pub blocked_at_ns: u64,
    pub expiry_ns: u64,
    pub reason: BlockReason,
    pub trigger: String,
}

pub struct BlockManager {
    blocked: HashMap<u32, BlockedPid>,
    enabled: bool,
    default_ttl: u64,
    // Some = block/unblock 同步下发内核 block_decisions map（aya 路径）
    kernel: Option<Arc<dyn KernelBlockWriter>>,
}

impl Default for BlockManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockManager {
    pub fn new() -> Self {
        Self {
            blocked: HashMap::new(),
            enabled: false,
            default_ttl: 300,
            kernel: None,
        }
    }

    pub fn with_config(enabled: bool, default_ttl: u64) -> Self {
        Self {
            blocked: HashMap::new(),
            enabled,
            default_ttl,
            kernel: None,
        }
    }

    /// 接通内核下发通道。只在 aya 加载路径调用（start.rs 侧按 map_reader 是否存在决定）。
    /// 未接通时 block/unblock 仅记录用户态表——与 8-31 之前的行为一致。
    pub fn set_kernel_sink(&mut self, sink: Arc<dyn KernelBlockWriter>) {
        self.kernel = Some(sink);
    }

    pub fn block_pid(
        &mut self,
        pid: u32,
        ttl_secs: u64,
        reason: BlockReason,
        trigger: &str,
    ) -> bool {
        if !self.enabled {
            return false;
        }

        let now = now_ns();
        let ttl = if ttl_secs == 0 {
            self.default_ttl
        } else {
            ttl_secs
        };
        let expiry = if ttl == u64::MAX {
            0
        } else {
            // saturating：ttl 过大时旧的加法会溢出回绕，"永久封禁"瞬间变成"立刻过期"
            now.saturating_add(ttl.saturating_mul(1_000_000_000))
        };

        self.blocked.insert(
            pid,
            BlockedPid {
                pid,
                blocked_at_ns: now,
                expiry_ns: expiry,
                reason,
                trigger: trigger.to_string(),
            },
        );

        // 同步下发内核：同一 PID 的下一次 syscall 会在探针的 ks_check_block 查表中命中。
        // 下发失败只降级为"仅用户态记录"，不推翻本次阻断决策本身
        if let Some(k) = &self.kernel {
            let expire_mono = if ttl == u64::MAX {
                0
            } else {
                monotonic_now_ns().saturating_add(ttl.saturating_mul(1_000_000_000))
            };
            if let Err(e) = k.apply_block(pid, expire_mono, reason as u8) {
                log::warn!(
                    "block_decisions 内核下发失败(pid={}, reason={}): {} — 仅记录用户态表，内核不会查表实杀",
                    pid,
                    reason,
                    e
                );
            }
        }
        true
    }

    pub fn unblock_pid(&mut self, pid: u32) -> bool {
        let removed = self.blocked.remove(&pid).is_some();
        if removed {
            if let Some(k) = &self.kernel {
                if let Err(e) = k.remove_block(pid) {
                    log::warn!("block_decisions 内核删除失败(pid={}): {} — TTL 到期后内核侧自动失效", pid, e);
                }
            }
        }
        removed
    }

    pub fn is_blocked(&mut self, pid: u32) -> bool {
        if let Some(entry) = self.blocked.get(&pid) {
            if entry.expiry_ns > 0 && now_ns() > entry.expiry_ns {
                self.blocked.remove(&pid);
                return false;
            }
            return true;
        }
        false
    }

    pub fn list_blocked(&mut self) -> Vec<BlockedPid> {
        self.cleanup_expired();
        self.blocked.values().cloned().collect()
    }

    pub fn cleanup_expired(&mut self) {
        let now = now_ns();
        self.blocked
            .retain(|_, entry| entry.expiry_ns == 0 || entry.expiry_ns > now);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_block_pid_basic() {
        let mut mgr = BlockManager::with_config(true, 300);
        assert!(mgr.block_pid(1234, 60, BlockReason::Manual, "test"));
        assert!(mgr.is_blocked(1234));
        assert_eq!(mgr.blocked_count(), 1);
    }

    #[test]
    fn test_block_disabled_returns_false() {
        let mut mgr = BlockManager::with_config(false, 300);
        assert!(!mgr.block_pid(1234, 60, BlockReason::Manual, "test"));
        assert!(!mgr.is_blocked(1234));
    }

    #[test]
    fn test_unblock_pid() {
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.block_pid(1234, 60, BlockReason::RuleMatch, "reverse_shell");
        assert!(mgr.is_blocked(1234));
        assert!(mgr.unblock_pid(1234));
        assert!(!mgr.is_blocked(1234));
    }

    #[test]
    fn test_unblock_nonexistent() {
        let mut mgr = BlockManager::with_config(true, 300);
        assert!(!mgr.unblock_pid(9999));
    }

    #[test]
    fn test_block_ttl_expiry() {
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.block_pid(1234, 1, BlockReason::Manual, "test");
        assert!(mgr.is_blocked(1234));
        thread::sleep(Duration::from_millis(1100));
        assert!(!mgr.is_blocked(1234));
    }

    #[test]
    fn test_list_blocked() {
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.block_pid(100, 60, BlockReason::RuleMatch, "rule1");
        mgr.block_pid(200, 60, BlockReason::MlAnomaly, "ml1");
        mgr.block_pid(300, 60, BlockReason::Correlation, "corr1");

        let list = mgr.list_blocked();
        assert_eq!(list.len(), 3);
        assert!(list
            .iter()
            .any(|b| b.pid == 100 && b.reason == BlockReason::RuleMatch));
        assert!(list
            .iter()
            .any(|b| b.pid == 200 && b.reason == BlockReason::MlAnomaly));
        assert!(list
            .iter()
            .any(|b| b.pid == 300 && b.reason == BlockReason::Correlation));
    }

    #[test]
    fn test_cleanup_expired() {
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.block_pid(100, 60, BlockReason::Manual, "test1");
        mgr.block_pid(200, 1, BlockReason::Manual, "test2");
        thread::sleep(Duration::from_millis(1100));
        mgr.cleanup_expired();
        assert_eq!(mgr.blocked_count(), 1);
        assert!(mgr.is_blocked(100));
        assert!(!mgr.is_blocked(200));
    }

    #[test]
    fn test_block_reason_display() {
        assert_eq!(BlockReason::RuleMatch.to_string(), "rule_match");
        assert_eq!(BlockReason::MlAnomaly.to_string(), "ml_anomaly");
        assert_eq!(BlockReason::from_u8(1), BlockReason::RuleMatch);
        assert_eq!(BlockReason::from_u8(99), BlockReason::Manual);
    }

    #[test]
    fn test_default_ttl_used_when_zero() {
        let mut mgr = BlockManager::with_config(true, 300);
        assert!(mgr.block_pid(1234, 0, BlockReason::Manual, "test"));
        let list = mgr.list_blocked();
        assert_eq!(list.len(), 1);
        let entry = &list[0];
        assert!(entry.expiry_ns > entry.blocked_at_ns);
    }

    #[test]
    fn test_update_existing_block() {
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.block_pid(1234, 60, BlockReason::RuleMatch, "rule1");
        mgr.block_pid(1234, 60, BlockReason::MlAnomaly, "ml1");
        let list = mgr.list_blocked();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].reason, BlockReason::MlAnomaly);
    }
}

/// 内核下发通道的记录桩：核对 block/unblock 触发的 apply/remove 参数
#[cfg(test)]
struct RecordingSink {
    calls: std::sync::Mutex<Vec<(u32, u64, u8)>>,
    removed: std::sync::Mutex<Vec<u32>>,
    fail: bool,
}

#[cfg(test)]
impl RecordingSink {
    fn new() -> Self {
        Self {
            calls: std::sync::Mutex::new(Vec::new()),
            removed: std::sync::Mutex::new(Vec::new()),
            fail: false,
        }
    }
}

#[cfg(test)]
impl KernelBlockWriter for RecordingSink {
    fn apply_block(&self, pid: u32, expire_monotonic_ns: u64, reason: u8) -> anyhow::Result<()> {
        if self.fail {
            anyhow::bail!("注入的内核写入失败");
        }
        self.calls
            .lock()
            .unwrap()
            .push((pid, expire_monotonic_ns, reason));
        Ok(())
    }
    fn remove_block(&self, pid: u32) -> anyhow::Result<()> {
        if self.fail {
            anyhow::bail!("注入的内核写入失败");
        }
        self.removed.lock().unwrap().push(pid);
        Ok(())
    }
}

#[cfg(test)]
mod kernel_sync_tests {
    use super::*;

    #[test]
    fn test_kernel_sink_called_on_block() {
        let sink = Arc::new(RecordingSink::new());
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.set_kernel_sink(sink.clone());

        assert!(mgr.block_pid(1234, 60, BlockReason::RuleMatch, "t"));
        let calls = sink.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (pid, expire, reason) = calls[0];
        assert_eq!(pid, 1234);
        assert_eq!(reason, BlockReason::RuleMatch as u8);
        // TTL=60s：expire 应是未来的单调时钟值（且与 UNIX 时钟无关）
        assert!(expire > monotonic_now_ns(), "expire 应在当前单调时刻之后");
        assert!(expire <= monotonic_now_ns() + 61_000_000_000);
    }

    #[test]
    fn test_kernel_sink_permanent_block_uses_zero_expire() {
        let sink = Arc::new(RecordingSink::new());
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.set_kernel_sink(sink.clone());

        assert!(mgr.block_pid(1234, u64::MAX, BlockReason::Manual, "t"));
        let calls = sink.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, 0, "永久阻断应写 expire_ns=0（内核语义：0=永久）");
    }

    #[test]
    fn test_kernel_sink_not_called_when_disabled_or_unblock_only() {
        let sink = Arc::new(RecordingSink::new());
        let mut mgr = BlockManager::with_config(false, 300);
        mgr.set_kernel_sink(sink.clone());

        assert!(!mgr.block_pid(1234, 60, BlockReason::Manual, "t"));
        assert!(sink.calls.lock().unwrap().is_empty(), "阻断未启用时不应下发内核");
        assert!(!mgr.unblock_pid(1234));
        assert!(sink.removed.lock().unwrap().is_empty(), "未阻断的 unblock 不应下发内核");
    }

    #[test]
    fn test_kernel_remove_on_unblock() {
        let sink = Arc::new(RecordingSink::new());
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.set_kernel_sink(sink.clone());

        mgr.block_pid(1234, 60, BlockReason::Manual, "t");
        assert!(mgr.unblock_pid(1234));
        assert_eq!(sink.removed.lock().unwrap().as_slice(), &[1234]);
    }

    #[test]
    fn test_kernel_sink_error_still_records_table() {
        let sink = Arc::new(RecordingSink {
            calls: std::sync::Mutex::new(Vec::new()),
            removed: std::sync::Mutex::new(Vec::new()),
            fail: true,
        });
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.set_kernel_sink(sink);

        // 内核下发失败只降级：用户态表照常记录（决策不回滚），下次阻断重试
        assert!(mgr.block_pid(1234, 60, BlockReason::Manual, "t"));
        assert!(mgr.is_blocked(1234));
    }

    #[test]
    fn test_monotonic_now_ns_positive_on_linux() {
        // 与 bpf_ktime_get_ns 同源的时钟应给出正值（内核启动以来至少跑了些许时间）
        assert!(monotonic_now_ns() > 0);
    }

    #[test]
    fn test_ttl_zero_uses_default_for_kernel_expire() {
        let sink = Arc::new(RecordingSink::new());
        let mut mgr = BlockManager::with_config(true, 300);
        mgr.set_kernel_sink(sink.clone());

        mgr.block_pid(1234, 0, BlockReason::Manual, "t");
        let calls = sink.calls.lock().unwrap();
        let (_, expire, _) = calls[0];
        // ttl=0 → default_ttl=300s，内核 expire 应落在 ~300s 后而非 0（0 是永久语义，不能混用）
        assert!(expire > monotonic_now_ns() + 299_000_000_000);
    }
}

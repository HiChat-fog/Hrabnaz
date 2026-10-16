use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::loader::BpfMapReader;

/// block_decisions 在 bpffs 的 pin 路径：引擎启动 pin、退出摘除，
/// `ks block` 等独立进程经此跨进程读写裁决（map 是契约，进程不是）
pub const BLOCK_DECISIONS_PIN: &str = "/sys/fs/bpf/kernelsentinel_block_decisions";

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

/// 与 `bpf_ktime_get_ns()` 同源的 CLOCK_MONOTONIC 纳秒（unsafe FFI 收拢在 `crate::sys`）
pub fn monotonic_now_ns() -> u64 {
    crate::sys::monotonic_now_ns()
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

/// 一轮实杀的结果：实际执行的 pid 与被豁免跳过的 pid。
/// 豁免必须在 kill 之前判定——comm 是进程自设的，且读 comm 需要进程还活着。
pub struct KillTickOutcome {
    pub fired: Vec<(u32, BlockReason)>,
    pub exempt: Vec<u32>,
}

/// 非 Modern tier 的用户态实杀：老内核无 `bpf_send_signal`，`ks_check_block` 只查表不杀，
/// 由用户态读 block_decisions 全表补一刀（ADR-011 闭环在 Legacy/Ancient 上的出口）。
///
/// 纯函数便于测试：entries 为内核 map 全表，killed 记录"上次处理时的 expire"
/// （expire 变了说明同 pid 被重新裁决，要再处理），is_exempt 在 kill 前判定豁免
/// （保护名单、comm 匹配等），返回本轮实际执行 kill 的 pid 列表与被跳过的 pid 列表。
pub fn user_kill_tick(
    entries: &[(u32, u64, u8)],
    killed: &mut HashMap<u32, u64>,
    protected: &std::collections::HashSet<u32>,
    is_exempt: impl Fn(u32) -> bool,
    now_mono_ns: u64,
    kill_fn: impl Fn(u32) -> bool,
) -> KillTickOutcome {
    let mut out = KillTickOutcome {
        fired: Vec::new(),
        exempt: Vec::new(),
    };
    for &(pid, expire, reason) in entries {
        if pid == 0 || protected.contains(&pid) {
            continue;
        }
        if expire != 0 && expire <= now_mono_ns {
            continue;
        }
        if killed.get(&pid) == Some(&expire) {
            continue;
        }
        // 豁免判定先于 kill：读 /proc/pid/comm 需要进程存活，且豁免进程不能被杀
        if is_exempt(pid) {
            killed.insert(pid, expire);
            out.exempt.push(pid);
            continue;
        }
        if kill_fn(pid) {
            killed.insert(pid, expire);
            out.fired.push((pid, BlockReason::from_u8(reason)));
        } else {
            killed.remove(&pid);
        }
    }
    out
}

pub fn kill_pid_sigkill(pid: u32) -> bool {
    crate::sys::kill_sigkill(pid)
}

/// 系统进程 comm 保护（与内核 protected_comms 同一名单 + KS_PROTECTED_COMMS 扩展）：
/// killer 侧兜底，防手动 `ks block` 或误配置把 sshd 等写进裁决。
pub fn protected_comms() -> Vec<String> {
    let mut comms: Vec<String> = crate::loader::DEFAULT_PROTECTED_COMMS
        .iter()
        .map(|s| s.to_string())
        .collect();
    if let Ok(extra) = std::env::var("KS_PROTECTED_COMMS") {
        for c in extra.split(',') {
            let c = c.trim();
            if !c.is_empty() && !comms.iter().any(|x| x == c) {
                comms.push(c.to_string());
            }
        }
    }
    comms
}

#[cfg(target_os = "linux")]
pub fn comm_of(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

/// 与内核 `ks_exe_path_suspicious` 同款判定：exe 位于 /tmp、/dev/shm、/var/tmp
/// 等可写目录的进程不享受 comm 豁免（comm 可由 prctl(PR_SET_NAME) 伪造）。
/// 读不到 exe（内核线程、权限不足、进程已退出）时不判可疑。
#[cfg(target_os = "linux")]
pub fn exe_path_suspicious(pid: u32) -> bool {
    const PREFIXES: [&str; 3] = ["/tmp", "/dev/shm", "/var/tmp"];
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(p) => {
            let s = p.to_string_lossy();
            PREFIXES.iter().any(|pre| s.starts_with(pre))
        }
        Err(_) => false,
    }
}

/// 跨进程访问 pinned block_decisions 的薄封装（`ks block` 用）。
/// key [u8;8]=pid+pad，value [u8;16]=expire_mono(8)+reason(1)+pad(7)，
/// 与 common.h 的 block_key/block_value 逐字节对齐（native endian，同架构）。
#[cfg(target_os = "linux")]
pub struct PinnedBlockMap {
    inner: aya::maps::HashMap<aya::maps::MapData, [u8; 8], [u8; 16]>,
}

#[cfg(target_os = "linux")]
impl PinnedBlockMap {
    pub fn open() -> anyhow::Result<Self> {
        let md = aya::maps::MapData::from_pin(BLOCK_DECISIONS_PIN).map_err(|e| {
            anyhow::anyhow!(
                "打开 {} 失败: {} — 引擎未运行（引擎启动时才 pin）",
                BLOCK_DECISIONS_PIN,
                e
            )
        })?;
        Ok(Self {
            inner: aya::maps::HashMap::try_from(aya::maps::Map::HashMap(md))?,
        })
    }

    fn key(pid: u32) -> [u8; 8] {
        let mut k = [0u8; 8];
        k[..4].copy_from_slice(&pid.to_ne_bytes());
        k
    }

    pub fn write(&mut self, pid: u32, expire_mono_ns: u64, reason: u8) -> anyhow::Result<()> {
        let mut value = [0u8; 16];
        value[..8].copy_from_slice(&expire_mono_ns.to_ne_bytes());
        value[8] = reason;
        self.inner
            .insert(Self::key(pid), value, 0)
            .map_err(|e| anyhow::anyhow!("写入裁决失败: {}", e))
    }

    /// 返回 false = 该 pid 无裁决（aya 对 delete ENOENT 报 SyscallError 而非 KeyNotFound）
    pub fn remove(&mut self, pid: u32) -> anyhow::Result<bool> {
        match self.inner.remove(&Self::key(pid)) {
            Ok(_) => Ok(true),
            Err(aya::maps::MapError::SyscallError(aya::sys::SyscallError { io_error, .. }))
                if io_error.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(false)
            }
            Err(e) => Err(anyhow::anyhow!("删除裁决失败: {}", e)),
        }
    }

    pub fn entries(&self) -> Vec<(u32, u64, u8)> {
        let mut out = Vec::new();
        for (key, value) in self.inner.iter().flatten() {
            let pid = u32::from_ne_bytes(key[..4].try_into().unwrap_or([0; 4]));
            let expire = u64::from_ne_bytes(value[..8].try_into().unwrap_or([0; 8]));
            out.push((pid, expire, value[8]));
        }
        out
    }
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

#[cfg(test)]
mod user_kill_tests {
    use super::*;

    fn set(v: &[u32]) -> std::collections::HashSet<u32> {
        v.iter().copied().collect()
    }

    #[test]
    fn test_kills_active_decision_once() {
        let mut killed = HashMap::new();
        let now = 1_000_000;
        let entries = [(111, now + 60_000_000, BlockReason::Manual as u8)];
        let out = user_kill_tick(&entries, &mut killed, &set(&[]), |_| false, now, |p| {
            assert_eq!(p, 111);
            true
        });
        assert_eq!(out.fired.len(), 1);
        // 下一轮同 expire 不重复杀
        let out2 = user_kill_tick(&entries, &mut killed, &set(&[]), |_| false, now, |_| true);
        assert!(out2.fired.is_empty());
    }

    #[test]
    fn test_exempt_checked_before_kill() {
        // 豁免进程绝不能被 kill_fn 碰到（读 comm 需要进程存活，且豁免意味着不杀）
        let mut killed = HashMap::new();
        let now = 1_000_000;
        let entries = [(42, 0u64, BlockReason::Manual as u8)];
        let out = user_kill_tick(&entries, &mut killed, &set(&[]), |p| p == 42, now, |_| {
            panic!("豁免进程不应进入 kill_fn")
        });
        assert!(out.fired.is_empty());
        assert_eq!(out.exempt, vec![42]);
        // 已记录，下轮不再重复判定
        let out2 = user_kill_tick(&entries, &mut killed, &set(&[]), |_| true, now, |_| true);
        assert!(out2.exempt.is_empty() && out2.fired.is_empty());
    }

    #[test]
    fn test_permanent_and_expired() {
        let mut killed = HashMap::new();
        let now = 1_000_000;
        // expire=0 永久；expire<now 已过期不杀
        let entries = [(1, 0u64, 5u8), (2, now - 1, 1u8)];
        let out = user_kill_tick(&entries, &mut killed, &set(&[]), |_| false, now, |_| true);
        assert_eq!(out.fired, vec![(1, BlockReason::Manual)]);
    }

    #[test]
    fn test_protected_and_self_skipped() {
        let mut killed = HashMap::new();
        let now = 1_000_000;
        let entries = [(1, 0u64, 5u8), (42, 0u64, 5u8), (0, 0u64, 5u8)];
        let out = user_kill_tick(&entries, &mut killed, &set(&[1, 42]), |_| false, now, |_| {
            panic!("protected 条目不应触发 kill")
        });
        assert!(out.fired.is_empty());
    }

    #[test]
    fn test_rearm_on_expire_change() {
        let mut killed = HashMap::new();
        let now = 1_000_000;
        let e1 = [(111u32, now + 60_000_000u64, 5u8)];
        user_kill_tick(&e1, &mut killed, &set(&[]), |_| false, now, |_| true);
        // 同 pid 重新裁决（新 expire）→ 再杀
        let e2 = [(111u32, now + 120_000_000u64, 1u8)];
        let out = user_kill_tick(&e2, &mut killed, &set(&[]), |_| false, now, |_| true);
        assert_eq!(out.fired, vec![(111, BlockReason::RuleMatch)]);
    }

    #[test]
    fn test_kill_failure_does_not_remember() {
        let mut killed = HashMap::new();
        let now = 1_000_000;
        let entries = [(111, 0u64, 5u8)];
        // kill 失败不记 killed，下轮重试
        let out = user_kill_tick(&entries, &mut killed, &set(&[]), |_| false, now, |_| false);
        assert!(out.fired.is_empty());
        let out2 = user_kill_tick(&entries, &mut killed, &set(&[]), |_| false, now, |_| true);
        assert_eq!(out2.fired.len(), 1);
    }
}

//! 用户态反向阻断通道BlockManager。
//!
//! 申报书依据:阻断机制基于bpf_send_signal实现,风险分阈值设为大于等于70触发阻断。
//!
//! BlockManager维护一个内存中的阻断决策表(block_decisions),支持block_pid(pid, ttl, reason)添加阻断(带TTL过期)、unblock_pid(pid)解除阻断、list_blocked()列出所有被阻断的PID、is_blocked(pid)检查PID是否被阻断、cleanup_expired()清理过期条目。
//!
//! 当内核态阻断完成后,BlockManager可选地写入BPF block_decisions map,使内核探针在下次事件时读取map并调用bpf_send_signal(SIGKILL)。当前版本为用户态内存管理,不依赖BPF loader。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// 阻断原因编码
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    /// 规则匹配触发(severity >= 阈值)
    RuleMatch = 1,
    /// 基线偏离触发(z-score >= 5σ)
    BaselineDeviation = 2,
    /// ML异常检测触发
    MlAnomaly = 3,
    /// 关联引擎触发
    Correlation = 4,
    /// 手动阻断(REST API)
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

/// 被阻断的PID条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedPid {
    pub pid: u32,
    /// 阻断生效时间(UNIX纳秒)
    pub blocked_at_ns: u64,
    /// 过期时间(UNIX纳秒),0表示永久
    pub expiry_ns: u64,
    /// 阻断原因
    pub reason: BlockReason,
    /// 触发告警的规则名或描述
    pub trigger: String,
}

pub struct BlockManager {
    /// pid到BlockedPid的映射
    blocked: HashMap<u32, BlockedPid>,
    /// 是否启用阻断(false时block_pid静默返回Ok)
    enabled: bool,
    /// 默认TTL(秒)
    default_ttl: u64,
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
        }
    }

    pub fn with_config(enabled: bool, default_ttl: u64) -> Self {
        Self {
            blocked: HashMap::new(),
            enabled,
            default_ttl,
        }
    }

    /// 阻断指定PID。ttl_secs为0表示用默认TTL,返回是否实际添加了阻断(若已存在且未过期则更新)。
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
            now + ttl * 1_000_000_000
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
        true
    }

    /// 解除阻断
    pub fn unblock_pid(&mut self, pid: u32) -> bool {
        self.blocked.remove(&pid).is_some()
    }

    /// 检查PID是否被阻断(同时清理过期条目)
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

    /// 列出所有被阻断的PID(先清理过期条目)
    pub fn list_blocked(&mut self) -> Vec<BlockedPid> {
        self.cleanup_expired();
        self.blocked.values().cloned().collect()
    }

    /// 清理过期条目
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
        // 1秒TTL
        mgr.block_pid(1234, 1, BlockReason::Manual, "test");
        assert!(mgr.is_blocked(1234));
        // 等 1.1 秒
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
        // 等 1.1 秒让 200 过期
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
        // ttl_secs=0 → 使用默认 300
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
        // 再次阻断同PID,更新原因
        mgr.block_pid(1234, 60, BlockReason::MlAnomaly, "ml1");
        let list = mgr.list_blocked();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].reason, BlockReason::MlAnomaly);
    }
}

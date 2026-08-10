//! z-score统计基线偏离检测。
//! 给每个进程建立正常行为基线,算出偏差z-score,超过2σ告警。
//! 比detector.rs里硬编码的打分法更自适应。

use crate::aggregator::DecodedEvent;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorBaseline {
    pub pid: u32,
    pub comm: String,
    pub syscall_baseline: StatBaseline,
    pub file_ops_baseline: StatBaseline,
    pub net_ops_baseline: StatBaseline,
    pub dns_ops_baseline: StatBaseline,
    pub ptrace_ops_baseline: StatBaseline,
    pub signal_ops_baseline: StatBaseline,
    pub established_at_ns: u64,
    pub sample_count: u32,
    pub is_inherently_high_freq: bool,
    /// 最后一次更新该PID的时间戳,用于LRU淘汰不活跃PID,防止per-PID结构无界增长。
    pub last_seen_ns: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct StatBaseline {
    pub mean: f64,
    pub stddev: f64,
    pub max: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviationResult {
    pub pid: u32,
    pub deviations: Vec<DimensionDeviation>,
    pub overall_score: f64,
    pub most_deviated_dimension: Option<DeviationDimension>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionDeviation {
    pub dimension: DeviationDimension,
    pub current_value: f64,
    pub baseline_mean: f64,
    pub z_score: f64,
    pub severity: DeviationSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeviationDimension {
    SyscallFrequency,
    FileOpsFrequency,
    NetOpsFrequency,
    DnsOpsFrequency,
    PtraceOpsFrequency,
    SignalOpsFrequency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviationSeverity {
    Normal,
    Low,
    Medium,
    High,
    Critical,
}

const WINDOW_DURATION_NS: u64 = 60_000_000_000;
const INHERENTLY_HIGH_FREQ: &[&str] = &[
    "wget",
    "curl",
    "python",
    "python3",
    "node",
    "java",
    "chrome",
    "firefox",
    "nginx",
    "apache2",
    "httpd",
    "postgres",
    "mysql",
    "redis-server",
    "mongod",
    "systemd",
    "sshd",
    "cron",
];

pub struct BaselineManager {
    baselines: HashMap<u32, BehaviorBaseline>,
    freq_history: HashMap<u32, Vec<FreqSnapshot>>,
    max_history_windows: usize,
    z_score_threshold: f64,
    min_samples: u32,
    fixed_thresholds: FixedThresholds,
    established_pids: HashSet<u32>,
    /// per-PID结构容量上限。超过时按last_seen_ns淘汰最不活跃的PID,
    /// 防止长期运行下baselines/freq_history随累计PID数无界增长(RSS涨)。
    max_pids: usize,
}

#[derive(Debug, Clone, Copy)]
struct FreqSnapshot {
    syscall_count: u32,
    file_op_count: u32,
    net_op_count: u32,
    dns_op_count: u32,
    ptrace_count: u32,
    signal_count: u32,
    timestamp_ns: u64,
}

#[derive(Debug, Clone, Copy)]
struct FixedThresholds {
    syscall_60s: u32,
    file_ops_60s: u32,
    net_ops_60s: u32,
    dns_ops_60s: u32,
    ptrace_60s: u32,
    signal_60s: u32,
}

impl Default for BaselineManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BaselineManager {
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            freq_history: HashMap::new(),
            max_history_windows: 20,
            z_score_threshold: 2.0,
            min_samples: 5,
            max_pids: 10000,
            fixed_thresholds: FixedThresholds {
                syscall_60s: 5000,
                file_ops_60s: 500,
                net_ops_60s: 100,
                dns_ops_60s: 50,
                ptrace_60s: 3,
                signal_60s: 10,
            },
            established_pids: HashSet::new(),
        }
    }

    /// 每个事件都要调用,更新当前窗口计数。
    /// 窗口满60秒自动创建新窗口。
    pub fn update_from_event(&mut self, event: &DecodedEvent) {
        let pid = event.header.pid;
        let comm = event.comm.clone();
        let is_high_freq = INHERENTLY_HIGH_FREQ.iter().any(|p| comm.contains(p));

        let history = self.freq_history.entry(pid).or_default();

        let is_file = (10..=15).contains(&event.header.event_type);
        let is_net = (20..=24).contains(&event.header.event_type);
        let is_dns = event.header.event_type == 24;
        let is_ptrace = event.header.event_type == 30;
        let is_signal = event.header.event_type == 31;

        if history.is_empty() {
            history.push(FreqSnapshot {
                syscall_count: 1,
                file_op_count: if is_file { 1 } else { 0 },
                net_op_count: if is_net { 1 } else { 0 },
                dns_op_count: if is_dns { 1 } else { 0 },
                ptrace_count: if is_ptrace { 1 } else { 0 },
                signal_count: if is_signal { 1 } else { 0 },
                timestamp_ns: event.header.timestamp_ns,
            });
        } else {
            let elapsed = event
                .header
                .timestamp_ns
                .saturating_sub(history.last().unwrap().timestamp_ns);
            if elapsed >= WINDOW_DURATION_NS {
                history.push(FreqSnapshot {
                    syscall_count: 1,
                    file_op_count: if is_file { 1 } else { 0 },
                    net_op_count: if is_net { 1 } else { 0 },
                    dns_op_count: if is_dns { 1 } else { 0 },
                    ptrace_count: if is_ptrace { 1 } else { 0 },
                    signal_count: if is_signal { 1 } else { 0 },
                    timestamp_ns: event.header.timestamp_ns,
                });
            } else {
                let cur = history.last_mut().unwrap();
                cur.syscall_count += 1;
                match event.header.event_type {
                    10..=15 => cur.file_op_count += 1,
                    20..=23 => cur.net_op_count += 1,
                    24 => {
                        cur.dns_op_count += 1;
                        cur.net_op_count += 1;
                    }
                    30 => cur.ptrace_count += 1,
                    31 => cur.signal_count += 1,
                    _ => {}
                }
            }
        }

        while history.len() > self.max_history_windows {
            history.remove(0);
        }

        if !self.established_pids.contains(&pid) {
            let completed = history.iter().filter(|s| s.syscall_count > 1).count();
            if completed >= self.min_samples as usize {
                self.recalculate_baseline(pid, &comm, is_high_freq);
                self.established_pids.insert(pid);
            }
        } else if let Some(b) = self.baselines.get_mut(&pid) {
            // 已建立基线的PID,刷新last_seen,供LRU淘汰判断活跃度。
            b.last_seen_ns = event.header.timestamp_ns;
        }

        // 容量上限淘汰:per-PID结构随累计PID数无界增长(84核机器3小时见6.5万PID)。
        // 守卫查freq_history而非baselines:短命进程fork后活不到min_samples=5进不了baselines,
        // 只在freq_history留1~2个snapshot,若查baselines.len()则淘汰永不触发,freq_history无界涨。
        if self.freq_history.len() > self.max_pids {
            self.evict_inactive_pids();
        }
    }

    /// 淘汰最不活跃的PID:freq_history比baselines多(短命进程只进freq_history),
    /// 所以以freq_history为淘汰主表,按其snapshot的timestamp_ns升序删最不活跃PID。
    /// 同步清理baselines/established_pids中对应entry。
    fn evict_inactive_pids(&mut self) {
        let target = self.max_pids.saturating_sub(self.max_pids / 10);
        while self.freq_history.len() > target {
            // 找freq_history里最早snapshot的PID(最不活跃)
            let evict_pid = match self.freq_history.iter().min_by_key(|(_, snaps)| {
                snaps.last().map(|s| s.timestamp_ns).unwrap_or(u64::MAX)
            }) {
                Some((p, _)) => *p,
                None => break,
            };
            self.freq_history.remove(&evict_pid);
            self.baselines.remove(&evict_pid);
            self.established_pids.remove(&evict_pid);
        }
    }

    fn recalculate_baseline(&mut self, pid: u32, comm: &str, is_high_freq: bool) {
        let snapshots = match self.freq_history.get(&pid) {
            Some(h) if h.len() >= self.min_samples as usize => h,
            _ => return,
        };

        self.baselines.insert(
            pid,
            BehaviorBaseline {
                pid,
                comm: comm.to_string(),
                syscall_baseline: calc_baseline(snapshots.iter().map(|s| s.syscall_count as f64)),
                file_ops_baseline: calc_baseline(snapshots.iter().map(|s| s.file_op_count as f64)),
                net_ops_baseline: calc_baseline(snapshots.iter().map(|s| s.net_op_count as f64)),
                dns_ops_baseline: calc_baseline(snapshots.iter().map(|s| s.dns_op_count as f64)),
                ptrace_ops_baseline: calc_baseline(snapshots.iter().map(|s| s.ptrace_count as f64)),
                signal_ops_baseline: calc_baseline(snapshots.iter().map(|s| s.signal_count as f64)),
                established_at_ns: snapshots.first().unwrap().timestamp_ns,
                sample_count: snapshots.len() as u32,
                is_inherently_high_freq: is_high_freq,
                last_seen_ns: snapshots.last().unwrap().timestamp_ns,
            },
        );
    }

    /// 基线偏离检测:手动解除某PID的一次性训练锁定并立即重算基线。
    /// 用于运维在确认某进程行为合法变更后手动重训练,避免基线被异常数据稀释后锁死。
    pub fn refresh_baseline(&mut self, pid: u32) {
        self.established_pids.remove(&pid);
        let (comm, is_high_freq, has_baseline) = match self.baselines.get(&pid) {
            Some(b) => (b.comm.clone(), b.is_inherently_high_freq, true),
            None => (String::new(), false, false),
        };
        let enough = has_baseline
            && self
                .freq_history
                .get(&pid)
                .map_or(0, |h| h.len())
                >= self.min_samples as usize;
        if enough {
            self.recalculate_baseline(pid, &comm, is_high_freq);
            self.established_pids.insert(pid);
        }
    }

    /// 检测当前窗口的偏离度
    pub fn detect_deviation(&self, pid: u32) -> Option<DeviationResult> {
        let history = self.freq_history.get(&pid)?;
        let current = history.last()?;
        let baseline = self.baselines.get(&pid);

        let mut deviations = Vec::new();
        let mut max_z = 0.0;
        let mut most = None;

        let dims = [
            (
                DeviationDimension::SyscallFrequency,
                current.syscall_count as f64,
                baseline.map(|b| b.syscall_baseline),
                self.fixed_thresholds.syscall_60s,
            ),
            (
                DeviationDimension::FileOpsFrequency,
                current.file_op_count as f64,
                baseline.map(|b| b.file_ops_baseline),
                self.fixed_thresholds.file_ops_60s,
            ),
            (
                DeviationDimension::NetOpsFrequency,
                current.net_op_count as f64,
                baseline.map(|b| b.net_ops_baseline),
                self.fixed_thresholds.net_ops_60s,
            ),
            (
                DeviationDimension::DnsOpsFrequency,
                current.dns_op_count as f64,
                baseline.map(|b| b.dns_ops_baseline),
                self.fixed_thresholds.dns_ops_60s,
            ),
            (
                DeviationDimension::PtraceOpsFrequency,
                current.ptrace_count as f64,
                baseline.map(|b| b.ptrace_ops_baseline),
                self.fixed_thresholds.ptrace_60s,
            ),
            (
                DeviationDimension::SignalOpsFrequency,
                current.signal_count as f64,
                baseline.map(|b| b.signal_ops_baseline),
                self.fixed_thresholds.signal_60s,
            ),
        ];

        for (dim, val, sb, ft) in &dims {
            let z = if let Some(s) = sb {
                if s.stddev > 0.0 {
                    (val - s.mean) / s.stddev
                } else if *val > s.mean {
                    3.0
                } else {
                    0.0
                }
            } else if *val > *ft as f64 {
                5.0
            } else {
                0.0
            };

            if z > self.z_score_threshold {
                deviations.push(DimensionDeviation {
                    dimension: *dim,
                    current_value: *val,
                    baseline_mean: sb.map(|s| s.mean).unwrap_or(0.0),
                    z_score: z,
                    severity: classify_severity(z),
                });
                if z > max_z {
                    max_z = z;
                    most = Some(*dim);
                }
            }
        }

        if deviations.is_empty() {
            return None;
        }
        Some(DeviationResult {
            pid,
            deviations,
            overall_score: (max_z / 5.0).min(1.0),
            most_deviated_dimension: most,
        })
    }

    pub fn get_baseline(&self, pid: u32) -> Option<&BehaviorBaseline> {
        self.baselines.get(&pid)
    }
    pub fn all_baselines(&self) -> &HashMap<u32, BehaviorBaseline> {
        &self.baselines
    }
}

fn calc_baseline(values: impl Iterator<Item = f64>) -> StatBaseline {
    let vals: Vec<f64> = values.collect();
    if vals.is_empty() {
        return StatBaseline::default();
    }
    let n = vals.len() as f64;
    let mean = vals.iter().sum::<f64>() / n;
    let variance = if n > 1.0 {
        vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / n
    } else {
        0.0
    };
    StatBaseline {
        mean,
        stddev: variance.sqrt(),
        max: vals.iter().fold(0.0_f64, |a, b| a.max(*b)),
    }
}

fn classify_severity(z: f64) -> DeviationSeverity {
    if z < 2.0 {
        DeviationSeverity::Normal
    } else if z < 3.0 {
        DeviationSeverity::Low
    } else if z < 4.0 {
        DeviationSeverity::Medium
    } else if z < 5.0 {
        DeviationSeverity::High
    } else {
        DeviationSeverity::Critical
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::event::EventHeader;

    fn make_event(seq: u64, pid: u32, et: u32, comm: &str) -> DecodedEvent {
        let mut cb = [0u8; 16];
        let len = comm.len().min(16);
        cb[..len].copy_from_slice(&comm.as_bytes()[..len]);
        DecodedEvent {
            seq,
            comm: comm.to_string(),
            header: EventHeader {
                event_type: et,
                _pad1: 0,
                timestamp_ns: seq * 1_000_000_000,
                pid,
                tid: 0,
                uid: 0,
                ppid: 0,
                comm: cb,
                syscall_nr: 0,
                _pad2: 0,
                retval: 0,
            },
            filename: None,
            args: None,
            saddr: None,
            daddr: None,
            sport: None,
            dport: None,
            proto: None,
            target_pid: None,
            signal: None,
            file_bytes: None,
            module_name: None,
            prog_name: None,
            source_ns_inum: None,
            target_ns_inum: None,
            cap_eff: None,
            action: None,
        }
    }

    #[test]
    fn test_baseline_building() {
        let mut mgr = BaselineManager::new();
        for i in 0..5 {
            for _ in 0..20 {
                mgr.update_from_event(&make_event(i * 60 + 1, 1234, 12, "cat"));
            }
            mgr.update_from_event(&make_event((i + 1) * 60, 1234, 1, "cat"));
        }
        assert!(mgr.get_baseline(1234).is_some());
    }

    #[test]
    fn test_deviation_detection() {
        let mut mgr = BaselineManager::new();
        for i in 0..5 {
            for j in 0..5 {
                mgr.update_from_event(&make_event(i * 60 + j + 1, 1234, 12, "cat"));
            }
            mgr.update_from_event(&make_event((i + 1) * 60, 1234, 1, "cat"));
        }
        for i in 0..500 {
            mgr.update_from_event(&make_event(301 + i, 1234, 12, "cat"));
        }
        let result = mgr.detect_deviation(1234);
        assert!(result.is_some());
        assert!(result.unwrap().overall_score > 0.0);
    }

    #[test]
    fn test_no_deviation_for_normal() {
        let mut mgr = BaselineManager::new();
        for i in 0..5 {
            for j in 0..10 {
                mgr.update_from_event(&make_event(i * 60 + j + 1, 1234, 1, "ls"));
            }
        }
        if let Some(dev) = mgr.detect_deviation(1234) {
            assert!(dev.overall_score < 0.5);
        }
    }

    #[test]
    fn test_severity() {
        assert_eq!(classify_severity(2.5), DeviationSeverity::Low);
        assert_eq!(classify_severity(6.0), DeviationSeverity::Critical);
    }
}

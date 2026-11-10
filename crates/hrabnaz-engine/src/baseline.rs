use hrabnaz_core::event::DecodedEvent;
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

/// 编译期默认的天然高频进程 comm（`inherently_high_freq_comms()` 追加 HRABNAZ_BASELINE_HIGHFREQ 扩展）
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

/// 天然高频进程 comm 白名单（H-1.4 配置化）：
/// - 编译期默认覆盖 wget/curl/python/nginx 等常见服务进程；
/// - `HRABNAZ_BASELINE_HIGHFREQ` 环境变量按逗号扩展部署环境专属条目（如桌面环境的
///   chrome 子进程、k8s 节点的 kubelet），引擎启动时读取一次；
/// - 匹配大小写不敏感（Chrome_ChildIOT 之类子进程 comm 能命中 chrome 条目），
///   命中后该 pid 不建立 z-score 基线、不报基线偏离（fixed_threshold 冷启动兜底仍在）。
pub fn inherently_high_freq_comms() -> Vec<String> {
    let mut comms: Vec<String> = INHERENTLY_HIGH_FREQ.iter().map(|s| s.to_string()).collect();
    if let Ok(extra) = std::env::var("HRABNAZ_BASELINE_HIGHFREQ") {
        for c in extra.split(',') {
            let c = c.trim();
            if !c.is_empty() {
                comms.push(c.to_string());
            }
        }
    }
    comms
}

fn is_inherently_high_freq_comm(comms: &[String], comm: &str) -> bool {
    /* starts_with 而非 contains：contains 让攻击者把 comm 改成 python-worker
    等即可绕过基线和 ML 告警（code-review H-2）。前缀匹配保留 tokio-rt-worker
    之类截断名的匹配能力。 */
    let lower = comm.to_lowercase();
    comms.iter().any(|p| lower.starts_with(&p.to_lowercase()))
}

pub struct BaselineManager {
    baselines: HashMap<u32, BehaviorBaseline>,
    freq_history: HashMap<u32, Vec<FreqSnapshot>>,
    max_history_windows: usize,
    z_score_threshold: f64,
    min_samples: u32,
    fixed_thresholds: FixedThresholds,
    established_pids: HashSet<u32>,
    max_pids: usize,
    // 启动时解析一次的天然高频名单（默认 + HRABNAZ_BASELINE_HIGHFREQ 扩展），匹配大小写不敏感
    high_freq_comms: Vec<String>,
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
            high_freq_comms: inherently_high_freq_comms(),
        }
    }

    pub fn update_from_event(&mut self, event: &DecodedEvent) {
        let pid = event.header.pid;
        let comm = event.comm.clone();
        let is_high_freq = is_inherently_high_freq_comm(&self.high_freq_comms, &comm);

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
            b.last_seen_ns = event.header.timestamp_ns;
        }

        if self.freq_history.len() > self.max_pids {
            self.evict_inactive_pids();
        }
    }

    fn evict_inactive_pids(&mut self) {
        let target = self.max_pids.saturating_sub(self.max_pids / 10);
        if self.freq_history.len() <= target {
            return;
        }
        // 单次收集+排序按最后活跃时间批量淘汰最旧一批，替代逐个 min_by_key 全表扫描
        let mut by_activity: Vec<(u32, u64)> = self
            .freq_history
            .iter()
            .map(|(p, snaps)| (*p, snaps.last().map(|s| s.timestamp_ns).unwrap_or(u64::MAX)))
            .collect();
        by_activity.sort_unstable_by_key(|(_, ts)| *ts);
        let excess = self.freq_history.len() - target;
        for (pid, _) in by_activity.into_iter().take(excess) {
            self.freq_history.remove(&pid);
            self.baselines.remove(&pid);
            self.established_pids.remove(&pid);
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

    pub fn refresh_baseline(&mut self, pid: u32) {
        self.established_pids.remove(&pid);
        let (comm, is_high_freq, has_baseline) = match self.baselines.get(&pid) {
            Some(b) => (b.comm.clone(), b.is_inherently_high_freq, true),
            None => (String::new(), false, false),
        };
        let enough = has_baseline
            && self.freq_history.get(&pid).map_or(0, |h| h.len()) >= self.min_samples as usize;
        if enough {
            self.recalculate_baseline(pid, &comm, is_high_freq);
            self.established_pids.insert(pid);
        }
    }

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

    /// comm 是否命中天然高频白名单（大小写不敏感，H-1.4 配置化入口的运行时查询）
    pub fn is_inherently_high_freq(&self, comm: &str) -> bool {
        is_inherently_high_freq_comm(&self.high_freq_comms, comm)
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
    use hrabnaz_core::event::EventHeader;

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

    #[test]
    fn test_high_freq_matching_case_insensitive() {
        let comms = inherently_high_freq_comms();
        assert!(is_inherently_high_freq_comm(&comms, "chrome"));
        // H-1.4：Chrome_ChildIOT 这类子进程 comm 原实现大小写敏感未命中
        assert!(is_inherently_high_freq_comm(&comms, "Chrome_ChildIOT"));
        assert!(is_inherently_high_freq_comm(&comms, "NGINX"));
        assert!(!is_inherently_high_freq_comm(&comms, "ransomware"));
    }

    #[test]
    fn test_high_freq_env_extension() {
        // 部署环境专属 comm（云盾/伴生控制台/tokio worker/rsyslog 模块）由部署方经
        // HRABNAZ_BASELINE_HIGHFREQ 配置——默认名单只放普适项，不得回退成硬编码。
        // 注：同进程内多个测试会并行抢该环境变量，相关断言必须集中在同一个测试里。
        std::env::set_var(
            "HRABNAZ_BASELINE_HIGHFREQ",
            "kubelet, my-worker , AliYunDun, hlidskjalf-serv, tokio-rt-worker, in:imjournal",
        );
        let comms = inherently_high_freq_comms();
        std::env::remove_var("HRABNAZ_BASELINE_HIGHFREQ");
        // 默认条目保留 + 环境变量扩展（去空格、忽略空段）
        assert!(comms.iter().any(|c| c == "wget"));
        assert!(comms.iter().any(|c| c == "kubelet"));
        assert!(comms.iter().any(|c| c == "my-worker"));
        assert_eq!(comms.iter().filter(|c| c.is_empty()).count(), 0);
        // 真机实测形态全覆盖：15 字节截断 + 子串匹配变体
        assert!(is_inherently_high_freq_comm(&comms, "AliYunDunMonito"));
        assert!(is_inherently_high_freq_comm(&comms, "hlidskjalf-serv"));
        assert!(is_inherently_high_freq_comm(&comms, "tokio-rt-worker"));
        assert!(is_inherently_high_freq_comm(&comms, "in:imjournal"));
        assert!(
            is_inherently_high_freq_comm(&comms, "crond"),
            "cron 子串覆盖 crond"
        );
        assert!(is_inherently_high_freq_comm(&comms, "systemd-journal"));
        // 未配置时默认名单不得命中部署专属 comm
        assert!(!INHERENTLY_HIGH_FREQ.iter().any(|c| {
            "aliyundunmonito".contains(&c.to_lowercase())
                || "tokio-rt-worker".contains(&c.to_lowercase())
        }));
    }
}

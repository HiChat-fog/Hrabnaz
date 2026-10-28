use ks_core::event::DecodedEvent;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const DEFAULT_ALPHA: f64 = 0.3;

const COLD_START_SAMPLES: usize = 5;

const DEFAULT_Z_THRESHOLD: f64 = 2.0;

const FALSE_POSITIVE_THRESHOLD_BOOST: f64 = 1.1;

const THRESHOLD_DECAY_INTERVAL: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MlDimension {
    SyscallFrequency,
    FileOpsFrequency,
    NetOpsFrequency,
    DnsOpsFrequency,
    PtraceOpsFrequency,
    SignalOpsFrequency,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EwmaState {
    pub mean: f64,
    pub variance: f64,
    pub last_update_ns: u64,
    pub sample_count: usize,
}

impl Default for EwmaState {
    fn default() -> Self {
        Self {
            mean: 0.0,
            variance: 0.0,
            last_update_ns: 0,
            sample_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResult {
    pub pid: u32,
    pub dimensions: Vec<MlDimensionAnomaly>,
    pub overall_score: f64,
    pub model: AnomalyModel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyModel {
    Ewma,
    ColdStart,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlDimensionAnomaly {
    pub dimension: MlDimension,
    pub current_value: f64,
    pub ewma_mean: f64,
    pub z_score: f64,
    pub threshold: f64,
}

#[derive(Debug, Clone, Copy, Default)]
struct WindowSnapshot {
    syscall_count: u32,
    file_op_count: u32,
    net_op_count: u32,
    dns_op_count: u32,
    ptrace_count: u32,
    signal_count: u32,
    timestamp_ns: u64,
}

const WINDOW_DURATION_NS: u64 = 60_000_000_000;

const DEFAULT_OBSERVE_SEC: u64 = 180;

pub struct AdaptiveDetector {
    states: HashMap<(u32, MlDimension), EwmaState>,
    current_windows: HashMap<u32, WindowSnapshot>,
    pid_sample_counts: HashMap<u32, usize>,
    threshold_multipliers: HashMap<u32, f64>,
    normal_samples_since_feedback: HashMap<u32, usize>,
    alpha: f64,
    z_threshold: f64,
    cold_start_samples: usize,
    fixed_thresholds: FixedThresholds,
    observe_until: Option<std::time::Instant>,
    max_pids: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct FixedThresholds {
    pub syscall_60s: u32,
    pub file_ops_60s: u32,
    pub net_ops_60s: u32,
    pub dns_ops_60s: u32,
    pub ptrace_60s: u32,
    pub signal_60s: u32,
}

impl Default for FixedThresholds {
    fn default() -> Self {
        Self {
            syscall_60s: 5000,
            file_ops_60s: 500,
            net_ops_60s: 100,
            dns_ops_60s: 50,
            ptrace_60s: 3,
            signal_60s: 10,
        }
    }
}

impl Default for AdaptiveDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AdaptiveDetector {
    pub fn new() -> Self {
        Self {
            states: HashMap::new(),
            current_windows: HashMap::new(),
            pid_sample_counts: HashMap::new(),
            threshold_multipliers: HashMap::new(),
            normal_samples_since_feedback: HashMap::new(),
            alpha: DEFAULT_ALPHA,
            z_threshold: DEFAULT_Z_THRESHOLD,
            cold_start_samples: COLD_START_SAMPLES,
            fixed_thresholds: FixedThresholds::default(),
            observe_until: None,
            max_pids: 10_000,
        }
    }

    pub fn with_alpha(alpha: f64) -> Self {
        let mut d = Self::new();
        d.alpha = alpha;
        d
    }

    pub fn with_config(fixed_thresholds: FixedThresholds, observe_sec: u64) -> Self {
        let mut d = Self::new();
        d.fixed_thresholds = fixed_thresholds;
        if observe_sec > 0 {
            // 用 Instant 缓存学习期截止时刻：旧实现每次判定都同步读 /proc/uptime，
            // 而 detect() 对每个事件每个 pid 都会调它——热路径上的文件系统 syscall
            d.observe_until =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(observe_sec));
        }
        d
    }

    pub fn in_observe_period(&self) -> bool {
        self.observe_until
            .is_some_and(|deadline| std::time::Instant::now() < deadline)
    }

    pub fn from_env() -> Self {
        let mut thresholds = FixedThresholds::default();
        if let Ok(v) = std::env::var("KS_ML_SYSCALL_60S") {
            if let Ok(n) = v.parse::<u32>() {
                thresholds.syscall_60s = n;
            }
        }
        if let Ok(v) = std::env::var("KS_ML_FILE_OPS_60S") {
            if let Ok(n) = v.parse::<u32>() {
                thresholds.file_ops_60s = n;
            }
        }
        if let Ok(v) = std::env::var("KS_ML_NET_OPS_60S") {
            if let Ok(n) = v.parse::<u32>() {
                thresholds.net_ops_60s = n;
            }
        }
        if let Ok(v) = std::env::var("KS_ML_DNS_OPS_60S") {
            if let Ok(n) = v.parse::<u32>() {
                thresholds.dns_ops_60s = n;
            }
        }
        let observe_sec = std::env::var("KS_ML_OBSERVE_SEC")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_OBSERVE_SEC);
        log::info!(
            "ML学习期: {}s (0=关闭), 冷启动阈值 syscall={}/file={}/net={}/dns={}",
            observe_sec,
            thresholds.syscall_60s,
            thresholds.file_ops_60s,
            thresholds.net_ops_60s,
            thresholds.dns_ops_60s
        );
        Self::with_config(thresholds, observe_sec)
    }

    pub fn update_from_event(&mut self, event: &DecodedEvent) {
        let pid = event.header.pid;
        let ts = event.header.timestamp_ns;

        let is_file = (10..=15).contains(&event.header.event_type);
        let is_net = (20..=24).contains(&event.header.event_type);
        let is_dns = event.header.event_type == 24;
        let is_ptrace = event.header.event_type == 30;
        let is_signal = event.header.event_type == 31;

        let mut window = self.current_windows.get(&pid).copied().unwrap_or_default();
        if window.timestamp_ns == 0 {
            window.timestamp_ns = ts;
        }

        let elapsed = ts.saturating_sub(window.timestamp_ns);
        if elapsed >= WINDOW_DURATION_NS {
            self.commit_window(pid, &window);
            window = WindowSnapshot {
                syscall_count: 1,
                file_op_count: if is_file { 1 } else { 0 },
                net_op_count: if is_net { 1 } else { 0 },
                dns_op_count: if is_dns { 1 } else { 0 },
                ptrace_count: if is_ptrace { 1 } else { 0 },
                signal_count: if is_signal { 1 } else { 0 },
                timestamp_ns: ts,
            };
        } else {
            window.syscall_count += 1;
            match event.header.event_type {
                10..=15 => window.file_op_count += 1,
                20..=23 => window.net_op_count += 1,
                24 => {
                    window.dns_op_count += 1;
                    window.net_op_count += 1;
                }
                30 => window.ptrace_count += 1,
                31 => window.signal_count += 1,
                _ => {}
            }
        }
        self.current_windows.insert(pid, window);

        if let Some(count) = self.normal_samples_since_feedback.get_mut(&pid) {
            *count += 1;
            if *count >= THRESHOLD_DECAY_INTERVAL {
                if let Some(mult) = self.threshold_multipliers.get_mut(&pid) {
                    *mult = (*mult / FALSE_POSITIVE_THRESHOLD_BOOST).max(1.0);
                }
                *count = 0;
            }
        }

        if self.current_windows.len() > self.max_pids {
            self.evict_inactive_pids();
        }
    }

    fn evict_inactive_pids(&mut self) {
        let target = self.max_pids.saturating_sub(self.max_pids / 10);
        if self.current_windows.len() <= target {
            return;
        }
        // 单次收集+排序取最旧的一批一次性淘汰：旧实现每淘汰 1 个 pid 就
        // min_by_key 全表扫一遍（触发时单事件千万级比较）
        let mut by_activity: Vec<(u32, u64)> = self
            .current_windows
            .iter()
            .map(|(p, w)| (*p, w.timestamp_ns))
            .collect();
        by_activity.sort_unstable_by_key(|(_, ts)| *ts);
        let excess = self.current_windows.len() - target;
        for (pid, _) in by_activity.into_iter().take(excess) {
            self.current_windows.remove(&pid);
            self.pid_sample_counts.remove(&pid);
            self.threshold_multipliers.remove(&pid);
            self.normal_samples_since_feedback.remove(&pid);
            self.states.retain(|(p, _), _| *p != pid);
        }
    }

    fn commit_window(&mut self, pid: u32, window: &WindowSnapshot) {
        let dims = [
            (MlDimension::SyscallFrequency, window.syscall_count as f64),
            (MlDimension::FileOpsFrequency, window.file_op_count as f64),
            (MlDimension::NetOpsFrequency, window.net_op_count as f64),
            (MlDimension::DnsOpsFrequency, window.dns_op_count as f64),
            (MlDimension::PtraceOpsFrequency, window.ptrace_count as f64),
            (MlDimension::SignalOpsFrequency, window.signal_count as f64),
        ];

        for (dim, val) in &dims {
            let state = self.states.entry((pid, *dim)).or_default();

            if state.sample_count == 0 {
                state.mean = *val;
                state.variance = 0.0;
            } else {
                let old_mean = state.mean;
                let diff = *val - old_mean;
                state.mean = self.alpha * *val + (1.0 - self.alpha) * old_mean;
                state.variance = (1.0 - self.alpha) * (state.variance + self.alpha * diff * diff);
            }
            state.last_update_ns = window.timestamp_ns;
            state.sample_count += 1;
        }

        *self.pid_sample_counts.entry(pid).or_insert(0) += 1;
    }

    pub fn detect(&self, pid: u32) -> Option<AnomalyResult> {
        if self.in_observe_period() {
            return None;
        }
        let window = self.current_windows.get(&pid)?;
        let sample_count = self.pid_sample_counts.get(&pid).copied().unwrap_or(0);

        let threshold_mult = self.threshold_multipliers.get(&pid).copied().unwrap_or(1.0);

        let dims = [
            (
                MlDimension::SyscallFrequency,
                window.syscall_count as f64,
                self.fixed_thresholds.syscall_60s as f64,
            ),
            (
                MlDimension::FileOpsFrequency,
                window.file_op_count as f64,
                self.fixed_thresholds.file_ops_60s as f64,
            ),
            (
                MlDimension::NetOpsFrequency,
                window.net_op_count as f64,
                self.fixed_thresholds.net_ops_60s as f64,
            ),
            (
                MlDimension::DnsOpsFrequency,
                window.dns_op_count as f64,
                self.fixed_thresholds.dns_ops_60s as f64,
            ),
            (
                MlDimension::PtraceOpsFrequency,
                window.ptrace_count as f64,
                self.fixed_thresholds.ptrace_60s as f64,
            ),
            (
                MlDimension::SignalOpsFrequency,
                window.signal_count as f64,
                self.fixed_thresholds.signal_60s as f64,
            ),
        ];

        let mut anomalies = Vec::new();
        let mut max_z = 0.0;

        let mut used_ewma = false;
        for (dim, val, fixed_threshold) in &dims {
            let state = self.states.get(&(pid, *dim));

            let (z, ewma_mean, threshold) = if sample_count >= self.cold_start_samples {
                if let Some(s) = state {
                    used_ewma = true;
                    let stddev = s.variance.sqrt();
                    let z = if stddev > 0.0 {
                        /* 单侧偏离（与 baseline.rs 一致）：低于均值不告警 */
                        if val > &s.mean {
                            (val - s.mean) / stddev
                        } else {
                            0.0
                        }
                    } else if val > &s.mean {
                        3.0
                    } else {
                        0.0
                    };
                    let thr = self.z_threshold * threshold_mult;
                    (z, s.mean, thr)
                } else {
                    let z = if *val > *fixed_threshold { 5.0 } else { 0.0 };
                    let thr = self.z_threshold * threshold_mult;
                    (z, 0.0, thr)
                }
            } else {
                let z = if *val > *fixed_threshold { 5.0 } else { 0.0 };
                let thr = self.z_threshold * threshold_mult;
                (z, 0.0, thr)
            };

            if z > threshold {
                anomalies.push(MlDimensionAnomaly {
                    dimension: *dim,
                    current_value: *val,
                    ewma_mean,
                    z_score: z,
                    threshold,
                });
                if z > max_z {
                    max_z = z;
                }
            }
        }

        if anomalies.is_empty() {
            return None;
        }

        let model = if used_ewma {
            AnomalyModel::Ewma
        } else {
            AnomalyModel::ColdStart
        };

        Some(AnomalyResult {
            pid,
            dimensions: anomalies,
            overall_score: (max_z / 5.0).min(1.0),
            model,
        })
    }

    pub fn false_feedback(&mut self, pid: u32, is_false_positive: bool) {
        if is_false_positive {
            let mult = self.threshold_multipliers.entry(pid).or_insert(1.0);
            *mult *= FALSE_POSITIVE_THRESHOLD_BOOST;
            self.normal_samples_since_feedback.insert(pid, 0);
        }
    }

    pub fn get_state(&self, pid: u32, dim: MlDimension) -> Option<&EwmaState> {
        self.states.get(&(pid, dim))
    }

    pub fn get_threshold_multiplier(&self, pid: u32) -> f64 {
        self.threshold_multipliers.get(&pid).copied().unwrap_or(1.0)
    }

    pub fn window_count(&self, pid: u32) -> usize {
        self.pid_sample_counts.get(&pid).copied().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::EventAggregator;

    fn make_event(seq: u64, pid: u32, et: u32, comm: &str, ts_ns: u64) -> DecodedEvent {
        let mut data = vec![0u8; core::mem::size_of::<ks_core::event::ExecEvent>()];
        let etype: u32 = et;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let ts_off = 8;
        data[ts_off..ts_off + 8].copy_from_slice(&ts_ns.to_ne_bytes());
        let pid_off = 16;
        data[pid_off..pid_off + 4].copy_from_slice(&pid.to_ne_bytes());
        let comm_off = 28;
        let comm_bytes = comm.as_bytes();
        let copy_len = comm_bytes.len().min(16);
        data[comm_off..comm_off + copy_len].copy_from_slice(&comm_bytes[..copy_len]);

        let mut agg = EventAggregator::new(100);
        let _ = seq;
        (*agg.decode(&data).expect("decode failed")).clone()
    }

    #[test]
    fn test_ewma_converges_to_steady_state() {
        let mut det = AdaptiveDetector::new();
        let pid = 1000;
        let base_ts = 1_000_000_000;

        for i in 0..10 {
            for j in 0..100 {
                let ts = base_ts + i * WINDOW_DURATION_NS + j * 1_000_000;
                let event = make_event(i * 100 + j, pid, 1, "test", ts);
                det.update_from_event(&event);
            }
            if i < 9 {
                let ts = base_ts + (i + 1) * WINDOW_DURATION_NS;
                let event = make_event(999, pid, 1, "test", ts);
                det.update_from_event(&event);
            }
        }

        let state = det.get_state(pid, MlDimension::SyscallFrequency).unwrap();
        assert!(state.sample_count >= 9);
        assert!(
            state.mean > 50.0 && state.mean < 150.0,
            "EWMA mean should be near 100, got {}",
            state.mean
        );
        let result = det.detect(pid);
        assert!(
            result.is_none(),
            "Steady-state should not trigger anomaly: {:?}",
            result
        );
    }

    #[test]
    fn test_cold_start_uses_fixed_threshold() {
        let mut det = AdaptiveDetector::new();
        let pid = 2000;
        let base_ts = 1_000_000_000;

        for i in 0..2 {
            for j in 0..200 {
                let ts = base_ts + i * WINDOW_DURATION_NS + j * 1_000_000;
                let event = make_event(i * 200 + j, pid, 1, "test", ts);
                det.update_from_event(&event);
            }
            let ts = base_ts + (i + 1) * WINDOW_DURATION_NS;
            let event = make_event(999, pid, 1, "test", ts);
            det.update_from_event(&event);
        }

        let result = det.detect(pid);
        assert!(
            result.is_none(),
            "Cold start with low freq should not alert"
        );

        assert_eq!(det.window_count(pid), 2);
    }

    #[test]
    fn test_ransomware_frequency_spike_detected() {
        let mut det = AdaptiveDetector::new();
        let pid = 3000;
        let base_ts = 1_000_000_000;

        for i in 0..6 {
            for j in 0..50 {
                let ts = base_ts + i * WINDOW_DURATION_NS + j * 1_000_000;
                let event = make_event(i * 50 + j, pid, 10, "normal", ts);
                det.update_from_event(&event);
            }
            if i < 5 {
                let ts = base_ts + (i + 1) * WINDOW_DURATION_NS;
                let event = make_event(999, pid, 10, "normal", ts);
                det.update_from_event(&event);
            }
        }

        let normal = det.detect(pid);
        assert!(normal.is_none(), "Normal file ops should not alert");

        for j in 0..600 {
            let ts = base_ts + 7 * WINDOW_DURATION_NS + j * 1_000_000;
            let event = make_event(j, pid, 10, "ransomware", ts);
            det.update_from_event(&event);
        }

        let attack = det.detect(pid);
        assert!(attack.is_some(), "Ransomware spike should trigger anomaly");
        let result = attack.unwrap();
        assert!(result.overall_score > 0.0);
        assert!(
            result
                .dimensions
                .iter()
                .any(|d| d.dimension == MlDimension::FileOpsFrequency),
            "Should detect file ops anomaly"
        );
    }

    #[test]
    fn test_false_positive_feedback_raises_threshold() {
        let mut det = AdaptiveDetector::new();
        let pid = 4000;

        assert!((det.get_threshold_multiplier(pid) - 1.0).abs() < 0.001);

        det.false_feedback(pid, true);
        assert!(
            (det.get_threshold_multiplier(pid) - 1.1).abs() < 0.001,
            "Threshold should be 1.1 after one false positive"
        );

        det.false_feedback(pid, true);
        assert!(
            (det.get_threshold_multiplier(pid) - 1.21).abs() < 0.001,
            "Threshold should be 1.21 after two false positives"
        );
    }

    #[test]
    fn test_threshold_decay_after_normal_samples() {
        let mut det = AdaptiveDetector::new();
        let pid = 5000;

        det.false_feedback(pid, true);
        det.false_feedback(pid, true);
        assert!((det.get_threshold_multiplier(pid) - 1.21).abs() < 0.001);

        for _ in 0..100 {
            det.update_from_event(&make_event(1, pid, 1, "test", 1_000_000_000));
        }
        assert!(
            (det.get_threshold_multiplier(pid) - 1.1).abs() < 0.001,
            "Threshold should decay to 1.1 after 100 normal samples, got {}",
            det.get_threshold_multiplier(pid)
        );
    }

    #[test]
    fn test_dns_tunnel_high_freq_detected() {
        let mut det = AdaptiveDetector::new();
        let pid = 6000;
        let base_ts = 1_000_000_000;

        for i in 0..6 {
            for j in 0..5 {
                let ts = base_ts + i * WINDOW_DURATION_NS + j * 10_000_000;
                let event = make_event(i * 5 + j, pid, 24, "dns", ts);
                det.update_from_event(&event);
            }
            if i < 5 {
                let ts = base_ts + (i + 1) * WINDOW_DURATION_NS;
                let event = make_event(999, pid, 24, "dns", ts);
                det.update_from_event(&event);
            }
        }

        assert!(det.detect(pid).is_none());

        for j in 0..60 {
            let ts = base_ts + 7 * WINDOW_DURATION_NS + j * 1_000_000;
            let event = make_event(j, pid, 24, "dns_tunnel", ts);
            det.update_from_event(&event);
        }

        let result = det.detect(pid);
        assert!(result.is_some(), "DNS tunnel should trigger anomaly");
        let r = result.unwrap();
        assert!(
            r.dimensions
                .iter()
                .any(|d| d.dimension == MlDimension::DnsOpsFrequency),
            "Should detect DNS anomaly"
        );
    }

    #[test]
    fn test_dual_model_complementarity() {
        let mut det = AdaptiveDetector::new();
        let pid = 7000;
        let base_ts = 1_000_000_000;

        for i in 0..6 {
            for j in 0..50 {
                let ts = base_ts + i * WINDOW_DURATION_NS + j * 1_000_000;
                let event = make_event(i * 50 + j, pid, 1, "test", ts);
                det.update_from_event(&event);
            }
            if i < 5 {
                let ts = base_ts + (i + 1) * WINDOW_DURATION_NS;
                let event = make_event(999, pid, 1, "test", ts);
                det.update_from_event(&event);
            }
        }

        for (w, count) in [(7, 80), (8, 120), (9, 200)] {
            for j in 0..count {
                let ts = base_ts + w * WINDOW_DURATION_NS + j * 1_000_000;
                let event = make_event(w * 200 + j, pid, 1, "attack", ts);
                det.update_from_event(&event);
            }
            let next_ts = base_ts + (w + 1) * WINDOW_DURATION_NS;
            let event = make_event(9999, pid, 1, "attack", next_ts);
            det.update_from_event(&event);
        }

        let _result = det.detect(pid);
        let state = det.get_state(pid, MlDimension::SyscallFrequency).unwrap();
        assert!(state.sample_count >= 8, "Should have 8+ EWMA samples");
        assert!(
            state.mean > 50.0,
            "EWMA mean should reflect increasing trend: {}",
            state.mean
        );
    }
}

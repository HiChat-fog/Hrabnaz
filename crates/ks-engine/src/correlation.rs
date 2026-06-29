//! 跨事件关联引擎 —— 补足单事件规则检测不到的"读/etc/shadow后外连"这类多步攻击。
//! 不替代 rule.rs，而是在其之上做第二层检测。

use crate::aggregator::DecodedEvent;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, PartialEq)]
pub enum CorrelationType {
    Window { window_secs: u64, condition_a: CorrelationCondition, condition_b: CorrelationCondition },
    Sequence { steps: Vec<CorrelationCondition>, max_gap_secs: u64 },
    ProcessTree { parent_condition: CorrelationCondition, child_condition: CorrelationCondition },
}

#[derive(Debug, Clone, PartialEq)]
pub enum CorrelationCondition {
    EventType(u32),
    CommContains(String),
    FilenameContains(String),
    DportEquals(u16),
    DaddrMatches(String),
    ArgsContains(String),
    And(Vec<CorrelationCondition>),
}

#[derive(Debug, Clone)]
pub struct CorrelationAlert {
    pub rule_name: String,
    pub correlation_type: CorrelationType,
    pub events: Vec<DecodedEvent>,
    pub description: String,
    pub severity: String,
    pub mitre: Option<MitreMapping>,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct MitreMapping {
    pub tactic: String,
    pub technique: String,
}

struct PartialAlert {
    events: Vec<DecodedEvent>,
    confidence: f64,
}

/// 维护滑动窗口，检查新事件是否与窗口内的历史事件形成关联模式
pub struct CorrelationEngine {
    event_window: VecDeque<DecodedEvent>,
    window_size_secs: u64,
    rules: Vec<CorrelationRule>,
    sequence_trackers: HashMap<(usize, u32), SequenceTracker>,
}

#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub name: String,
    pub correlation_type: CorrelationType,
    pub description: String,
    pub severity: String,
    pub mitre: Option<MitreMapping>,
}

#[derive(Debug, Clone)]
struct SequenceTracker {
    current_step: usize,
    matched_events: Vec<DecodedEvent>,
    last_step_timestamp_ns: u64,
}

impl CorrelationEngine {
    pub fn new(window_size_secs: u64) -> Self {
        Self {
            event_window: VecDeque::with_capacity(10000),
            window_size_secs,
            rules: Self::default_rules(),
            sequence_trackers: HashMap::new(),
        }
    }

    fn default_rules() -> Vec<CorrelationRule> {
        vec![
            CorrelationRule {
                name: "数据窃取: 读取敏感文件后建立外部连接".to_string(),
                correlation_type: CorrelationType::Window {
                    window_secs: 30,
                    condition_a: CorrelationCondition::And(vec![
                        CorrelationCondition::EventType(10),
                        CorrelationCondition::FilenameContains("/etc/shadow".to_string()),
                    ]),
                    condition_b: CorrelationCondition::And(vec![
                        CorrelationCondition::EventType(20),
                        CorrelationCondition::DportEquals(4444),
                    ]),
                },
                description: "30秒内读/etc/shadow后外连4444端口".to_string(),
                severity: "critical".to_string(),
                mitre: Some(MitreMapping { tactic: "TA0010".to_string(), technique: "T1041".to_string() }),
            },
            CorrelationRule {
                name: "数据窃取: 读取SSH密钥后建立外部连接".to_string(),
                correlation_type: CorrelationType::Window {
                    window_secs: 60,
                    condition_a: CorrelationCondition::And(vec![
                        CorrelationCondition::EventType(10),
                        CorrelationCondition::FilenameContains(".ssh".to_string()),
                    ]),
                    condition_b: CorrelationCondition::EventType(20),
                },
                description: "60秒内读SSH密钥后外连".to_string(),
                severity: "high".to_string(),
                mitre: Some(MitreMapping { tactic: "TA0010".to_string(), technique: "T1048".to_string() }),
            },
            CorrelationRule {
                name: "勒索软件: 读→加密写→删".to_string(),
                correlation_type: CorrelationType::Sequence {
                    steps: vec![
                        CorrelationCondition::EventType(11),
                        CorrelationCondition::And(vec![
                            CorrelationCondition::EventType(12),
                            CorrelationCondition::FilenameContains(".encrypted".to_string()),
                        ]),
                        CorrelationCondition::EventType(13),
                    ],
                    max_gap_secs: 10,
                },
                description: "10秒内依次: 读文件→写.encrypted→删原文件".to_string(),
                severity: "critical".to_string(),
                mitre: Some(MitreMapping { tactic: "TA0040".to_string(), technique: "T1486".to_string() }),
            },
            CorrelationRule {
                name: "反弹Shell: bash交互模式后外连".to_string(),
                correlation_type: CorrelationType::Window {
                    window_secs: 5,
                    condition_a: CorrelationCondition::And(vec![
                        CorrelationCondition::EventType(1),
                        CorrelationCondition::CommContains("bash".to_string()),
                        CorrelationCondition::ArgsContains("-i".to_string()),
                    ]),
                    condition_b: CorrelationCondition::EventType(20),
                },
                description: "5秒内以bash -i启动后建立网络连接".to_string(),
                severity: "critical".to_string(),
                mitre: Some(MitreMapping { tactic: "TA0002".to_string(), technique: "T1059.004".to_string() }),
            },
            CorrelationRule {
                name: "提权+持久化: SUID设置后修改sudoers".to_string(),
                correlation_type: CorrelationType::Sequence {
                    steps: vec![
                        CorrelationCondition::And(vec![
                            CorrelationCondition::EventType(1),
                            CorrelationCondition::CommContains("chmod".to_string()),
                            CorrelationCondition::ArgsContains("+s".to_string()),
                        ]),
                        CorrelationCondition::And(vec![
                            CorrelationCondition::EventType(12),
                            CorrelationCondition::FilenameContains("/etc/sudoers".to_string()),
                        ]),
                    ],
                    max_gap_secs: 60,
                },
                description: "先SUID再写sudoers".to_string(),
                severity: "critical".to_string(),
                mitre: Some(MitreMapping { tactic: "TA0004".to_string(), technique: "T1548.001".to_string() }),
            },
            CorrelationRule {
                name: "DNS隧道: 高频DNS+可疑目标".to_string(),
                correlation_type: CorrelationType::Window {
                    window_secs: 60,
                    condition_a: CorrelationCondition::EventType(24),
                    condition_b: CorrelationCondition::EventType(24),
                },
                description: "60秒内重复DNS查询".to_string(),
                severity: "high".to_string(),
                mitre: Some(MitreMapping { tactic: "TA0011".to_string(), technique: "T1071.004".to_string() }),
            },
        ]
    }

    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    /// 新事件进来 → 入窗口 → 清过期 → 检查所有规则
    pub fn detect_correlations(&mut self, event: &DecodedEvent) -> Vec<CorrelationAlert> {
        self.event_window.push_back(event.clone());
        let window_ns = self.window_size_secs * 1_000_000_000;
        let current_ts = event.header.timestamp_ns;
        while let Some(front) = self.event_window.front() {
            if current_ts - front.header.timestamp_ns > window_ns {
                self.event_window.pop_front();
            } else { break; }
        }

        let mut alerts = Vec::new();
        let rule_checks: Vec<(usize, u64, Vec<CorrelationCondition>, u64)> = self.rules.iter().enumerate()
            .filter_map(|(i, rule)| match &rule.correlation_type {
                CorrelationType::Window { window_secs, condition_a, condition_b } =>
                    Some((i, *window_secs, vec![condition_a.clone(), condition_b.clone()], 0)),
                CorrelationType::Sequence { steps, max_gap_secs } =>
                    Some((i, 0, steps.clone(), *max_gap_secs)),
                CorrelationType::ProcessTree { .. } => None,
            }).collect();

        for (rule_idx, window_secs, conditions, max_gap_secs) in rule_checks {
            if window_secs > 0 && conditions.len() == 2 {
                if let Some(alert) = self.check_window_correlation(event, window_secs, &conditions[0], &conditions[1]) {
                    let rule = &self.rules[rule_idx];
                    alerts.push(CorrelationAlert {
                        rule_name: rule.name.clone(), correlation_type: rule.correlation_type.clone(),
                        events: alert.events, description: rule.description.clone(),
                        severity: rule.severity.clone(), mitre: rule.mitre.clone(), confidence: alert.confidence,
                    });
                }
            } else if conditions.len() >= 2 && max_gap_secs > 0 {
                if let Some(alert) = self.check_sequence_correlation(event, rule_idx, &conditions, max_gap_secs) {
                    let rule = &self.rules[rule_idx];
                    alerts.push(CorrelationAlert {
                        rule_name: rule.name.clone(), correlation_type: rule.correlation_type.clone(),
                        events: alert.events, description: rule.description.clone(),
                        severity: rule.severity.clone(), mitre: rule.mitre.clone(), confidence: alert.confidence,
                    });
                }
            }
        }
        alerts
    }

    /// 检查当前事件(B)是否在窗口内与历史事件(A)形成配对
    fn check_window_correlation(&mut self, event: &DecodedEvent, window_secs: u64,
        condition_a: &CorrelationCondition, condition_b: &CorrelationCondition) -> Option<PartialAlert> {
        if !matches_condition(event, condition_b) { return None; }

        let window_ns = window_secs * 1_000_000_000;
        let current_ts = event.header.timestamp_ns;
        let matched: Vec<_> = self.event_window.iter()
            .filter(|e| current_ts - e.header.timestamp_ns <= window_ns && matches_condition(e, condition_a))
            .cloned().collect();

        if matched.is_empty() { return None; }

        let same_pid = matched.iter().any(|e| e.header.pid == event.header.pid);
        let mut confidence: f64 = 0.6;
        if same_pid { confidence += 0.2; }
        if matched.len() >= 2 { confidence += 0.1; }

        let mut all_events = matched;
        all_events.push(event.clone());
        Some(PartialAlert { events: all_events, confidence: confidence.min(1.0) })
    }

    /// 追踪同 PID 的事件是否按步骤顺序出现
    fn check_sequence_correlation(&mut self, event: &DecodedEvent, rule_idx: usize,
        steps: &[CorrelationCondition], max_gap_secs: u64) -> Option<PartialAlert> {
        let pid = event.header.pid;
        let tracker = self.sequence_trackers.entry((rule_idx, pid)).or_insert_with(||
            SequenceTracker { current_step: 0, matched_events: Vec::new(), last_step_timestamp_ns: 0 });

        if tracker.current_step >= steps.len() {
            tracker.current_step = 0; tracker.matched_events.clear(); tracker.last_step_timestamp_ns = 0;
        }

        if matches_condition(event, &steps[tracker.current_step]) {
            let max_gap_ns = max_gap_secs * 1_000_000_000;
            if tracker.last_step_timestamp_ns > 0
                && event.header.timestamp_ns - tracker.last_step_timestamp_ns > max_gap_ns {
                tracker.current_step = 0; tracker.matched_events.clear(); tracker.last_step_timestamp_ns = 0;
                if matches_condition(event, &steps[0]) {
                    tracker.current_step = 1; tracker.matched_events.push(event.clone());
                    tracker.last_step_timestamp_ns = event.header.timestamp_ns;
                }
                return None;
            }

            tracker.current_step += 1;
            tracker.matched_events.push(event.clone());
            tracker.last_step_timestamp_ns = event.header.timestamp_ns;

            if tracker.current_step >= steps.len() {
                let events = tracker.matched_events.clone();
                tracker.current_step = 0; tracker.matched_events.clear(); tracker.last_step_timestamp_ns = 0;

                let mut confidence: f64 = 0.7;
                if events.len() >= 2 {
                    let duration = events.last().unwrap().header.timestamp_ns - events.first().unwrap().header.timestamp_ns;
                    if duration < 3_000_000_000 { confidence += 0.2; }
                }
                return Some(PartialAlert { events, confidence: confidence.min(1.0) });
            }
        }
        None
    }
}

fn matches_condition(event: &DecodedEvent, condition: &CorrelationCondition) -> bool {
    match condition {
        CorrelationCondition::EventType(et) => event.header.event_type == *et,
        CorrelationCondition::CommContains(s) => event.comm.contains(s),
        CorrelationCondition::FilenameContains(s) => event.filename.as_ref().map_or(false, |f| f.contains(s)),
        CorrelationCondition::DportEquals(p) => event.dport == Some(*p),
        CorrelationCondition::DaddrMatches(pattern) => event.daddr.as_ref().map_or(false, |d| d.contains(pattern)),
        CorrelationCondition::ArgsContains(s) => event.args.as_ref().map_or(false, |a| a.contains(s)),
        CorrelationCondition::And(conds) => conds.iter().all(|c| matches_condition(event, c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::event::EventHeader;

    fn make_event(seq: u64, pid: u32, et: u32, comm: &str,
                  filename: Option<&str>, args: Option<&str>, dport: Option<u16>) -> DecodedEvent {
        let mut cb = [0u8; 16];
        let len = comm.len().min(16);
        cb[..len].copy_from_slice(&comm.as_bytes()[..len]);
        DecodedEvent {
            seq, comm: comm.to_string(),
            header: EventHeader { event_type: et, _pad1: 0, timestamp_ns: seq * 1_000_000_000, pid, tid: 0, uid: 0, ppid: 0, comm: cb, syscall_nr: 0, _pad2: 0, retval: 0 },
            filename: filename.map(|s| s.to_string()), args: args.map(|s| s.to_string()),
            saddr: None, daddr: dport.map(|_| "10.0.0.1".to_string()), sport: None, dport,
            proto: dport.map(|_| "TCP".to_string()), target_pid: None, signal: None, file_bytes: None,
        }
    }

    #[test]
    fn test_window_correlation_data_exfil() {
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations(&make_event(1, 1234, 10, "cat", Some("/etc/shadow"), None, None));
        let alerts = engine.detect_correlations(&make_event(2, 1234, 20, "cat", None, None, Some(4444)));
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].confidence > 0.6);
    }

    #[test]
    fn test_window_expiry() {
        let mut engine = CorrelationEngine::new(5);
        engine.detect_correlations(&make_event(1, 1234, 10, "cat", Some("/etc/shadow"), None, None));
        let alerts = engine.detect_correlations(&make_event(100, 1234, 20, "cat", None, None, Some(4444)));
        assert_eq!(alerts.len(), 0);
    }

    #[test]
    fn test_reverse_shell_correlation() {
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations(&make_event(1, 1234, 1, "bash", None, Some("bash -i"), None));
        let alerts = engine.detect_correlations(&make_event(2, 1234, 20, "bash", None, None, Some(4444)));
        assert!(alerts.iter().any(|a| a.rule_name.contains("反弹Shell")));
    }

    #[test]
    fn test_sequence_correlation_ransomware() {
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations(&make_event(1, 5678, 11, "encryptor", None, None, None));
        engine.detect_correlations(&make_event(2, 5678, 12, "encryptor", Some("x.encrypted"), None, None));
        let alerts = engine.detect_correlations(&make_event(3, 5678, 13, "encryptor", Some("x"), None, None));
        assert!(alerts.iter().any(|a| a.rule_name.contains("勒索软件")));
    }

    #[test]
    fn test_window_correlation_no_match() {
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations(&make_event(1, 1234, 10, "cat", Some("/etc/hosts"), None, None));
        let alerts = engine.detect_correlations(&make_event(2, 1234, 20, "cat", None, None, Some(4444)));
        assert!(alerts.is_empty());
    }
}
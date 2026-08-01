//! 跨事件关联引擎,补足单事件规则检测不到的"读/etc/shadow后外连"这类多步攻击。
//! 不替代rule.rs,而是在其之上做第二层检测。

use crate::aggregator::DecodedEvent;
use crate::process_tree::ProcessTreeManager;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CorrelationType {
    Window {
        window_secs: u64,
        condition_a: CorrelationCondition,
        condition_b: CorrelationCondition,
    },
    Sequence {
        steps: Vec<CorrelationCondition>,
        max_gap_secs: u64,
    },
    ProcessTree {
        parent_condition: CorrelationCondition,
        child_condition: CorrelationCondition,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CorrelationCondition {
    EventType(u32),
    CommContains(String),
    FilenameContains(String),
    DportEquals(u16),
    DaddrMatches(String),
    ArgsContains(String),
    And(Vec<CorrelationCondition>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationAlert {
    pub rule_name: String,
    pub correlation_type: CorrelationType,
    pub events: Vec<DecodedEvent>,
    pub description: String,
    pub severity: String,
    pub mitre: Option<MitreMapping>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub tactic: String,
    pub technique: String,
}

struct PartialAlert {
    events: Vec<DecodedEvent>,
    confidence: f64,
}

/// 维护滑动窗口,检查新事件是否与窗口内的历史事件形成关联模式
pub struct CorrelationEngine {
    event_window: VecDeque<DecodedEvent>,
    window_size_secs: u64,
    rules: Vec<CorrelationRule>,
    sequence_trackers: HashMap<(usize, u32), SequenceTracker>,
    /// per-(rule,pid) tracker容量上限。超过时按last_step_timestamp_ns删最老的,
    /// 防止sequence_trackers随累计PID数无界增长(84核机器见3.8万PID,RSS涨到3.7GB)。
    max_trackers: usize,
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
            max_trackers: 10000,
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
                mitre: Some(MitreMapping {
                    tactic: "TA0010".to_string(),
                    technique: "T1041".to_string(),
                }),
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
                mitre: Some(MitreMapping {
                    tactic: "TA0010".to_string(),
                    technique: "T1048".to_string(),
                }),
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
                mitre: Some(MitreMapping {
                    tactic: "TA0040".to_string(),
                    technique: "T1486".to_string(),
                }),
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
                mitre: Some(MitreMapping {
                    tactic: "TA0002".to_string(),
                    technique: "T1059.004".to_string(),
                }),
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
                mitre: Some(MitreMapping {
                    tactic: "TA0004".to_string(),
                    technique: "T1548.001".to_string(),
                }),
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
                mitre: Some(MitreMapping {
                    tactic: "TA0011".to_string(),
                    technique: "T1071.004".to_string(),
                }),
            },
            CorrelationRule {
                name: "进程树异常: sshd→bash→网络工具".to_string(),
                correlation_type: CorrelationType::ProcessTree {
                    parent_condition: CorrelationCondition::CommContains("sshd".to_string()),
                    child_condition: CorrelationCondition::CommContains("nc".to_string()),
                },
                description: "SSH 会话启动网络工具，疑似反弹 Shell".to_string(),
                severity: "critical".to_string(),
                mitre: Some(MitreMapping {
                    tactic: "TA0001".to_string(),
                    technique: "T1059.004".to_string(),
                }),
            },
            CorrelationRule {
                name: "进程树异常: cron→下载工具".to_string(),
                correlation_type: CorrelationType::ProcessTree {
                    parent_condition: CorrelationCondition::CommContains("cron".to_string()),
                    child_condition: CorrelationCondition::CommContains("wget".to_string()),
                },
                description: "定时任务启动下载工具，疑似 payload 投递".to_string(),
                severity: "high".to_string(),
                mitre: Some(MitreMapping {
                    tactic: "TA0003".to_string(),
                    technique: "T1053.003".to_string(),
                }),
            },
        ]
    }

    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    /// 新事件进来,入窗口,清过期,检查所有规则
    pub fn detect_correlations(&mut self, event: &DecodedEvent) -> Vec<CorrelationAlert> {
        self.detect_correlations_with_tree(event, None)
    }

    /// 带进程树的关联检测,ProcessTree规则需要查询进程树获取父进程信息。
    /// 原detect_correlations调用此方法并传None,跳过ProcessTree规则,向后兼容。
    pub fn detect_correlations_with_tree(
        &mut self,
        event: &DecodedEvent,
        process_tree: Option<&ProcessTreeManager>,
    ) -> Vec<CorrelationAlert> {
        self.event_window.push_back(event.clone());
        let window_ns = self.window_size_secs * 1_000_000_000;
        let current_ts = event.header.timestamp_ns;
        while let Some(front) = self.event_window.front() {
            if current_ts - front.header.timestamp_ns > window_ns {
                self.event_window.pop_front();
            } else {
                break;
            }
        }
        // 容量上限淘汰:sequence_trackers随累计(rule,pid)数无界增长(84核机器见3.8万PID),
        // 超过max_trackers时删last_step_timestamp_ns最老(含0即从未推进)的tracker。
        if self.sequence_trackers.len() > self.max_trackers {
            let target = self.max_trackers.saturating_sub(self.max_trackers / 10);
            while self.sequence_trackers.len() > target {
                let evict_key = match self
                    .sequence_trackers
                    .iter()
                    .min_by_key(|(_, t)| t.last_step_timestamp_ns)
                {
                    Some((k, _)) => *k,
                    None => break,
                };
                self.sequence_trackers.remove(&evict_key);
            }
        }

        let mut alerts = Vec::new();
        let rule_checks: Vec<(usize, u64, Vec<CorrelationCondition>, u64)> = self
            .rules
            .iter()
            .enumerate()
            .filter_map(|(i, rule)| match &rule.correlation_type {
                CorrelationType::Window {
                    window_secs,
                    condition_a,
                    condition_b,
                } => Some((
                    i,
                    *window_secs,
                    vec![condition_a.clone(), condition_b.clone()],
                    0,
                )),
                CorrelationType::Sequence {
                    steps,
                    max_gap_secs,
                } => Some((i, 0, steps.clone(), *max_gap_secs)),
                CorrelationType::ProcessTree { .. } => None,
            })
            .collect();

        for (rule_idx, window_secs, conditions, max_gap_secs) in rule_checks {
            if window_secs > 0 && conditions.len() == 2 {
                if let Some(alert) = self.check_window_correlation(
                    event,
                    window_secs,
                    &conditions[0],
                    &conditions[1],
                ) {
                    let rule = &self.rules[rule_idx];
                    alerts.push(CorrelationAlert {
                        rule_name: rule.name.clone(),
                        correlation_type: rule.correlation_type.clone(),
                        events: alert.events,
                        description: rule.description.clone(),
                        severity: rule.severity.clone(),
                        mitre: rule.mitre.clone(),
                        confidence: alert.confidence,
                    });
                }
            } else if conditions.len() >= 2 && max_gap_secs > 0 {
                if let Some(alert) =
                    self.check_sequence_correlation(event, rule_idx, &conditions, max_gap_secs)
                {
                    let rule = &self.rules[rule_idx];
                    alerts.push(CorrelationAlert {
                        rule_name: rule.name.clone(),
                        correlation_type: rule.correlation_type.clone(),
                        events: alert.events,
                        description: rule.description.clone(),
                        severity: rule.severity.clone(),
                        mitre: rule.mitre.clone(),
                        confidence: alert.confidence,
                    });
                }
            }
        }

        // ProcessTree关联规则,查询进程树检查父子关系
        if let Some(pt) = process_tree {
            for (rule_idx, rule) in self.rules.iter().enumerate() {
                if let CorrelationType::ProcessTree {
                    parent_condition,
                    child_condition,
                } = &rule.correlation_type
                {
                    if let Some(alert) = self.check_process_tree_correlation(
                        event,
                        rule_idx,
                        parent_condition,
                        child_condition,
                        pt,
                    ) {
                        alerts.push(CorrelationAlert {
                            rule_name: rule.name.clone(),
                            correlation_type: rule.correlation_type.clone(),
                            events: alert.events,
                            description: rule.description.clone(),
                            severity: rule.severity.clone(),
                            mitre: rule.mitre.clone(),
                            confidence: alert.confidence,
                        });
                    }
                }
            }
        }

        alerts
    }

    /// 进程树关联检查,当前事件匹配child_condition,其父进程匹配parent_condition时告警。
    fn check_process_tree_correlation(
        &self,
        event: &DecodedEvent,
        _rule_idx: usize,
        parent_condition: &CorrelationCondition,
        child_condition: &CorrelationCondition,
        process_tree: &ProcessTreeManager,
    ) -> Option<PartialAlert> {
        // 当前事件必须匹配child_condition
        if !matches_condition(event, child_condition) {
            return None;
        }

        let ppid = event.header.ppid;
        if ppid == 0 {
            return None;
        }

        // 获取父进程信息
        let parent_node = process_tree.get_node(ppid)?;
        let parent_comm = parent_node.comm.clone();

        // 构造父进程的临时事件来匹配parent_condition
        let mut parent_cb = [0u8; 16];
        let len = parent_comm.len().min(16);
        parent_cb[..len].copy_from_slice(&parent_comm.as_bytes()[..len]);
        let parent_event = DecodedEvent {
            seq: 0,
            comm: parent_comm.clone(),
            header: ks_core::event::EventHeader {
                event_type: 1,
                _pad1: 0,
                timestamp_ns: parent_node.create_time_ns,
                pid: ppid,
                tid: 0,
                uid: 0,
                ppid: 0,
                comm: parent_cb,
                syscall_nr: 0,
                _pad2: 0,
                retval: 0,
            },
            filename: if parent_node.exe_path.is_empty() {
                None
            } else {
                Some(parent_node.exe_path.clone())
            },
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
        };

        // 检查父进程是否匹配parent_condition
        if !matches_condition(&parent_event, parent_condition) {
            return None;
        }

        let mut all_events = vec![parent_event];
        all_events.push(event.clone());
        Some(PartialAlert {
            events: all_events,
            confidence: 0.8,
        })
    }

    /// 检查当前事件B是否在窗口内与历史事件A形成配对
    fn check_window_correlation(
        &mut self,
        event: &DecodedEvent,
        window_secs: u64,
        condition_a: &CorrelationCondition,
        condition_b: &CorrelationCondition,
    ) -> Option<PartialAlert> {
        if !matches_condition(event, condition_b) {
            return None;
        }

        let window_ns = window_secs * 1_000_000_000;
        let current_ts = event.header.timestamp_ns;
        let matched: Vec<_> = self
            .event_window
            .iter()
            .filter(|e| {
                current_ts - e.header.timestamp_ns <= window_ns && matches_condition(e, condition_a)
            })
            .cloned()
            .collect();

        if matched.is_empty() {
            return None;
        }

        let same_pid = matched.iter().any(|e| e.header.pid == event.header.pid);
        let mut confidence: f64 = 0.6;
        if same_pid {
            confidence += 0.2;
        }
        if matched.len() >= 2 {
            confidence += 0.1;
        }

        let mut all_events = matched;
        all_events.push(event.clone());
        Some(PartialAlert {
            events: all_events,
            confidence: confidence.min(1.0),
        })
    }

    /// 追踪同PID的事件是否按步骤顺序出现
    fn check_sequence_correlation(
        &mut self,
        event: &DecodedEvent,
        rule_idx: usize,
        steps: &[CorrelationCondition],
        max_gap_secs: u64,
    ) -> Option<PartialAlert> {
        let pid = event.header.pid;
        let tracker = self
            .sequence_trackers
            .entry((rule_idx, pid))
            .or_insert_with(|| SequenceTracker {
                current_step: 0,
                matched_events: Vec::new(),
                last_step_timestamp_ns: 0,
            });

        if tracker.current_step >= steps.len() {
            tracker.current_step = 0;
            tracker.matched_events.clear();
            tracker.last_step_timestamp_ns = 0;
        }

        if matches_condition(event, &steps[tracker.current_step]) {
            let max_gap_ns = max_gap_secs * 1_000_000_000;
            if tracker.last_step_timestamp_ns > 0
                && event.header.timestamp_ns - tracker.last_step_timestamp_ns > max_gap_ns
            {
                tracker.current_step = 0;
                tracker.matched_events.clear();
                tracker.last_step_timestamp_ns = 0;
                if matches_condition(event, &steps[0]) {
                    tracker.current_step = 1;
                    tracker.matched_events.push(event.clone());
                    tracker.last_step_timestamp_ns = event.header.timestamp_ns;
                }
                return None;
            }

            tracker.current_step += 1;
            tracker.matched_events.push(event.clone());
            tracker.last_step_timestamp_ns = event.header.timestamp_ns;

            if tracker.current_step >= steps.len() {
                let events = tracker.matched_events.clone();
                tracker.current_step = 0;
                tracker.matched_events.clear();
                tracker.last_step_timestamp_ns = 0;

                let mut confidence: f64 = 0.7;
                if events.len() >= 2 {
                    let duration = events.last().unwrap().header.timestamp_ns
                        - events.first().unwrap().header.timestamp_ns;
                    if duration < 3_000_000_000 {
                        confidence += 0.2;
                    }
                }
                return Some(PartialAlert {
                    events,
                    confidence: confidence.min(1.0),
                });
            }
        }
        None
    }
}

fn matches_condition(event: &DecodedEvent, condition: &CorrelationCondition) -> bool {
    match condition {
        CorrelationCondition::EventType(et) => event.header.event_type == *et,
        CorrelationCondition::CommContains(s) => event.comm.contains(s),
        CorrelationCondition::FilenameContains(s) => {
            event.filename.as_ref().is_some_and(|f| f.contains(s))
        }
        CorrelationCondition::DportEquals(p) => event.dport == Some(*p),
        CorrelationCondition::DaddrMatches(pattern) => {
            event.daddr.as_ref().is_some_and(|d| d.contains(pattern))
        }
        CorrelationCondition::ArgsContains(s) => event.args.as_ref().is_some_and(|a| a.contains(s)),
        CorrelationCondition::And(conds) => conds.iter().all(|c| matches_condition(event, c)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::event::EventHeader;

    fn make_event(
        seq: u64,
        pid: u32,
        et: u32,
        comm: &str,
        filename: Option<&str>,
        args: Option<&str>,
        dport: Option<u16>,
    ) -> DecodedEvent {
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
            filename: filename.map(|s| s.to_string()),
            args: args.map(|s| s.to_string()),
            saddr: None,
            daddr: dport.map(|_| "10.0.0.1".to_string()),
            sport: None,
            dport,
            proto: dport.map(|_| "TCP".to_string()),
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
    fn test_window_correlation_data_exfil() {
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations(&make_event(
            1,
            1234,
            10,
            "cat",
            Some("/etc/shadow"),
            None,
            None,
        ));
        let alerts =
            engine.detect_correlations(&make_event(2, 1234, 20, "cat", None, None, Some(4444)));
        assert_eq!(alerts.len(), 1);
        assert!(alerts[0].confidence > 0.6);
    }

    #[test]
    fn test_window_expiry() {
        let mut engine = CorrelationEngine::new(5);
        engine.detect_correlations(&make_event(
            1,
            1234,
            10,
            "cat",
            Some("/etc/shadow"),
            None,
            None,
        ));
        let alerts =
            engine.detect_correlations(&make_event(100, 1234, 20, "cat", None, None, Some(4444)));
        assert_eq!(alerts.len(), 0);
    }

    #[test]
    fn test_reverse_shell_correlation() {
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations(&make_event(1, 1234, 1, "bash", None, Some("bash -i"), None));
        let alerts =
            engine.detect_correlations(&make_event(2, 1234, 20, "bash", None, None, Some(4444)));
        assert!(alerts.iter().any(|a| a.rule_name.contains("反弹Shell")));
    }

    #[test]
    fn test_sequence_correlation_ransomware() {
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations(&make_event(1, 5678, 11, "encryptor", None, None, None));
        engine.detect_correlations(&make_event(
            2,
            5678,
            12,
            "encryptor",
            Some("x.encrypted"),
            None,
            None,
        ));
        let alerts = engine.detect_correlations(&make_event(
            3,
            5678,
            13,
            "encryptor",
            Some("x"),
            None,
            None,
        ));
        assert!(alerts.iter().any(|a| a.rule_name.contains("勒索软件")));
    }

    #[test]
    fn test_window_correlation_no_match() {
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations(&make_event(
            1,
            1234,
            10,
            "cat",
            Some("/etc/hosts"),
            None,
            None,
        ));
        let alerts =
            engine.detect_correlations(&make_event(2, 1234, 20, "cat", None, None, Some(4444)));
        assert!(alerts.is_empty());
    }

    /// 扩展helper,支持设置ppid,用于构造父子进程关系
    fn make_event_with_parent(seq: u64, pid: u32, ppid: u32, et: u32, comm: &str) -> DecodedEvent {
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
                ppid,
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
    fn test_process_tree_correlation_sshd_to_nc() {
        // 场景: sshd启动nc(反弹Shell),应触发critical告警
        // 规则名: "进程树异常: sshd→bash→网络工具"
        let mut tree = ProcessTreeManager::new();
        // 先把sshd父进程加入树
        let sshd_event = make_event_with_parent(1, 1000, 0, 1, "sshd");
        tree.update_from_event(&sshd_event);
        // 再把nc子进程加入树(建立ppid=1000关系)
        let nc_event = make_event_with_parent(2, 1001, 1000, 1, "nc");
        tree.update_from_event(&nc_event);

        let mut engine = CorrelationEngine::new(300);
        let alerts = engine.detect_correlations_with_tree(&nc_event, Some(&tree));
        assert!(
            alerts
                .iter()
                .any(|a| a.rule_name.contains("sshd") && a.rule_name.contains("网络工具")),
            "应触发 sshd→网络工具 关联告警，实际: {:?}",
            alerts.iter().map(|a| &a.rule_name).collect::<Vec<_>>()
        );
        let alert = alerts
            .iter()
            .find(|a| a.rule_name.contains("sshd"))
            .unwrap();
        assert_eq!(alert.severity, "critical");
        assert!(alert.confidence >= 0.8);
        assert_eq!(alert.events.len(), 2);
        // 第一条应是父进程sshd,第二条是子进程nc
        assert_eq!(alert.events[0].header.pid, 1000);
        assert_eq!(alert.events[1].header.pid, 1001);
        // MITRE映射
        assert!(alert.mitre.is_some());
        let mitre = alert.mitre.as_ref().unwrap();
        assert_eq!(mitre.tactic, "TA0001");
        assert_eq!(mitre.technique, "T1059.004");
    }

    #[test]
    fn test_process_tree_correlation_cron_to_wget() {
        // 场景: cron启动wget(payload投递),应触发high告警
        // 规则名: "进程树异常: cron→下载工具"
        let mut tree = ProcessTreeManager::new();
        let cron_event = make_event_with_parent(1, 2000, 0, 1, "cron");
        tree.update_from_event(&cron_event);
        let wget_event = make_event_with_parent(2, 2001, 2000, 1, "wget");
        tree.update_from_event(&wget_event);

        let mut engine = CorrelationEngine::new(300);
        let alerts = engine.detect_correlations_with_tree(&wget_event, Some(&tree));
        assert!(
            alerts
                .iter()
                .any(|a| a.rule_name.contains("cron") && a.rule_name.contains("下载工具")),
            "应触发 cron→下载工具 关联告警，实际: {:?}",
            alerts.iter().map(|a| &a.rule_name).collect::<Vec<_>>()
        );
        let alert = alerts
            .iter()
            .find(|a| a.rule_name.contains("cron"))
            .unwrap();
        assert_eq!(alert.severity, "high");
        assert!(alert.confidence >= 0.8);
        assert_eq!(alert.events[0].header.pid, 2000);
        assert_eq!(alert.events[1].header.pid, 2001);
        let mitre = alert.mitre.as_ref().unwrap();
        assert_eq!(mitre.tactic, "TA0003");
        assert_eq!(mitre.technique, "T1053.003");
    }

    #[test]
    fn test_process_tree_no_match() {
        // 场景: 父进程是vim(非sshd/cron),子是nc,不应触发ProcessTree规则
        let mut tree = ProcessTreeManager::new();
        let vim_event = make_event_with_parent(1, 3000, 0, 1, "vim");
        tree.update_from_event(&vim_event);
        let nc_event = make_event_with_parent(2, 3001, 3000, 1, "nc");
        tree.update_from_event(&nc_event);

        let mut engine = CorrelationEngine::new(300);
        let alerts = engine.detect_correlations_with_tree(&nc_event, Some(&tree));
        assert!(
            !alerts.iter().any(|a| a.rule_name.contains("进程树异常")),
            "vim→nc 不应触发进程树关联告警，实际: {:?}",
            alerts.iter().map(|a| &a.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_process_tree_no_match_ppid_zero() {
        // 场景: 子进程ppid=0(无父进程),不应触发告警
        let mut tree = ProcessTreeManager::new();
        let nc_event = make_event_with_parent(1, 4000, 0, 1, "nc");
        tree.update_from_event(&nc_event);

        let mut engine = CorrelationEngine::new(300);
        let alerts = engine.detect_correlations_with_tree(&nc_event, Some(&tree));
        assert!(
            !alerts.iter().any(|a| a.rule_name.contains("进程树异常")),
            "ppid=0 不应触发进程树关联告警"
        );
    }

    #[test]
    fn test_detect_correlations_with_tree_backward_compat() {
        // 场景: 传None(向后兼容),ProcessTree规则应被跳过,
        // 但Window/Sequence规则仍正常工作
        let mut engine = CorrelationEngine::new(30);
        // 先添加一个bash -i事件(满足reverse_shell规则的condition_a)
        engine.detect_correlations_with_tree(
            &make_event(1, 1234, 1, "bash", None, Some("bash -i"), None),
            None,
        );
        // 再添加外连4444事件(满足condition_b),应触发reverse_shell Window规则
        let alerts = engine.detect_correlations_with_tree(
            &make_event(2, 1234, 20, "bash", None, None, Some(4444)),
            None,
        );
        assert!(
            alerts.iter().any(|a| a.rule_name.contains("反弹Shell")),
            "传 None 时 Window 规则应正常工作，实际: {:?}",
            alerts.iter().map(|a| &a.rule_name).collect::<Vec<_>>()
        );
        // 不应触发任何进程树规则
        assert!(
            !alerts.iter().any(|a| a.rule_name.contains("进程树异常")),
            "传 None 时不应触发进程树关联告警"
        );
    }

    #[test]
    fn test_process_tree_correlation_with_old_api() {
        // 场景: 旧API detect_correlations(&event)等价于detect_correlations_with_tree(event, None)
        // 验证旧调用方不会破坏(向后兼容)
        let mut tree = ProcessTreeManager::new();
        let sshd_event = make_event_with_parent(1, 5000, 0, 1, "sshd");
        tree.update_from_event(&sshd_event);
        let nc_event = make_event_with_parent(2, 5001, 5000, 1, "nc");
        tree.update_from_event(&nc_event);

        let mut engine = CorrelationEngine::new(300);
        // 旧API(无process_tree参数)
        let alerts_old = engine.detect_correlations(&nc_event);
        // 新API传None
        let alerts_none = engine.detect_correlations_with_tree(&nc_event, None);
        // 两者结果应等价(都不触发ProcessTree规则,但Window/Sequence一致)
        assert_eq!(alerts_old.len(), alerts_none.len());
        assert!(
            !alerts_old
                .iter()
                .any(|a| a.rule_name.contains("进程树异常")),
            "旧 API 不应触发进程树关联告警"
        );
    }
}

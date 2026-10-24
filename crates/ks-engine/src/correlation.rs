use crate::process_tree::ProcessTreeManager;
use ks_core::alert::{Alert, MitreInfo, ProcessInfo};
use ks_core::event::DecodedEvent;
use ks_core::rule::Severity;
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

/* correlationcondition“怎么判断一个事件满足某个条件”。
EventType(u32)：事件类型等于某值。
CommContains(String)：进程名包含某字符串。
FilenameContains(String)：文件名包含某字符串。
DportEquals(u16)：目标端口等于某值。
DaddrMatches(String)：目标地址包含某字符串。
ArgsContains(String)：参数包含某字符串。
And(Vec<...>)：所有子条件都满足。 */

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
    pub enforce: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub tactic: String,
    pub technique: String,
}

impl CorrelationAlert {
    /// 转成通用 Alert（入取证链/外部消费的统一形态，H-7 从 CLI 下沉）：
    /// severity 字符串 → Severity 枚举、进程取首个关联事件、经 event_ids 保留关联事件序列，
    /// MITRE 透传
    pub fn to_alert(&self) -> Alert {
        let proc = self
            .events
            .first()
            .map(|e| ProcessInfo {
                pid: e.header.pid,
                ppid: e.header.ppid,
                comm: e.comm.clone(),
                uid: e.header.uid,
                exe_path: e.filename.clone(),
                cmdline: e.args.clone(),
            })
            .unwrap_or_else(|| ProcessInfo {
                pid: 0,
                ppid: 0,
                comm: "unknown".to_string(),
                uid: 0,
                exe_path: None,
                cmdline: None,
            });

        let severity = match self.severity.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Low,
        };

        let ts = self
            .events
            .first()
            .map(|e| e.header.timestamp_ns)
            .unwrap_or(0);
        let mut alert = Alert::new(
            severity,
            ts,
            self.rule_name.clone(),
            self.rule_name.clone(),
            proc,
        );
        alert.description = self.description.clone();
        alert.event_ids = self.events.iter().map(|e| e.seq).collect();
        alert.mitre = self.mitre.as_ref().map(|m| MitreInfo {
            tactic: m.tactic.clone(),
            technique: m.technique.clone(),
            sub_technique: None,
        });
        alert
    }
}

struct PartialAlert {
    events: Vec<DecodedEvent>,
    confidence: f64,
}

pub struct CorrelationEngine {
    event_window: VecDeque<DecodedEvent>,
    window_size_secs: u64,
    rules: Vec<CorrelationRule>,
    sequence_trackers: HashMap<(usize, u32), SequenceTracker>,
    max_trackers: usize,
    max_window_events: usize,
}

#[derive(Debug, Clone)]
pub struct CorrelationRule {
    pub name: String,
    pub correlation_type: CorrelationType,
    pub description: String,
    pub severity: String,
    pub mitre: Option<MitreMapping>,
    /// 阻断模式下是否允许写 block_decisions 实杀（默认 false=audit，搬 KubeArmor action 分离）
    pub enforce: bool,
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
            max_window_events: 2000,
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
                enforce: false,
            },
            CorrelationRule {
                name: "数据窃取: 读取SSH密钥后建立外部连接".to_string(),
                correlation_type: CorrelationType::Window {
                    window_secs: 60,
                    // 只认私钥文件：authorized_keys/known_hosts 是公钥材料，
                    // sshd 认证期读取属正常行为；旧条件 ".ssh" 子串还误伤
                    // /etc/ssh/ssh_host_*，真机实测单窗口 61 条误报
                    condition_a: CorrelationCondition::And(vec![
                        CorrelationCondition::EventType(10),
                        CorrelationCondition::FilenameContains("/.ssh/id_".to_string()),
                    ]),
                    condition_b: CorrelationCondition::EventType(20),
                },
                description: "60秒内读SSH私钥后外连".to_string(),
                severity: "high".to_string(),
                mitre: Some(MitreMapping {
                    tactic: "TA0010".to_string(),
                    technique: "T1048".to_string(),
                }),
                enforce: false,
            },
            CorrelationRule {
                name: "勒索软件: 加密写→删".to_string(),
                correlation_type: CorrelationType::Sequence {
                    steps: vec![
                        CorrelationCondition::And(vec![
                            CorrelationCondition::EventType(12),
                            CorrelationCondition::FilenameContains(".encrypted".to_string()),
                        ]),
                        CorrelationCondition::EventType(13),
                    ],
                    max_gap_secs: 10,
                },
                // 旧版三步"读→写.encrypted→删"的第一步依赖 FILE_READ(11)，
                // 该事件类型无探针发射（读只计频不流式，见 ARCHITECTURE §5.3），
                // 真机上整条规则永不命中。两步序列（写.encrypted→删原文件）的
                // 两个事件都来自 kprobe 路径（vfs_write≥1024B / vfs_unlink），真机可命中
                description: "10秒内依次: 写.encrypted→删原文件".to_string(),
                severity: "critical".to_string(),
                mitre: Some(MitreMapping {
                    tactic: "TA0040".to_string(),
                    technique: "T1486".to_string(),
                }),
                enforce: false,
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
                enforce: false,
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
                enforce: false,
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
                enforce: false,
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
                enforce: false,
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
                enforce: false,
            },
        ]
    }

    pub fn add_rule(&mut self, rule: CorrelationRule) {
        self.rules.push(rule);
    }

    pub fn detect_correlations(&mut self, event: &DecodedEvent) -> Vec<CorrelationAlert> {
        self.detect_correlations_with_tree(event, None)
    }

    pub fn detect_correlations_with_tree(
        &mut self,
        event: &DecodedEvent,
        process_tree: Option<&ProcessTreeManager>,
    ) -> Vec<CorrelationAlert> {
        self.event_window.push_back(event.clone());
        // 这个clone未来考虑优化一下 暂时不改
        let window_ns = self.window_size_secs * 1_000_000_000;
        let current_ts = event.header.timestamp_ns;
        while let Some(front) = self.event_window.front() {
            // perfbuf 多 ring 乱序到达时 current_ts 可能小于 front，非饱和减法会回绕出巨大窗口
            if current_ts.saturating_sub(front.header.timestamp_ns) > window_ns {
                self.event_window.pop_front();
            } else {
                break;
            }
        }
        while self.event_window.len() > self.max_window_events {
            self.event_window.pop_front();
        }
        if self.sequence_trackers.len() > self.max_trackers {
            // 先一次性清掉长时间无进展的死 tracker，避免逐条 min_by_key 全表扫描
            let stale_ns = (self.window_size_secs * 3).max(300) * 1_000_000_000;
            let now = current_ts;
            self.sequence_trackers.retain(|_, t| {
                t.last_step_timestamp_ns == 0
                    || now.saturating_sub(t.last_step_timestamp_ns) <= stale_ns
            });
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
        // 只收集 (规则下标, window_secs, max_gap_secs) 标量，条件按需借自 self.rules，
        // 旧实现每事件把所有规则的 condition_a/b 与 steps 整个 Vec 深拷贝一遍
        let rule_checks: Vec<(usize, u64, u64)> = self
            .rules
            .iter()
            .enumerate()
            .filter_map(|(i, rule)| match &rule.correlation_type {
                CorrelationType::Window { window_secs, .. } => Some((i, *window_secs, 0)),
                CorrelationType::Sequence { max_gap_secs, .. } => Some((i, 0, *max_gap_secs)),
                CorrelationType::ProcessTree { .. } => None,
            })
            .collect();

        for (rule_idx, window_secs, max_gap_secs) in rule_checks {
            if window_secs > 0 {
                if let CorrelationType::Window {
                    condition_a,
                    condition_b,
                    ..
                } = &self.rules[rule_idx].correlation_type
                {
                    if let Some(alert) =
                        self.check_window_correlation(event, window_secs, condition_a, condition_b)
                    {
                        let rule = &self.rules[rule_idx];
                        alerts.push(self.build_alert(rule, alert));
                    }
                }
            } else if max_gap_secs > 0 {
                if let Some(alert) = self.check_sequence_correlation(event, rule_idx, max_gap_secs)
                {
                    let rule = &self.rules[rule_idx];
                    alerts.push(self.build_alert(rule, alert));
                }
            }
        }

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
                        alerts.push(self.build_alert(rule, alert));
                    }
                }
            }
        }

        alerts
    }

    fn build_alert(&self, rule: &CorrelationRule, alert: PartialAlert) -> CorrelationAlert {
        CorrelationAlert {
            rule_name: rule.name.clone(),
            correlation_type: rule.correlation_type.clone(),
            events: alert.events,
            description: rule.description.clone(),
            severity: rule.severity.clone(),
            mitre: rule.mitre.clone(),
            confidence: alert.confidence,
            enforce: rule.enforce,
        }
    }

    fn check_process_tree_correlation(
        &self,
        event: &DecodedEvent,
        _rule_idx: usize,
        parent_condition: &CorrelationCondition,
        child_condition: &CorrelationCondition,
        process_tree: &ProcessTreeManager,
    ) -> Option<PartialAlert> {
        if !matches_condition(event, child_condition) {
            return None;
        }

        let ppid = event.header.ppid;
        if ppid == 0 {
            return None;
        }

        let parent_node = process_tree.get_node(ppid)?;
        let parent_comm = parent_node.comm.clone();

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

    fn check_window_correlation(
        &self,
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
                // 饱和减法：perfbuf 乱序到达时 e 的时间戳可能晚于当前事件
                current_ts.saturating_sub(e.header.timestamp_ns) <= window_ns
                    && matches_condition(e, condition_a)
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

    fn check_sequence_correlation(
        &mut self,
        event: &DecodedEvent,
        rule_idx: usize,
        max_gap_secs: u64,
    ) -> Option<PartialAlert> {
        // steps 借自 self.rules（字段级借用，与 trackers 的可变借用不冲突），
        // 免去调用方逐事件克隆整条 steps Vec
        let steps: &[CorrelationCondition] = match &self.rules[rule_idx].correlation_type {
            CorrelationType::Sequence { steps, .. } => steps,
            _ => return None,
        };
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
                && event
                    .header
                    .timestamp_ns
                    .saturating_sub(tracker.last_step_timestamp_ns)
                    > max_gap_ns
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
                    let duration = events
                        .last()
                        .unwrap()
                        .header
                        .timestamp_ns
                        .saturating_sub(events.first().unwrap().header.timestamp_ns);
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

    /// SSH 密钥外泄关联只认私钥：authorized_keys（sshd 认证期正常读取）不告警，
    /// /home/*/.ssh/id_* 读后外连才告警。真机曾因 ".ssh" 子串误伤导致 61 条/窗口
    #[test]
    fn test_ssh_exfil_ignores_authorized_keys() {
        let mut engine = CorrelationEngine::new(60);
        engine.detect_correlations(&make_event(
            1,
            100,
            10,
            "sshd",
            Some("/root/.ssh/authorized_keys"),
            None,
            None,
        ));
        let alerts =
            engine.detect_correlations(&make_event(2, 100, 20, "sshd", None, None, Some(22)));
        assert!(
            !alerts.iter().any(|a| a.rule_name.contains("SSH")),
            "authorized_keys 是公钥材料，不应触发 SSH 私钥外泄关联"
        );

        let mut engine = CorrelationEngine::new(60);
        engine.detect_correlations(&make_event(
            1,
            100,
            10,
            "cat",
            Some("/home/u/.ssh/id_rsa"),
            None,
            None,
        ));
        let alerts =
            engine.detect_correlations(&make_event(2, 100, 20, "curl", None, None, Some(443)));
        assert!(
            alerts.iter().any(|a| a.rule_name.contains("SSH")),
            "读取私钥后外连应告警"
        );
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
        // 两步序列：写 .encrypted → 删（FILE_READ 无探针发射，不再作为第一步）
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
        assert!(
            alerts.iter().any(|a| a.rule_name.contains("勒索软件")),
            "写.encrypted→删 应触发勒索关联，实际: {:?}",
            alerts.iter().map(|a| &a.rule_name).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_sequence_correlation_ransomware_gap_reset() {
        // 第一步之后间隔超过 max_gap → tracker 重置，不应触发
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations(&make_event(
            2,
            5678,
            12,
            "encryptor",
            Some("x.encrypted"),
            None,
            None,
        ));
        // make_event 时间戳 = seq 秒；seq 100 → 距第一步 98s > 10s gap
        let alerts = engine.detect_correlations(&make_event(
            100,
            5678,
            13,
            "encryptor",
            Some("x"),
            None,
            None,
        ));
        assert!(
            !alerts.iter().any(|a| a.rule_name.contains("勒索软件")),
            "超 gap 的写删序列不应触发勒索关联"
        );
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
        let mut tree = ProcessTreeManager::new();
        let sshd_event = make_event_with_parent(1, 1000, 0, 1, "sshd");
        tree.update_from_event(&sshd_event);
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
        assert_eq!(alert.events[0].header.pid, 1000);
        assert_eq!(alert.events[1].header.pid, 1001);
        assert!(alert.mitre.is_some());
        let mitre = alert.mitre.as_ref().unwrap();
        assert_eq!(mitre.tactic, "TA0001");
        assert_eq!(mitre.technique, "T1059.004");
    }

    #[test]
    fn test_process_tree_correlation_cron_to_wget() {
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
        let mut engine = CorrelationEngine::new(30);
        engine.detect_correlations_with_tree(
            &make_event(1, 1234, 1, "bash", None, Some("bash -i"), None),
            None,
        );
        let alerts = engine.detect_correlations_with_tree(
            &make_event(2, 1234, 20, "bash", None, None, Some(4444)),
            None,
        );
        assert!(
            alerts.iter().any(|a| a.rule_name.contains("反弹Shell")),
            "传 None 时 Window 规则应正常工作，实际: {:?}",
            alerts.iter().map(|a| &a.rule_name).collect::<Vec<_>>()
        );
        assert!(
            !alerts.iter().any(|a| a.rule_name.contains("进程树异常")),
            "传 None 时不应触发进程树关联告警"
        );
    }

    #[test]
    fn test_process_tree_correlation_with_old_api() {
        let mut tree = ProcessTreeManager::new();
        let sshd_event = make_event_with_parent(1, 5000, 0, 1, "sshd");
        tree.update_from_event(&sshd_event);
        let nc_event = make_event_with_parent(2, 5001, 5000, 1, "nc");
        tree.update_from_event(&nc_event);

        let mut engine = CorrelationEngine::new(300);
        let alerts_old = engine.detect_correlations(&nc_event);
        let alerts_none = engine.detect_correlations_with_tree(&nc_event, None);
        assert_eq!(alerts_old.len(), alerts_none.len());
        assert!(
            !alerts_old
                .iter()
                .any(|a| a.rule_name.contains("进程树异常")),
            "旧 API 不应触发进程树关联告警"
        );
    }

    fn make_correlation_alert_for_tests(severity: &str, with_mitre: bool) -> CorrelationAlert {
        let mut event = make_event(1, 1234, 1, "bash", None, Some("bash -i"), None);
        event.seq = 42;
        event.header.uid = 1000;
        event.header.ppid = 1;
        event.filename = Some("/bin/test".to_string());
        CorrelationAlert {
            enforce: false,
            rule_name: "测试关联规则".to_string(),
            correlation_type: CorrelationType::Window {
                window_secs: 30,
                condition_a: CorrelationCondition::EventType(1),
                condition_b: CorrelationCondition::EventType(20),
            },
            events: vec![event],
            description: "测试描述".to_string(),
            severity: severity.to_string(),
            mitre: if with_mitre {
                Some(MitreMapping {
                    tactic: "TA0002".to_string(),
                    technique: "T1059.004".to_string(),
                })
            } else {
                None
            },
            confidence: 0.85,
        }
    }

    /// to_alert（H-7 自 CLI 下沉）行为回归
    #[test]
    fn test_to_alert_basic_and_severity_mapping() {
        let ca = make_correlation_alert_for_tests("critical", false);
        let alert = ca.to_alert();
        assert_eq!(alert.severity, ks_core::rule::Severity::Critical);
        assert_eq!(alert.title, "测试关联规则");
        assert_eq!(alert.rule_name, "测试关联规则");
        assert_eq!(alert.description, "测试描述");
        assert_eq!(alert.process.pid, 1234);
        assert_eq!(alert.process.comm, "bash");
        assert_eq!(alert.process.uid, 1000);
        assert_eq!(alert.process.ppid, 1);
        assert_eq!(alert.event_ids, vec![42]);

        for (s, want) in [
            ("critical", ks_core::rule::Severity::Critical),
            ("high", ks_core::rule::Severity::High),
            ("medium", ks_core::rule::Severity::Medium),
            ("low", ks_core::rule::Severity::Low),
            ("unknown", ks_core::rule::Severity::Low),
        ] {
            let ca = make_correlation_alert_for_tests(s, false);
            assert_eq!(ca.to_alert().severity, want);
        }
    }

    #[test]
    fn test_to_alert_mitre_and_empty_events() {
        let ca = make_correlation_alert_for_tests("high", true);
        let mitre = ca.to_alert().mitre.expect("mitre should be present");
        assert_eq!(mitre.tactic, "TA0002");
        assert_eq!(mitre.technique, "T1059.004");

        let mut ca = make_correlation_alert_for_tests("low", false);
        ca.events.clear();
        let alert = ca.to_alert();
        assert_eq!(alert.process.pid, 0);
        assert_eq!(alert.process.comm, "unknown");
        assert_eq!(alert.timestamp_ns, 0);
    }
}

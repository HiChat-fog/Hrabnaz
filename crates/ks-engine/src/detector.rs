use crate::aggregator::DecodedEvent;
use anyhow::Result;
use ks_core::alert::{
    AddressFamily, Alert, AlertStatus, FileInfo, FileOperation, MitreInfo, NetworkInfo,
    ProcessInfo, Protocol,
};
use ks_core::rule::{Condition, DetectionRule, Field, MatchResult, Operator};
use log::{info, warn};
use std::collections::HashMap;

pub struct DetectionEngine {
    rules: Vec<DetectionRule>,
    rules_index: HashMap<String, usize>,
    regex_cache: HashMap<String, regex::Regex>,
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            rules_index: HashMap::new(),
            regex_cache: HashMap::new(),
        }
    }

    pub fn load_rules_from_yaml(&mut self, yaml_content: &str) -> Result<usize> {
        let rules: Vec<DetectionRule> = serde_yaml::from_str(yaml_content)?;
        let count = rules.len();
        for rule in &rules {
            // 重名规则会静默覆盖 rules_index（generate_alert 取错 MITRE 映射），显式 warn
            if let Some(&old_idx) = self.rules_index.get(&rule.name) {
                warn!(
                    "规则名重复: '{}' (第 {} 条被第 {} 条覆盖索引) — 建议重命名",
                    rule.name, old_idx, self.rules.len()
                );
            }
            let idx = self.rules.len();
            self.rules_index.insert(rule.name.clone(), idx);
        }
        self.rules.extend(rules);
        self.compile_regexes();
        info!("加载了 {} 条检测规则", count);
        Ok(count)
    }

    fn compile_regexes(&mut self) {
        for rule in &self.rules {
            for cond in &rule.conditions {
                if matches!(cond.operator, Operator::Regex | Operator::NotRegex)
                    && !self.regex_cache.contains_key(&cond.value)
                {
                    match regex::Regex::new(&cond.value) {
                        Ok(re) => {
                            self.regex_cache.insert(cond.value.clone(), re);
                        }
                        Err(e) => {
                            warn!("规则正则编译失败,运行时该条件恒false: '{}' — {}", cond.value, e);
                        }
                    }
                }
            }
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn match_event(&self, event: &DecodedEvent) -> Vec<MatchResult> {
        let mut results = Vec::new();
        for rule in &self.rules {
            if self.rule_matches(rule, event) {
                results.push(MatchResult {
                    rule_name: rule.name.clone(),
                    severity: rule.severity.clone(),
                    alert_message: rule.alert_message.clone(),
                    matched_conditions: rule
                        .conditions
                        .iter()
                        .map(|c| format!("{} {} {}", c.field, op_to_str(&c.operator), c.value))
                        .collect(),
                    enforce: rule.enforce,
                });
            }
        }
        results
    }

    fn rule_matches(&self, rule: &DetectionRule, event: &DecodedEvent) -> bool {
        rule.conditions
            .iter()
            .all(|cond| self.condition_matches(cond, event))
    }

    fn condition_matches(&self, cond: &Condition, event: &DecodedEvent) -> bool {
        let cache = &self.regex_cache;
        match &cond.field {
            Field::EventType => match_u32(event.header.event_type, &cond.operator, &cond.value, cache),
            Field::SyscallNr => match_i32(event.header.syscall_nr, &cond.operator, &cond.value, cache),
            Field::Pid => match_u32(event.header.pid, &cond.operator, &cond.value, cache),
            Field::Uid => match_u32(event.header.uid, &cond.operator, &cond.value, cache),
            Field::Ppid => match_u32(event.header.ppid, &cond.operator, &cond.value, cache),
            Field::Dport => {
                match_opt_u32(event.dport.map(|v| v as u32), &cond.operator, &cond.value, cache)
            }
            Field::Sport => {
                match_opt_u32(event.sport.map(|v| v as u32), &cond.operator, &cond.value, cache)
            }
            Field::TargetPid => match_opt_u32(event.target_pid, &cond.operator, &cond.value, cache),
            Field::Signal => match_opt_i32(event.signal, &cond.operator, &cond.value, cache),
            Field::FileBytes => match_opt_u64(event.file_bytes, &cond.operator, &cond.value),
            Field::Comm => match_str(&event.comm, &cond.operator, &cond.value, cache),
            Field::Filename => {
                match_opt_str(event.filename.as_deref(), &cond.operator, &cond.value, cache)
            }
            Field::Args => match_opt_str(event.args.as_deref(), &cond.operator, &cond.value, cache),
            Field::Saddr => match_opt_str(event.saddr.as_deref(), &cond.operator, &cond.value, cache),
            Field::Daddr => match_opt_str(event.daddr.as_deref(), &cond.operator, &cond.value, cache),
            Field::Proto => match_opt_str(event.proto.as_deref(), &cond.operator, &cond.value, cache),
            Field::Saddr6 => match_ipv6_field(event.saddr.as_deref(), &cond.operator, &cond.value, cache),
            Field::Daddr6 => match_ipv6_field(event.daddr.as_deref(), &cond.operator, &cond.value, cache),
            Field::Family => {
                let inferred_family =
                    event
                        .saddr
                        .as_ref()
                        .map(|a| if a.contains(':') { "IPv6" } else { "IPv4" });
                match_family_field(inferred_family, &cond.operator, &cond.value)
            }
            Field::ModuleName => {
                match_opt_str(event.module_name.as_deref(), &cond.operator, &cond.value, cache)
            }
            Field::ProgName => {
                match_opt_str(event.prog_name.as_deref(), &cond.operator, &cond.value, cache)
            }
            Field::SourceNsInum => match_opt_u32(event.source_ns_inum, &cond.operator, &cond.value, cache),
            Field::TargetNsInum => match_opt_u32(event.target_ns_inum, &cond.operator, &cond.value, cache),
            Field::CapEff => match_opt_u32(event.cap_eff, &cond.operator, &cond.value, cache),
            Field::Action => match_opt_str(event.action.as_deref(), &cond.operator, &cond.value, cache),
        }
    }

    pub fn generate_alert(&self, result: &MatchResult, event: &DecodedEvent) -> Alert {
        let mitre = self
            .rules_index
            .get(&result.rule_name)
            .map(|idx| &self.rules[*idx])
            .and_then(|r| match (&r.mitre_tactic, &r.mitre_technique) {
                (Some(tactic), Some(technique)) => Some(MitreInfo {
                    tactic: tactic.clone(),
                    technique: technique.clone(),
                    sub_technique: None,
                }),
                _ => None,
            });

        let family = event.saddr.as_ref().map(|addr| {
            if addr.contains(':') {
                AddressFamily::IPv6
            } else {
                AddressFamily::IPv4
            }
        });

        let proto = event
            .proto
            .as_ref()
            .map(|p| match p.as_str() {
                "TCP" => Protocol::TCP,
                "UDP" => Protocol::UDP,
                "ICMP" => Protocol::ICMP,
                _ => Protocol::OTHER,
            })
            .unwrap_or_default();

        Alert {
            id: uuid::Uuid::new_v4(),
            timestamp_ns: event.header.timestamp_ns,
            severity: result.severity.clone(),
            title: result.rule_name.clone(),
            description: result.alert_message.clone(),
            rule_name: result.rule_name.clone(),
            process: ProcessInfo {
                pid: event.header.pid,
                ppid: event.header.ppid,
                comm: event.comm.clone(),
                uid: event.header.uid,
                exe_path: event.filename.clone(),
                cmdline: event.args.clone(),
            },
            network: if event.daddr.is_some() {
                Some(NetworkInfo {
                    saddr: event.saddr.clone().unwrap_or_default(),
                    daddr: event.daddr.clone().unwrap_or_default(),
                    saddr6: if family == Some(AddressFamily::IPv6) {
                        event.saddr.clone()
                    } else {
                        None
                    },
                    daddr6: if family == Some(AddressFamily::IPv6) {
                        event.daddr.clone()
                    } else {
                        None
                    },
                    family,
                    sport: event.sport.unwrap_or(0),
                    dport: event.dport.unwrap_or(0),
                    proto,
                })
            } else {
                None
            },
            file: if event.filename.is_some() {
                Some(FileInfo {
                    path: event.filename.clone().unwrap_or_default(),
                    operation: FileOperation::from_event_type(event.header.event_type),
                    bytes: event.file_bytes,
                })
            } else {
                None
            },
            event_ids: vec![event.seq],
            mitre,
            status: AlertStatus::New,
            feedback: None,
        }
    }

    pub fn anomaly_score(&self, event: &DecodedEvent, recent_syscalls: usize) -> f64 {
        let mut score: f64 = 0.0;

        if recent_syscalls > 500 {
            score += 0.4;
        } else if recent_syscalls > 100 {
            score += 0.2;
        }

        if let Some(ref fname) = event.filename {
            for sensitive in &[
                "/etc/shadow",
                "/root/.ssh",
                "/etc/ssl/private",
                "/root/.gnupg",
            ] {
                if fname.contains(sensitive) {
                    score += 0.5;
                    break;
                }
            }
            if score < 0.5 {
                for sensitive in &[
                    "/etc/passwd",
                    "/etc/sudoers",
                    "/etc/crontab",
                    "/etc/ssh/sshd_config",
                ] {
                    if fname.contains(sensitive) {
                        score += 0.35;
                        break;
                    }
                }
            }
            if score < 0.35 {
                for sensitive in &["/var/log", "/proc/", "/etc/hosts"] {
                    if fname.contains(sensitive) {
                        score += 0.15;
                        break;
                    }
                }
            }
        }

        let args = event.args.as_deref().unwrap_or("");
        let suspicious_patterns: &[(&str, f64)] = &[
            ("bash -i", 0.5),
            ("/dev/tcp", 0.5),
            ("python -c", 0.4),
            ("nc -e", 0.5),
            ("wget", 0.2),
            ("curl", 0.2),
            ("chmod +s", 0.4),
            ("chmod u+s", 0.4),
            ("chmod 4755", 0.4),
            ("LD_PRELOAD", 0.4),
            ("ptrace", 0.4),
            ("nohup", 0.2),
            ("base64 -d", 0.3),
            ("mkfifo", 0.3),
        ];
        for (pattern, weight) in suspicious_patterns {
            if event.comm.contains(pattern) || args.contains(pattern) {
                score += weight;
                break;
            }
        }

        if let Some(ref fname) = event.filename {
            let ransomware_extensions: &[&str] = &[
                ".encrypted",
                ".locked",
                ".crypto",
                ".ryuk",
                ".wanna",
                ".cerber",
                ".crypt",
                ".cry",
                ".locky",
            ];
            for ext in ransomware_extensions {
                if fname.contains(ext) {
                    score += 0.4;
                    break;
                }
            }
        }

        if let Some(dport) = event.dport {
            let malicious_ports: &[u16] = &[4444, 1337, 31337, 5555, 6666, 6667, 9999, 12345];
            if malicious_ports.contains(&dport) {
                score += 0.5;
            } else if dport > 10000 && dport != 27017 && dport != 33060 && dport != 6379 {
                score += 0.2;
            }
            if let Some(ref daddr) = event.daddr {
                if !is_private_ip(daddr) {
                    score += 0.1;
                }
            }
        }

        score.min(1.0)
    }
}

fn match_i32(value: i32, op: &Operator, target: &str, cache: &HashMap<String, regex::Regex>) -> bool {
    match op {
        Operator::Equals
        | Operator::GreaterThan
        | Operator::LessThan
        | Operator::GreaterThanOrEqual
        | Operator::LessThanOrEqual
        | Operator::NotEquals => {
            let target_val: i32 = match target.parse() {
                Ok(v) => v,
                Err(_) => {
                    warn!("'{}' 不是有效的 i32", target);
                    return false;
                }
            };
            match op {
                Operator::Equals => value == target_val,
                Operator::GreaterThan => value > target_val,
                Operator::LessThan => value < target_val,
                Operator::GreaterThanOrEqual => value >= target_val,
                Operator::LessThanOrEqual => value <= target_val,
                Operator::NotEquals => value != target_val,
                _ => unreachable!(),
            }
        }
        Operator::Regex | Operator::Contains | Operator::StartsWith | Operator::NotRegex => {
            match_str(&value.to_string(), op, target, cache)
        }
    }
}

fn match_u32(value: u32, op: &Operator, target: &str, cache: &HashMap<String, regex::Regex>) -> bool {
    match op {
        Operator::Equals
        | Operator::GreaterThan
        | Operator::LessThan
        | Operator::GreaterThanOrEqual
        | Operator::LessThanOrEqual
        | Operator::NotEquals => {
            let target_val: u32 = match target.parse() {
                Ok(v) => v,
                Err(_) => {
                    warn!("'{}' 不是有效的 u32", target);
                    return false;
                }
            };
            match op {
                Operator::Equals => value == target_val,
                Operator::GreaterThan => value > target_val,
                Operator::LessThan => value < target_val,
                Operator::GreaterThanOrEqual => value >= target_val,
                Operator::LessThanOrEqual => value <= target_val,
                Operator::NotEquals => value != target_val,
                _ => unreachable!(),
            }
        }
        Operator::Regex | Operator::Contains | Operator::StartsWith | Operator::NotRegex => {
            match_str(&value.to_string(), op, target, cache)
        }
    }
}

fn match_opt_u32(value: Option<u32>, op: &Operator, target: &str, cache: &HashMap<String, regex::Regex>) -> bool {
    match value {
        Some(v) => match_u32(v, op, target, cache),
        None => false,
    }
}

fn match_opt_i32(value: Option<i32>, op: &Operator, target: &str, cache: &HashMap<String, regex::Regex>) -> bool {
    match value {
        Some(v) => match_i32(v, op, target, cache),
        None => false,
    }
}

fn match_opt_u64(value: Option<u64>, op: &Operator, target: &str) -> bool {
    let target_val: u64 = match target.parse() {
        Ok(v) => v,
        Err(_) => {
            warn!("'{}' 不是有效的 u64", target);
            return false;
        }
    };
    match value {
        Some(v) => match op {
            Operator::Equals => v == target_val,
            Operator::GreaterThan => v > target_val,
            Operator::LessThan => v < target_val,
            Operator::GreaterThanOrEqual => v >= target_val,
            Operator::LessThanOrEqual => v <= target_val,
            Operator::NotEquals => v != target_val,
            _ => false,
        },
        None => false,
    }
}

fn match_str(value: &str, op: &Operator, target: &str, cache: &HashMap<String, regex::Regex>) -> bool {
    match op {
        Operator::Equals => value == target,
        Operator::NotEquals => value != target,
        Operator::Contains => value.contains(target),
        Operator::StartsWith => value.starts_with(target),
        Operator::Regex | Operator::NotRegex => match cache.get(target) {
            Some(re) => {
                let m = re.is_match(value);
                if matches!(op, Operator::NotRegex) {
                    !m
                } else {
                    m
                }
            }
            None => false,
        },
        Operator::GreaterThan
        | Operator::LessThan
        | Operator::GreaterThanOrEqual
        | Operator::LessThanOrEqual => {
            // 非数字值不参与数值比较（恒 false）：旧实现 parse 失败静默当 0.0，
            // 会把 "abc" < 10 判成 true 这类悄悄错误的规则语义
            let (Ok(a), Ok(b)) = (value.parse::<f64>(), target.parse::<f64>()) else {
                warn!(
                    "数值比较遇到非数字值: '{}' vs '{}' — 条件按不匹配处理",
                    value, target
                );
                return false;
            };
            match op {
                Operator::GreaterThan => a > b,
                Operator::LessThan => a < b,
                Operator::GreaterThanOrEqual => a >= b,
                Operator::LessThanOrEqual => a <= b,
                _ => false,
            }
        }
    }
}

fn match_opt_str(value: Option<&str>, op: &Operator, target: &str, cache: &HashMap<String, regex::Regex>) -> bool {
    match value {
        Some(v) => match_str(v, op, target, cache),
        None => false,
    }
}

fn is_private_ip(addr: &str) -> bool {
    if addr.starts_with("10.") {
        return true;
    }
    if addr.starts_with("192.168.") {
        return true;
    }
    if addr.starts_with("172.") {
        let parts: Vec<&str> = addr.split('.').collect();
        if parts.len() >= 2 {
            if let Ok(second_octet) = parts[1].parse::<u8>() {
                if (16..=31).contains(&second_octet) {
                    return true;
                }
            }
        }
    }
    if addr.starts_with("127.") {
        return true;
    }
    if addr.starts_with("fc") || addr.starts_with("fd") || addr == "::1" {
        return true;
    }
    false
}

fn op_to_str(op: &Operator) -> &str {
    match op {
        Operator::Equals => "=",
        Operator::Contains => "contains",
        Operator::StartsWith => "startswith",
        Operator::Regex => "~=",
        Operator::GreaterThan => ">",
        Operator::LessThan => "<",
        Operator::GreaterThanOrEqual => ">=",
        Operator::LessThanOrEqual => "<=",
        Operator::NotEquals => "!=",
        Operator::NotRegex => "!~",
    }
}

fn match_ipv6_field(value: Option<&str>, op: &Operator, target: &str, cache: &HashMap<String, regex::Regex>) -> bool {
    match_opt_str(value, op, target, cache)
}

fn match_family_field(value: Option<&str>, op: &Operator, target: &str) -> bool {
    match op {
        Operator::Equals => value == Some(target),
        _ => {
            log::warn!("Family 字段不支持 {:?} 操作符", op);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::event::EventHeader;

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip("10.0.0.1"));
        assert!(is_private_ip("192.168.1.1"));
        assert!(is_private_ip("172.16.0.1"));
        assert!(is_private_ip("127.0.0.1"));
        assert!(is_private_ip("::1"));
        assert!(!is_private_ip("8.8.8.8"));
        assert!(!is_private_ip("172.15.0.1"));
    }

    #[test]
    fn test_load_rules_from_yaml() {
        let yaml = r#"
- name: test_rule
  description: "Test rule"
  severity: high
  conditions:
    - field: comm
      operator: contains
      value: "bash"
  alert_message: "bash detected"
"#;
        let mut engine = DetectionEngine::new();
        let count = engine.load_rules_from_yaml(yaml).unwrap();
        assert_eq!(count, 1);
    }

    fn make_header(event_type: u32, pid: u32) -> EventHeader {
        EventHeader {
            event_type,
            _pad1: 0,
            timestamp_ns: 100_000_000_000,
            pid,
            tid: 0,
            uid: 0,
            ppid: 0,
            comm: [0; 16],
            syscall_nr: 0,
            _pad2: 0,
            retval: 0,
        }
    }

    /// 规则层进程豁免：日志采集器读敏感日志不应命中；其他进程仍命中
    #[test]
    fn test_rule_comm_exclusion() {
        let yaml = r#"
- name: log_access
  description: "log access"
  severity: medium
  conditions:
    - field: filename
      operator: regex
      value: "^/var/log/(auth|secure)"
    - field: comm
      operator: not_regex
      value: "^(rsyslogd|AliYunDunMonito)$"
  alert_message: "log access detected"
"#;
        let mut engine = DetectionEngine::new();
        engine.load_rules_from_yaml(yaml).unwrap();
        let mk = |comm: &str| DecodedEvent {
            seq: 1,
            header: make_header(10, 100),
            comm: comm.to_string(),
            filename: Some("/var/log/secure".to_string()),
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
        assert!(
            engine.match_event(&mk("rsyslogd")).is_empty(),
            "日志守护进程读取属于本职行为，应被豁免"
        );
        assert!(
            engine.match_event(&mk("AliYunDunMonito")).is_empty(),
            "云监控代理（comm 截断名）应被豁免"
        );
        assert_eq!(
            engine.match_event(&mk("evil")).len(),
            1,
            "非豁免进程读取敏感日志仍应告警"
        );
    }

    #[test]
    fn test_regex_operator() {
        let yaml = r#"
- name: regex_test
  description: "Regex test"
  severity: medium
  conditions:
    - field: filename
      operator: regex
      value: "^/etc/.*shadow$"
  alert_message: "shadow file access"
"#;
        let mut engine = DetectionEngine::new();
        engine.load_rules_from_yaml(yaml).unwrap();
        let event = DecodedEvent {
            seq: 1,
            header: make_header(10, 100),
            comm: "cat".to_string(),
            filename: Some("/etc/shadow".to_string()),
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
        let results = engine.match_event(&event);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_anomaly_score_baseline() {
        let engine = DetectionEngine::new();
        let event = DecodedEvent {
            seq: 1,
            header: make_header(2, 100),
            comm: "ls".to_string(),
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
        };
        assert_eq!(engine.anomaly_score(&event, 0), 0.0);
    }

    #[test]
    fn test_anomaly_score_sensitive_file() {
        let engine = DetectionEngine::new();
        let event = DecodedEvent {
            seq: 1,
            header: make_header(10, 100),
            comm: "cat".to_string(),
            filename: Some("/etc/shadow".to_string()),
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
        assert!(engine.anomaly_score(&event, 0) >= 0.5);
    }

    #[test]
    fn test_numeric_field_matching() {
        let yaml = r#"
- name: syscall_match
  description: "Match syscall number"
  severity: high
  conditions:
    - field: syscall_nr
      operator: equals
      value: "59"
  alert_message: "execve detected"
"#;
        let mut engine = DetectionEngine::new();
        engine.load_rules_from_yaml(yaml).unwrap();
        let mut header = make_header(1, 100);
        header.syscall_nr = 59;
        let event = DecodedEvent {
            seq: 1,
            header,
            comm: "test".to_string(),
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
        };
        let results = engine.match_event(&event);
        assert_eq!(results.len(), 1);
    }
}

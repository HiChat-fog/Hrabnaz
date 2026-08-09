use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub conditions: Vec<Condition>,
    pub alert_message: String,
    pub mitre_tactic: Option<String>,
    pub mitre_technique: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Condition {
    pub field: Field,
    pub operator: Operator,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Field {
    #[serde(rename = "comm")]
    Comm,
    #[serde(rename = "pid")]
    Pid,
    #[serde(rename = "ppid")]
    Ppid,
    #[serde(rename = "uid")]
    Uid,
    #[serde(rename = "syscall_nr")]
    SyscallNr,
    #[serde(rename = "filename")]
    Filename,
    #[serde(rename = "args")]
    Args,
    #[serde(rename = "file_bytes")]
    FileBytes,
    #[serde(rename = "saddr")]
    Saddr,
    #[serde(rename = "daddr")]
    Daddr,
    #[serde(rename = "sport")]
    Sport,
    #[serde(rename = "dport")]
    Dport,
    #[serde(rename = "proto")]
    Proto,
    #[serde(rename = "saddr6")]
    Saddr6,
    #[serde(rename = "daddr6")]
    Daddr6,
    #[serde(rename = "family")]
    Family,
    #[serde(rename = "target_pid")]
    TargetPid,
    #[serde(rename = "signal")]
    Signal,
    // 新增字段(容器逃逸、LKM加载、eBPF篡改探针)
    #[serde(rename = "module_name")]
    ModuleName,
    #[serde(rename = "prog_name")]
    ProgName,
    #[serde(rename = "source_ns_inum")]
    SourceNsInum,
    #[serde(rename = "target_ns_inum")]
    TargetNsInum,
    #[serde(rename = "cap_eff")]
    CapEff,
    #[serde(rename = "action")]
    Action,
    #[serde(rename = "event_type")]
    EventType,
}

impl Field {
    pub fn is_numeric(&self) -> bool {
        matches!(
            self,
            Field::Pid | Field::Ppid | Field::Uid | Field::SyscallNr |
            Field::Sport | Field::Dport | Field::TargetPid | Field::Signal |
            Field::FileBytes | Field::EventType |
            // E4.4: 容器逃逸数值字段
            Field::SourceNsInum | Field::TargetNsInum | Field::CapEff
        )
    }

    pub fn is_string(&self) -> bool {
        matches!(
            self,
            Field::Comm | Field::Filename | Field::Args |
            Field::Saddr | Field::Daddr | Field::Proto |
            Field::Saddr6 | Field::Daddr6 | Field::Family |
            // LKM和eBPF字符串字段
            Field::ModuleName | Field::ProgName | Field::Action
        )
    }

    pub fn yaml_name(&self) -> &'static str {
        match self {
            Field::Comm => "comm",
            Field::Pid => "pid",
            Field::Ppid => "ppid",
            Field::Uid => "uid",
            Field::SyscallNr => "syscall_nr",
            Field::Filename => "filename",
            Field::Args => "args",
            Field::FileBytes => "file_bytes",
            Field::Saddr => "saddr",
            Field::Daddr => "daddr",
            Field::Sport => "sport",
            Field::Dport => "dport",
            Field::Proto => "proto",
            Field::Saddr6 => "saddr6",
            Field::Daddr6 => "daddr6",
            Field::Family => "family",
            Field::TargetPid => "target_pid",
            Field::Signal => "signal",
            // E4.4 新增字段
            Field::ModuleName => "module_name",
            Field::ProgName => "prog_name",
            Field::SourceNsInum => "source_ns_inum",
            Field::TargetNsInum => "target_ns_inum",
            Field::CapEff => "cap_eff",
            Field::Action => "action",
            Field::EventType => "event_type",
        }
    }

    pub fn all_yaml_names() -> &'static [&'static str] {
        &[
            "comm",
            "pid",
            "ppid",
            "uid",
            "syscall_nr",
            "filename",
            "args",
            "file_bytes",
            "saddr",
            "daddr",
            "sport",
            "dport",
            "proto",
            "saddr6",
            "daddr6",
            "family",
            "target_pid",
            "signal",
            // E4.4 新增字段
            "module_name",
            "prog_name",
            "source_ns_inum",
            "target_ns_inum",
            "cap_eff",
            "action",
        ]
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.yaml_name())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Operator {
    #[serde(rename = "equals")]
    Equals,
    #[serde(rename = "contains")]
    Contains,
    #[serde(rename = "starts_with")]
    StartsWith,
    #[serde(rename = "regex")]
    Regex,
    #[serde(rename = "gt")]
    GreaterThan,
    #[serde(rename = "lt")]
    LessThan,
    #[serde(rename = "gte")]
    GreaterThanOrEqual,
    #[serde(rename = "lte")]
    LessThanOrEqual,
    #[serde(rename = "not_equals")]
    NotEquals,
    /// 值不匹配给定正则(用于"非私有IP"等反向匹配,规避Rust regex不支持look-around)
    #[serde(rename = "not_regex")]
    NotRegex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub rule_name: String,
    pub severity: Severity,
    pub alert_message: String,
    pub matched_conditions: Vec<String>,
}

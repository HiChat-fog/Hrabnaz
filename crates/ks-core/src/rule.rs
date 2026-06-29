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
}

impl Field {
    pub fn is_numeric(&self) -> bool {
        matches!(self,
            Field::Pid | Field::Ppid | Field::Uid | Field::SyscallNr |
            Field::Sport | Field::Dport | Field::TargetPid | Field::Signal |
            Field::FileBytes
        )
    }

    pub fn is_string(&self) -> bool {
        matches!(self,
            Field::Comm | Field::Filename | Field::Args |
            Field::Saddr | Field::Daddr | Field::Proto |
            Field::Saddr6 | Field::Daddr6 | Field::Family
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
        }
    }

    pub fn all_yaml_names() -> &'static [&'static str] {
        &[
            "comm", "pid", "ppid", "uid", "syscall_nr",
            "filename", "args", "file_bytes",
            "saddr", "daddr", "sport", "dport", "proto",
            "saddr6", "daddr6", "family",
            "target_pid", "signal",
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub rule_name: String,
    pub severity: Severity,
    pub alert_message: String,
    pub matched_conditions: Vec<String>,
}
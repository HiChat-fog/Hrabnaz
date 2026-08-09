use crate::rule::Severity;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AddressFamily {
    #[serde(rename = "IPv4")]
    #[default]
    IPv4,
    #[serde(rename = "IPv6")]
    IPv6,
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressFamily::IPv4 => write!(f, "IPv4"),
            AddressFamily::IPv6 => write!(f, "IPv6"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    #[serde(rename = "TCP")]
    TCP,
    #[serde(rename = "UDP")]
    UDP,
    #[serde(rename = "ICMP")]
    ICMP,
    #[serde(rename = "OTHER")]
    #[default]
    OTHER,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::TCP => write!(f, "TCP"),
            Protocol::UDP => write!(f, "UDP"),
            Protocol::ICMP => write!(f, "ICMP"),
            Protocol::OTHER => write!(f, "OTHER"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOperation {
    #[serde(rename = "open")]
    Open,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "write")]
    Write,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "rename")]
    Rename,
    #[serde(rename = "chmod")]
    Chmod,
    #[serde(rename = "unknown")]
    Unknown,
}

impl FileOperation {
    pub fn from_event_type(event_type: u32) -> Self {
        match event_type {
            10 => FileOperation::Open,
            11 => FileOperation::Read,
            12 => FileOperation::Write,
            13 => FileOperation::Delete,
            14 => FileOperation::Rename,
            15 => FileOperation::Chmod,
            _ => FileOperation::Unknown,
        }
    }
}

impl fmt::Display for FileOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileOperation::Open => write!(f, "open"),
            FileOperation::Read => write!(f, "read"),
            FileOperation::Write => write!(f, "write"),
            FileOperation::Delete => write!(f, "delete"),
            FileOperation::Rename => write!(f, "rename"),
            FileOperation::Chmod => write!(f, "chmod"),
            FileOperation::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlertStatus {
    #[serde(rename = "new")]
    #[default]
    New,
    #[serde(rename = "investigating")]
    Investigating,
    #[serde(rename = "resolved")]
    Resolved,
    #[serde(rename = "false_positive")]
    FalsePositive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: Uuid,
    pub timestamp_ns: u64,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub rule_name: String,
    pub process: ProcessInfo,
    pub network: Option<NetworkInfo>,
    pub file: Option<FileInfo>,
    pub event_ids: Vec<u64>,
    pub mitre: Option<MitreInfo>,
    pub status: AlertStatus,
    /// 误报反馈,None为未反馈,Some(true)为确认告警,Some(false)为误报
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feedback: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub uid: u32,
    pub exe_path: Option<String>,
    pub cmdline: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInfo {
    pub saddr: String,
    pub daddr: String,
    pub saddr6: Option<String>,
    pub daddr6: Option<String>,
    pub family: Option<AddressFamily>,
    pub sport: u16,
    pub dport: u16,
    pub proto: Protocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub path: String,
    pub operation: FileOperation,
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreInfo {
    pub tactic: String,
    pub technique: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_technique: Option<String>,
}

impl Alert {
    pub fn new(severity: Severity, title: String, rule_name: String, process: ProcessInfo) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp_ns: 0,
            severity,
            title,
            description: String::new(),
            rule_name,
            process,
            network: None,
            file: None,
            event_ids: Vec::new(),
            mitre: None,
            status: AlertStatus::New,
            feedback: None,
        }
    }
}

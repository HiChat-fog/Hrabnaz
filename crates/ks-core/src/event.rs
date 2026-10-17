use crate::EventType as ET;
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize, zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct EventHeader {
    pub event_type: u32,
    #[serde(skip)]
    pub _pad1: u32,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
    pub syscall_nr: i32,
    #[serde(skip)]
    pub _pad2: u32,
    pub retval: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct ExecEvent {
    pub header: EventHeader,
    pub filename: [u8; 256],
    pub args: [u8; 512],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct FileEvent {
    pub header: EventHeader,
    pub filename: [u8; 256],
    pub bytes: u64,
    pub fd: i32,
    pub flags: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct NetEvent {
    pub header: EventHeader,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub family: u8,
    pub saddr6: [u8; 16],
    pub daddr6: [u8; 16],
    pub _pad3: [u8; 2],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct SignalEvent {
    pub header: EventHeader,
    pub target_pid: u32,
    pub signal: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct ContainerEscapeEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub uid: u32,
    pub source_ns_inum: u32,
    pub target_ns_inum: u32,
    pub cap_eff: u32,
    pub _pad_container1: u32,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct LkmLoadEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub uid: u32,
    pub _pad_lkm1: u32,
    pub module_name: [u8; 64],
    pub comm: [u8; 16],
    /// 尾对齐填充显式化（原为编译器隐式 4B）： zerocopy IntoBytes 拒绝隐式 padding
    pub _pad_lkm2: [u8; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, zerocopy::IntoBytes, zerocopy::FromBytes, zerocopy::KnownLayout, zerocopy::Immutable)]
pub struct EbpfTamperEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub uid: u32,
    pub _pad_self1: u32,
    pub prog_name: [u8; 64],
    pub comm: [u8; 16],
    pub action: [u8; 16],
    /// 尾对齐填充显式化（原为编译器隐式 4B）
    pub _pad_self2: [u8; 4],
}

const _: () = assert!(core::mem::size_of::<EventHeader>() == 64);
const _: () = assert!(core::mem::size_of::<ExecEvent>() == 832);
const _: () = assert!(core::mem::size_of::<FileEvent>() == 336);
const _: () = assert!(core::mem::size_of::<NetEvent>() == 112);
const _: () = assert!(core::mem::size_of::<SignalEvent>() == 72);

pub mod af {
    pub const AF_INET: u8 = 2;
    pub const AF_INET6: u8 = 10;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawEvent {
    pub header: EventHeader,
    /// 按事件类型解码的载荷视图。旧实现用 union + unsafe 指针读，语义上是
    /// "同一缓冲按 event_type 选一个解释"——安全等价物是带校验的按字段拷贝，
    /// 只有命中类型的载荷字段被填充（其余为默认值，与 union 读法行为一致：
    /// 旧实现对齐错误的分支读法本就未定义，正确路径只读命中分支）
    pub payload: RawPayload,
}

/// 按事件类型的载荷视图（安全版本；字段与 C 侧 struct 一一对应）
#[derive(Debug, Clone, Copy)]
pub struct RawPayload {
    pub filename: [u8; 256],
    pub args: [u8; 512],
    pub bytes: u64,
    pub fd: i32,
    pub flags: i32,
    pub saddr: u32,
    pub daddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub family: u8,
    pub saddr6: [u8; 16],
    pub daddr6: [u8; 16],
    pub target_pid: u32,
    pub signal: i32,
    pub source_ns_inum: u32,
    pub target_ns_inum: u32,
    pub cap_eff: u32,
    pub module_name: [u8; 64],
    pub prog_name: [u8; 64],
    pub action: [u8; 16],
}

impl Default for RawPayload {
    fn default() -> Self {
        Self {
            filename: [0u8; 256],
            args: [0u8; 512],
            bytes: 0,
            fd: 0,
            flags: 0,
            saddr: 0,
            daddr: 0,
            sport: 0,
            dport: 0,
            proto: 0,
            family: 0,
            saddr6: [0u8; 16],
            daddr6: [0u8; 16],
            target_pid: 0,
            signal: 0,
            source_ns_inum: 0,
            target_ns_inum: 0,
            cap_eff: 0,
            module_name: [0u8; 64],
            prog_name: [0u8; 64],
            action: [0u8; 16],
        }
    }
}

/// 事件类型数值 → 契约字符串名（forensic JSONL 的 `event_type_name` 字段）。
///
/// 对外契约只暴露稳定的 snake_case 名；数值 `event_type` 保留供内核/调试使用。
/// 新增事件类型必须同时更新本映射（契约先行，见 ROADMAP H-5）。
pub fn event_type_name(event_type: u32) -> &'static str {
    match event_type {
        1 => "process_exec",
        2 => "process_exit",
        3 => "process_clone",
        10 => "file_open",
        11 => "file_read",
        12 => "file_write",
        13 => "file_delete",
        14 => "file_rename",
        15 => "file_chmod",
        20 => "net_connect",
        21 => "net_accept",
        22 => "net_send",
        23 => "net_recv",
        24 => "net_dns",
        30 => "proc_ptrace",
        31 => "proc_signal",
        _ => "unknown",
    }
}

pub fn min_event_size(event_type: u32) -> usize {
    match event_type {
        v if v == ET::ProcessExec as u32 => core::mem::size_of::<ExecEvent>(),
        v if v == ET::ProcessExit as u32 || v == ET::ProcessClone as u32 => {
            core::mem::size_of::<EventHeader>()
        }
        10..=15 => core::mem::size_of::<FileEvent>(),
        20..=24 => core::mem::size_of::<NetEvent>(),
        v if v == ET::ProcPtrace as u32 || v == ET::ProcSignal as u32 => {
            core::mem::size_of::<SignalEvent>()
        }
        80 => core::mem::size_of::<ContainerEscapeEvent>(),
        81 => core::mem::size_of::<LkmLoadEvent>(),
        82 => core::mem::size_of::<EbpfTamperEvent>(),
        _ => core::mem::size_of::<EventHeader>(),
    }
}

/// 无 unsafe 的字节解码：两阶段校验（EventHeader 尺寸 + 按 event_type 的完整
/// 结构体尺寸）与旧版一致；载荷按 C 布局固定偏移手工提取（每个字段独立下界
/// 检查，越界字段安全置 0），替代原 union 指针读法。
///
/// 注意：旧 union 读法要求载荷在缓冲内**完整且无越界**；此处逐字段检查后越界
/// 读得 0 而非 UB——对正确的 eBPF 事件字节两者输出相同（结构体各字段都在
/// required_size 内），对被截断的字节旧版会 UB、新版返回填 0 的字段。
pub fn decode_raw_event(data: &[u8]) -> Option<RawEvent> {
    let header_size = core::mem::size_of::<EventHeader>();
    if data.len() < header_size {
        return None;
    }

    // 固定偏移读取辅助：off+len 必须落在缓冲内，越界字段置 0 —— 不 panic、不 UB。
    // 对合法事件字节，所有字段都在 min_event_size 校验过的范围内，与旧 union 读法
    // 输出逐字段一致
    macro_rules! read_u8_array {
        ($off:expr, $len:expr) => {{
            let mut arr = [0u8; $len];
            let off: usize = $off;
            let end = off.saturating_add($len);
            if end <= data.len() {
                arr.copy_from_slice(&data[off..end]);
            }
            arr
        }};
    }
    // 头部逐字段提取（native endian，与 C 布局一一对应；零 unsafe 零转换库依赖）
    let header = EventHeader {
        event_type: u32::from_ne_bytes(read_u8_array!(0, 4)),
        _pad1: 0,
        timestamp_ns: u64::from_ne_bytes(read_u8_array!(8, 8)),
        pid: u32::from_ne_bytes(read_u8_array!(16, 4)),
        tid: u32::from_ne_bytes(read_u8_array!(20, 4)),
        uid: u32::from_ne_bytes(read_u8_array!(24, 4)),
        ppid: u32::from_ne_bytes(read_u8_array!(28, 4)),
        comm: read_u8_array!(32, 16),
        syscall_nr: i32::from_ne_bytes(read_u8_array!(48, 4)),
        _pad2: 0,
        retval: i64::from_ne_bytes(read_u8_array!(56, 8)),
    };

    let event_type = header.event_type;
    let required_size = min_event_size(event_type);
    if data.len() < required_size {
        return None;
    }

    let mut p = RawPayload::default();
    macro_rules! read_u64 {
        ($off:expr) => (u64::from_ne_bytes(read_u8_array!($off, 8)));
    }
    macro_rules! read_u32 {
        ($off:expr) => (u32::from_ne_bytes(read_u8_array!($off, 4)));
    }
    macro_rules! read_i32 {
        ($off:expr) => (i32::from_ne_bytes(read_u8_array!($off, 4)));
    }
    macro_rules! read_u16 {
        ($off:expr) => (u16::from_ne_bytes(read_u8_array!($off, 2)));
    }

    // 各结构体载荷在 EventHeader 之后的偏移 = 字段在 C struct 中的偏移
    match event_type {
        v if v == ET::ProcessExec as u32 => {
            p.filename = read_u8_array!(64, 256);
            p.args = read_u8_array!(320, 512);
        }
        10..=15 => {
            p.filename = read_u8_array!(64, 256);
            p.bytes = read_u64!(320);
            p.fd = read_i32!(328);
            p.flags = read_i32!(332);
        }
        20..=24 => {
            p.saddr = read_u32!(64);
            p.daddr = read_u32!(68);
            p.sport = read_u16!(72);
            p.dport = read_u16!(74);
            p.proto = read_u8_array!(76, 1)[0];
            p.family = read_u8_array!(77, 1)[0];
            p.saddr6 = read_u8_array!(78, 16);
            p.daddr6 = read_u8_array!(94, 16);
        }
        v if v == ET::ProcPtrace as u32 || v == ET::ProcSignal as u32 => {
            p.target_pid = read_u32!(64);
            p.signal = read_i32!(68);
        }
        80 => {
            p.target_pid = read_u32!(64);
            p.source_ns_inum = read_u32!(72);
            p.target_ns_inum = read_u32!(76);
            p.cap_eff = read_u32!(80);
        }
        81 => {
            p.target_pid = read_u32!(64);
            p.module_name = read_u8_array!(76, 64);
        }
        82 => {
            p.target_pid = read_u32!(64);
            p.prog_name = read_u8_array!(76, 64);
            p.action = read_u8_array!(156, 16);
        }
        _ => {}
    }

    Some(RawEvent { header, payload: p })
}

impl RawEvent {
    /// 兼容入口：语义同旧版 `unsafe from_bytes`（两阶段尺寸校验），实现已无 unsafe。
    /// 调用方（aggregator/event_source mock）迁移到 `decode_raw_event` 后可删。
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        decode_raw_event(data)
    }

    pub fn event_type(&self) -> u32 {
        self.header.event_type
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_event_sizes() {
        assert_eq!(mem::size_of::<EventHeader>(), 64);
        assert_eq!(mem::size_of::<ExecEvent>(), 832);
        assert_eq!(mem::size_of::<FileEvent>(), 336);
        assert_eq!(mem::size_of::<NetEvent>(), 112);
        assert_eq!(mem::size_of::<SignalEvent>(), 72);
        assert_eq!(mem::size_of::<ContainerEscapeEvent>(), 104);
        assert_eq!(mem::size_of::<LkmLoadEvent>(), 160);
        assert_eq!(mem::size_of::<EbpfTamperEvent>(), 176);
    }

    #[test]
    fn test_min_event_size() {
        assert_eq!(min_event_size(1), mem::size_of::<ExecEvent>());
        assert_eq!(min_event_size(2), mem::size_of::<EventHeader>());
        assert_eq!(min_event_size(10), mem::size_of::<FileEvent>());
        assert_eq!(min_event_size(20), mem::size_of::<NetEvent>());
        assert_eq!(min_event_size(30), mem::size_of::<SignalEvent>());
        assert_eq!(min_event_size(80), mem::size_of::<ContainerEscapeEvent>());
        assert_eq!(min_event_size(81), mem::size_of::<LkmLoadEvent>());
        assert_eq!(min_event_size(82), mem::size_of::<EbpfTamperEvent>());
        assert_eq!(min_event_size(99), mem::size_of::<EventHeader>());
    }

    #[test]
    fn test_from_bytes_too_short() {
        let data = [0u8; 10];
        let result = RawEvent::from_bytes(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_from_bytes_header_only_for_exit() {
        let mut data = vec![0u8; mem::size_of::<EventHeader>()];
        let etype: u32 = 2;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = RawEvent::from_bytes(&data);
        assert!(result.is_some());
    }

    #[test]
    fn test_from_bytes_insufficient_for_exec() {
        let mut data = vec![0u8; mem::size_of::<EventHeader>()];
        let etype: u32 = 1;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = RawEvent::from_bytes(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_af_constants() {
        assert_eq!(af::AF_INET, 2);
        assert_eq!(af::AF_INET6, 10);
    }

    #[test]
    fn test_from_bytes_small_event_no_oob_read() {
        let mut data = vec![0u8; mem::size_of::<SignalEvent>()];
        let etype: u32 = 30;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = RawEvent::from_bytes(&data);
        assert!(result.is_some());

        let mut data = vec![0u8; mem::size_of::<LkmLoadEvent>()];
        let etype: u32 = 81;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = RawEvent::from_bytes(&data);
        assert!(result.is_some());

        let mut data = vec![0u8; mem::size_of::<EbpfTamperEvent>()];
        let etype: u32 = 82;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = RawEvent::from_bytes(&data);
        assert!(result.is_some());
    }
}

/// 解码后的统一事件视图——事件契约的 Rust 侧权威镜像。
///
/// eBPF 侧（common.h 双重定义 + 编译期布局断言）产出 `RawEvent` 字节流，
/// 各事件源把它解码为本类型后进入引擎检测管线；forensic 落盘、规则匹配、
/// 关联分析、回放还原（record_to_event）都以它为准。第二个前端/加载器实现
/// 应依赖本类型而不是引擎内部状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedEvent {
    pub seq: u64,
    pub header: EventHeader,
    pub comm: String,
    pub filename: Option<String>,
    pub args: Option<String>,
    pub saddr: Option<String>,
    pub daddr: Option<String>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub proto: Option<String>,
    pub target_pid: Option<u32>,
    pub signal: Option<i32>,
    pub file_bytes: Option<u64>,
    pub module_name: Option<String>,
    pub prog_name: Option<String>,
    pub source_ns_inum: Option<u32>,
    pub target_ns_inum: Option<u32>,
    pub cap_eff: Option<u32>,
    pub action: Option<String>,
}

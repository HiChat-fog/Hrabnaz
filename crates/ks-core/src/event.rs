use crate::EventType as ET;
use serde::{Deserialize, Serialize};

// 所有事件结构体都用 #[repr(C)]，跟 eBPF C 代码内存布局对齐。
// ring buffer 读出来的字节直接 cast 过来。

#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub header: EventHeader,
    pub filename: [u8; 256],
    pub args: [u8; 512],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileEvent {
    pub header: EventHeader,
    pub filename: [u8; 256],
    pub bytes: u64,
    pub fd: i32,
    pub flags: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
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
#[derive(Debug, Clone, Copy)]
pub struct SignalEvent {
    pub header: EventHeader,
    pub target_pid: u32,
    pub signal: i32,
}

/// E4.4.1: 容器逃逸探针事件 (镜像 ks_probes_container.h 的 container_escape_event)。
/// event_type=80, kprobe/commit_creds 触发。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
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

/// E4.4.2: 内核模块加载探针事件 (镜像 ks_probes_lkm.h 的 lkm_load_event)。
/// event_type=81, kprobe/do_init_module 触发。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LkmLoadEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub uid: u32,
    pub _pad_lkm1: u32,
    pub module_name: [u8; 64],
    pub comm: [u8; 16],
}

/// E4.4.3: eBPF 程序篡改探针事件 (镜像 ks_probes_self_protect.h 的 ebpf_tamper_event)。
/// event_type=82, kprobe/security_bpf_prog_free 触发。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EbpfTamperEvent {
    pub header: EventHeader,
    pub pid: u32,
    pub uid: u32,
    pub _pad_self1: u32,
    pub prog_name: [u8; 64],
    pub comm: [u8; 16],
    pub action: [u8; 16],
}

// 申报书 section 3（C/Rust 内存对齐与零拷贝传输）：编译期静态断言每个
// 事件结构体大小。若 C 端与 Rust 端任一字段遗漏或对齐不一致，此处编译期
// 失败报错，而非运行时数据错乱。
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
pub union RawEvent {
    pub header: EventHeader,
    pub exec: ExecEvent,
    pub file: FileEvent,
    pub net: NetEvent,
    pub signal: SignalEvent,
    pub container_escape: ContainerEscapeEvent,
    pub lkm_load: LkmLoadEvent,
    pub ebpf_tamper: EbpfTamperEvent,
}

/// 每种事件类型对应的结构体大小，做越界检查用。
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

impl RawEvent {
    /// 从 ring buffer 裸字节解析事件。
    /// 先读 event_type 判断类型，再按需做完整长度校验，
    /// 用 read_unaligned 避免对齐 UB。
    ///
    /// 注意: 任何事件 struct (如 SignalEvent=72B / NetEvent=112B / FileEvent=336B) 都小于
    /// RawEvent union 大小 (832B = ExecEvent 大小)。直接 read_unaligned(data.as_ptr() as *const RawEvent)
    /// 会无条件读满 832 字节，对 struct < 832 的事件触发 OOB 读，并行测试下可能撞未映射页 → SIGSEGV。
    /// 修复: 用栈缓冲零填充 —— 先清零 832 字节栈缓冲，再 copy 实际数据，最后 read_unaligned。
    ///
    /// # Safety
    ///
    /// 调用方必须保证 `data` 指向有效内存且 `data.len() >= size_of::<EventHeader>()`。
    /// 函数内部已做两阶段长度校验并用栈缓冲零填充避免 OOB 读，对任意长度的 `data` 均安全。
    pub unsafe fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < core::mem::size_of::<EventHeader>() {
            return None;
        }

        let event_type = core::ptr::read_unaligned(data.as_ptr() as *const u32);

        let required_size = min_event_size(event_type);
        if data.len() < required_size {
            return None;
        }

        // 栈缓冲零填充: 先清零整个 RawEvent 大小，再 copy 实际数据，避免 OOB 读。
        // 栈缓冲本身在栈上分配，访问整个 832 字节范围安全 (不会撞未映射页)。
        let mut buf = [0u8; core::mem::size_of::<RawEvent>()];
        let copy_len = data.len().min(buf.len());
        core::ptr::copy_nonoverlapping(data.as_ptr(), buf.as_mut_ptr(), copy_len);
        Some(core::ptr::read_unaligned(buf.as_ptr() as *const RawEvent))
    }

    pub fn event_type(&self) -> u32 {
        unsafe { self.header.event_type }
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
        // E4.4 新增结构体大小校验 (与 eBPF C 端布局对齐)
        // 注意: struct align 跟 EventHeader 的最大字段 (u64) 一致 = 8，
        // 因此 struct size 必须是 8 的倍数 (尾部 padding)。
        // ContainerEscapeEvent: 64 + 6*4 + 16 = 104 (8 倍数，无 padding)
        assert_eq!(mem::size_of::<ContainerEscapeEvent>(), 104);
        // LkmLoadEvent: 64 + 3*4 + 64 + 16 = 156 → 向上对齐到 160
        assert_eq!(mem::size_of::<LkmLoadEvent>(), 160);
        // EbpfTamperEvent: 64 + 3*4 + 64 + 16 + 16 = 172 → 向上对齐到 176
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
        let result = unsafe { RawEvent::from_bytes(&data) };
        assert!(result.is_none());
    }

    #[test]
    fn test_from_bytes_header_only_for_exit() {
        let mut data = vec![0u8; mem::size_of::<EventHeader>()];
        let etype: u32 = 2;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = unsafe { RawEvent::from_bytes(&data) };
        assert!(result.is_some());
    }

    #[test]
    fn test_from_bytes_insufficient_for_exec() {
        let mut data = vec![0u8; mem::size_of::<EventHeader>()];
        let etype: u32 = 1;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = unsafe { RawEvent::from_bytes(&data) };
        assert!(result.is_none());
    }

    #[test]
    fn test_af_constants() {
        assert_eq!(af::AF_INET, 2);
        assert_eq!(af::AF_INET6, 10);
    }

    /// 回归测试: 小于 RawEvent union size (832B) 的事件不应触发 OOB 读。
    /// 历史 bug: 直接 read_unaligned(data.as_ptr() as *const RawEvent) 会读满 832 字节，
    /// 对 struct < 832 的事件 (如 SignalEvent=72B) 触发 OOB 读，并行测试下撞未映射页 → SIGSEGV。
    /// 修复后用栈缓冲零填充，应安全读取任意 size >= min_event_size 的数据。
    #[test]
    fn test_from_bytes_small_event_no_oob_read() {
        // SignalEvent 仅 72 字节，远小于 RawEvent union 大小 (832B)
        let mut data = vec![0u8; mem::size_of::<SignalEvent>()];
        let etype: u32 = 30; // ProcSignal
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = unsafe { RawEvent::from_bytes(&data) };
        assert!(result.is_some());

        // LkmLoadEvent 156 字节
        let mut data = vec![0u8; mem::size_of::<LkmLoadEvent>()];
        let etype: u32 = 81;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = unsafe { RawEvent::from_bytes(&data) };
        assert!(result.is_some());

        // EbpfTamperEvent 172 字节
        let mut data = vec![0u8; mem::size_of::<EbpfTamperEvent>()];
        let etype: u32 = 82;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = unsafe { RawEvent::from_bytes(&data) };
        assert!(result.is_some());
    }
}

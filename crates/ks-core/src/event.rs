use crate::EventType as ET;

// 所有事件结构体都用 #[repr(C)]，跟 eBPF C 代码内存布局对齐。
// ring buffer 读出来的字节直接 cast 过来。

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EventHeader {
    pub event_type: u32,
    pub _pad1: u32,
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub ppid: u32,
    pub comm: [u8; 16],
    pub syscall_nr: i32,
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
}

/// 每种事件类型对应的结构体大小，做越界检查用。
pub fn min_event_size(event_type: u32) -> usize {
    match event_type {
        v if v == ET::ProcessExec as u32 => core::mem::size_of::<ExecEvent>(),
        v if v == ET::ProcessExit as u32 || v == ET::ProcessClone as u32 => core::mem::size_of::<EventHeader>(),
        10..=15 => core::mem::size_of::<FileEvent>(),
        20..=24 => core::mem::size_of::<NetEvent>(),
        v if v == ET::ProcPtrace as u32 || v == ET::ProcSignal as u32 => core::mem::size_of::<SignalEvent>(),
        _ => core::mem::size_of::<EventHeader>(),
    }
}

impl RawEvent {
    /// 从 ring buffer 裸字节解析事件。
    /// 先读 event_type 判断类型，再按需做完整长度校验，
    /// 用 read_unaligned 避免对齐 UB。
    pub unsafe fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < core::mem::size_of::<EventHeader>() {
            return None;
        }

        let event_type = core::ptr::read_unaligned(data.as_ptr() as *const u32);

        let required_size = min_event_size(event_type);
        if data.len() < required_size {
            return None;
        }

        Some(core::ptr::read_unaligned(data.as_ptr() as *const RawEvent))
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
    }

    #[test]
    fn test_min_event_size() {
        assert_eq!(min_event_size(1), mem::size_of::<ExecEvent>());
        assert_eq!(min_event_size(2), mem::size_of::<EventHeader>());
        assert_eq!(min_event_size(10), mem::size_of::<FileEvent>());
        assert_eq!(min_event_size(20), mem::size_of::<NetEvent>());
        assert_eq!(min_event_size(30), mem::size_of::<SignalEvent>());
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
}
use crate::EventType as ET;
use serde::{Deserialize, Serialize};

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
    pub unsafe fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < core::mem::size_of::<EventHeader>() {
            return None;
        }

        let event_type = core::ptr::read_unaligned(data.as_ptr() as *const u32);

        let required_size = min_event_size(event_type);
        if data.len() < required_size {
            return None;
        }

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

    #[test]
    fn test_from_bytes_small_event_no_oob_read() {
        let mut data = vec![0u8; mem::size_of::<SignalEvent>()];
        let etype: u32 = 30;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = unsafe { RawEvent::from_bytes(&data) };
        assert!(result.is_some());

        let mut data = vec![0u8; mem::size_of::<LkmLoadEvent>()];
        let etype: u32 = 81;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = unsafe { RawEvent::from_bytes(&data) };
        assert!(result.is_some());

        let mut data = vec![0u8; mem::size_of::<EbpfTamperEvent>()];
        let etype: u32 = 82;
        data[..4].copy_from_slice(&etype.to_ne_bytes());
        let result = unsafe { RawEvent::from_bytes(&data) };
        assert!(result.is_some());
    }
}

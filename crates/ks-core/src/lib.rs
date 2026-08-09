pub mod alert;
pub mod event;
pub mod rule;

use serde::{Deserialize, Serialize};

pub mod syscall_nr {
    pub const EXECVE: i32 = 59;
    pub const OPEN: i32 = 2;
    pub const OPENAT: i32 = 257;
    pub const READ: i32 = 0;
    pub const WRITE: i32 = 1;
    pub const CONNECT: i32 = 42;
    pub const PTRACE: i32 = 101;
    pub const KILL: i32 = 62;
    pub const FORK: i32 = 9;
    pub const CLONE: i32 = 56;
    pub const UNLINK: i32 = 87;
    pub const UNLINKAT: i32 = 263;
    pub const RENAME: i32 = 82;
    pub const CHMOD: i32 = 90;
    pub const SOCKET: i32 = 41;
    pub const BIND: i32 = 49;
    pub const LISTEN: i32 = 50;
    pub const ACCEPT: i32 = 43;
    pub const SENDTO: i32 = 44;
    pub const RECVFROM: i32 = 45;
}

/// ARM64架构的系统调用号跟x86_64不一样。
/// 注意ARM64没有fork(),只有clone,unlink也不存在,用unlinkat代替。
pub mod syscall_nr_aarch64 {
    pub const EXECVE: i32 = 221;
    pub const OPENAT: i32 = 56;
    pub const READ: i32 = 63;
    pub const WRITE: i32 = 64;
    pub const CONNECT: i32 = 203;
    pub const PTRACE: i32 = 117;
    pub const KILL: i32 = 129;
    pub const CLONE: i32 = 220;
    pub const UNLINKAT: i32 = 35;
    pub const RENAMEAT: i32 = 38;
    pub const CHMOD: i32 = 51;
    pub const SOCKET: i32 = 198;
    pub const BIND: i32 = 200;
    pub const LISTEN: i32 = 201;
    pub const ACCEPT: i32 = 202;
    pub const SENDTO: i32 = 206;
    pub const RECVFROM: i32 = 207;
}

pub fn event_type_from_syscall_nr(nr: i32) -> Option<EventType> {
    match nr {
        syscall_nr::EXECVE => Some(EventType::ProcessExec),
        syscall_nr::OPEN | syscall_nr::OPENAT => Some(EventType::FileOpen),
        syscall_nr::CONNECT => Some(EventType::NetConnect),
        syscall_nr::PTRACE => Some(EventType::ProcPtrace),
        syscall_nr::KILL => Some(EventType::ProcSignal),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u32)]
pub enum EventType {
    Unknown = 0,
    ProcessExec = 1,
    ProcessExit = 2,
    ProcessClone = 3,
    FileOpen = 10,
    FileRead = 11,
    FileWrite = 12,
    FileDelete = 13,
    FileRename = 14,
    FileChmod = 15,
    NetConnect = 20,
    NetAccept = 21,
    NetSend = 22,
    NetRecv = 23,
    NetDns = 24,
    ProcPtrace = 30,
    ProcSignal = 31,
}

/// TryFrom<u32>,从原始u32值反序列化EventType。
/// 不知道的值返回Err,不静默吞掉。
impl TryFrom<u32> for EventType {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EventType::Unknown),
            1 => Ok(EventType::ProcessExec),
            2 => Ok(EventType::ProcessExit),
            3 => Ok(EventType::ProcessClone),
            10 => Ok(EventType::FileOpen),
            11 => Ok(EventType::FileRead),
            12 => Ok(EventType::FileWrite),
            13 => Ok(EventType::FileDelete),
            14 => Ok(EventType::FileRename),
            15 => Ok(EventType::FileChmod),
            20 => Ok(EventType::NetConnect),
            21 => Ok(EventType::NetAccept),
            22 => Ok(EventType::NetSend),
            23 => Ok(EventType::NetRecv),
            24 => Ok(EventType::NetDns),
            30 => Ok(EventType::ProcPtrace),
            31 => Ok(EventType::ProcSignal),
            _ => Err(()),
        }
    }
}

impl From<EventType> for u32 {
    fn from(et: EventType) -> u32 {
        et as u32
    }
}

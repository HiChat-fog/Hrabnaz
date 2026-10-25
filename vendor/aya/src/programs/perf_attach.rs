//! Perf attach links.
use std::{
    io,
    os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, RawFd},
};

use aya_obj::generated::bpf_attach_type::BPF_PERF_EVENT;

use crate::{
    FEATURES,
    programs::{FdLink, Link, ProgramError, id_as_key, probe::ProbeEvent},
    sys::{
        BpfLinkCreateArgs, LinkTarget, PerfEventIoctlRequest, SyscallError, bpf_link_create,
        is_bpf_cookie_supported, perf_event_ioctl,
    },
};

#[derive(Debug, Hash, Eq, PartialEq)]
pub(crate) enum PerfLinkIdInner {
    FdLinkId(<FdLink as Link>::Id),
    PerfLinkId(<PerfLink as Link>::Id),
}

#[derive(Debug)]
pub(crate) enum PerfLinkInner {
    Fd(FdLink),
    PerfLink(PerfLink),
}

impl Link for PerfLinkInner {
    type Id = PerfLinkIdInner;

    fn id(&self) -> Self::Id {
        match self {
            Self::Fd(link) => PerfLinkIdInner::FdLinkId(link.id()),
            Self::PerfLink(link) => PerfLinkIdInner::PerfLinkId(link.id()),
        }
    }

    fn detach(self) -> Result<(), ProgramError> {
        match self {
            Self::Fd(link) => link.detach(),
            Self::PerfLink(link) => link.detach(),
        }
    }
}

id_as_key!(PerfLinkInner, PerfLinkIdInner);

/// The identifier of a `PerfLink`.
#[derive(Debug, Hash, Eq, PartialEq)]
pub struct PerfLinkId(RawFd);

/// The attachment type of [`PerfEvent`] programs.
///
/// [`PerfEvent`]: crate::programs::PerfEvent
#[derive(Debug)]
pub(crate) struct PerfLink {
    perf_fd: crate::MockableFd,
    event: Option<ProbeEvent>,
}

impl Link for PerfLink {
    type Id = PerfLinkId;

    fn id(&self) -> Self::Id {
        PerfLinkId(self.perf_fd.as_raw_fd())
    }

    fn detach(self) -> Result<(), ProgramError> {
        let Self { perf_fd, event } = self;
        let _unused: io::Result<()> =
            perf_event_ioctl(perf_fd.as_fd(), PerfEventIoctlRequest::Disable);
        // HRABNAZ-PATCH(3): 见 vendor/aya/PATCHES.md
        // 必须先关 perf fd 再删 tracefs 条目。<4.17 的内核
        // （走 debugfs 建条目的路径）在条目仍被 perf event 引用时返回 EBUSY
        // ——实测 3.10 上写成 "-:kprobes/<tag>" 报 "设备或资源忙"，删除静默失败，
        // 每次退出都留一批 aya_<pid>_* 条目。
        drop(perf_fd);
        if let Some(event) = event {
            let _unused: Result<(), ProgramError> = event.detach();
        }

        Ok(())
    }
}

id_as_key!(PerfLink, PerfLinkId);

pub(crate) fn perf_attach(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    cookie: Option<u64>,
) -> Result<PerfLinkInner, ProgramError> {
    if cookie.is_some() && (!is_bpf_cookie_supported() || !FEATURES.bpf_perf_link()) {
        return Err(ProgramError::AttachCookieNotSupported);
    }
    // HRABNAZ-PATCH(4): 见 vendor/aya/PATCHES.md
    // 强制走老式 PERF_EVENT_IOC_SET_BPF，绕过 bpf(BPF_LINK_CREATE)。
    // 背景是在5.15 KVM上调试modern tier时曾观察到LINK_CREATE路径异常，统一改用
    // SET_BPF后3.10(nobtf C loader)/5.15(modern aya)两路均验证稳定。cookie依赖
    // bpf_perf_link，禁用link_create则cookie不可用（当前探针不使用cookie）。
    let _ = cookie;
    perf_attach_either(prog_fd, perf_fd, None)
}

pub(crate) fn perf_attach_debugfs(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    event: ProbeEvent,
) -> Result<PerfLinkInner, ProgramError> {
    perf_attach_either(prog_fd, perf_fd, Some(event))
}

fn perf_attach_either(
    prog_fd: BorrowedFd<'_>,
    perf_fd: crate::MockableFd,
    mut event: Option<ProbeEvent>,
) -> Result<PerfLinkInner, ProgramError> {
    perf_event_ioctl(perf_fd.as_fd(), PerfEventIoctlRequest::SetBpf(prog_fd)).map_err(
        |io_error| SyscallError {
            call: "PERF_EVENT_IOC_SET_BPF",
            io_error,
        },
    )?;
    perf_event_ioctl(perf_fd.as_fd(), PerfEventIoctlRequest::Enable).map_err(|io_error| {
        SyscallError {
            call: "PERF_EVENT_IOC_ENABLE",
            io_error,
        }
    })?;

    // HRABNAZ-PATCH(5): 见 vendor/aya/PATCHES.md
    // 不再 disarm。上游在这里关掉 ProbeEvent 的 RAII 守卫，条目在
    // PerfLink 存活期不会被误删，但 PerfLink 没有 Drop 实现，条目就再没人删——
    // <4.17 的 debugfs 路径（3.10 等老内核）上每次启动都往 kprobe_events 留一批
    // aya_<pid>_* 残留。保持守卫有效即可：PerfLink drop 时先关 perf 事件
    // （perf_fd 字段声明在前）再删条目，顺序正确。
    Ok(PerfLinkInner::PerfLink(PerfLink { perf_fd, event }))
}

//! 系统调用边界的单一收拢模块（H-4 unsafe 收敛至零）。
//!
//! 全部 libc FFI 通过 nix 的安全封装表达，本模块与业务代码中**零 unsafe**：
//! FFI 的 unsafe 收敛进 nix 库内部（其承诺封装层安全），仓库内审计面只剩
//! "这里调了哪个系统调用"。签名全部使用安全类型，错误以 Result/bool 表达。
//!
//! 注：本模块居于 ks-core，CLI 与引擎两侧的进程工具（setrlimit/geteuid/
//! fcntl 锁/kill/单调钟）共用同一实现，全仓库运行时 unsafe 为 0。
//!
//! 单调时钟不用 /proc/uptime 口径（boottime 含 suspend，会话挂起后 TTL 会
//! 变长），与内核 `bpf_ktime_get_ns()` 同为 CLOCK_MONOTONIC。

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

/// memlock 无上限（eBPF map 创建需要；失败仅告警，systemd 由 LimitMEMLOCK 覆盖）
#[cfg(target_os = "linux")]
pub fn set_memlock_unlimited() -> Result<(), std::io::Error> {
    use nix::sys::resource::{setrlimit, Resource, RLIM_INFINITY};
    setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY).map_err(std::io::Error::from)
}

/// 当前 euid 是否 root
#[cfg(target_os = "linux")]
pub fn is_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// 非阻塞文件锁（F_SETLK WRLCK）：单实例锁的内核原语。
/// 返回 Err(WouldBlock) 表示锁被占用
#[cfg(target_os = "linux")]
pub fn try_lock_file<F: std::os::fd::AsFd>(fd: &F) -> Result<(), std::io::Error> {
    use nix::fcntl::{fcntl, FcntlArg};
    let fl = nix::libc::flock {
        l_type: nix::libc::F_WRLCK as _,
        l_whence: nix::libc::SEEK_SET as _,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    fcntl(fd, FcntlArg::F_SETLK(&fl))
        .map(|_| ())
        .map_err(std::io::Error::from)
}

/// 与 `bpf_ktime_get_ns()` 同源的 CLOCK_MONOTONIC 纳秒。
#[cfg(target_os = "linux")]
pub fn monotonic_now_ns() -> u64 {
    match nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC) {
        Ok(ts) => {
            let d = std::time::Duration::from(ts);
            d.as_secs().saturating_mul(1_000_000_000) + u64::from(d.subsec_nanos())
        }
        Err(_) => 0,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn monotonic_now_ns() -> u64 {
    0
}

/// SIGKILL。ESRCH（进程已死）视为成功：裁决已达成，等 LRU/TTL 清条目。
/// 显式匹配 Errno::ESRCH —— std 的 ErrorKind 对 ESRCH 是 Uncategorized 而非
/// NotFound，按 kind 判会漏掉这一支。
#[cfg(target_os = "linux")]
pub fn kill_sigkill(pid: u32) -> bool {
    matches!(
        kill(Pid::from_raw(pid as i32), Signal::SIGKILL),
        Ok(()) | Err(Errno::ESRCH)
    )
}

#[cfg(not(target_os = "linux"))]
pub fn kill_sigkill(_pid: u32) -> bool {
    false
}

/// SIGTERM（优雅退出请求；对端是否处理由其自身信号处理决定）
#[cfg(target_os = "linux")]
pub fn kill_sigterm(pid: u32) {
    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
}

#[cfg(not(target_os = "linux"))]
pub fn kill_sigterm(_pid: u32) {}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// ESRCH（进程不存在）必须计为成功：旧实现按 std ErrorKind::NotFound 判，
    /// 但 ESRCH 映射到 Uncategorized，那支从未生效——这里钉死新语义。
    /// 用 status() 已 wait 回收的子进程 PID：确定不存在（不选固定小 PID，
    /// 现代内核的 kworker 等占着 2/3/4 且非 root 下返回 EPERM 而非 ESRCH）。
    #[test]
    fn kill_sigkill_treats_esrch_as_success() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id();
        child.wait().expect("wait 回收子进程");
        // wait 之后该 pid 已消亡，kill 返回 ESRCH
        assert!(kill_sigkill(pid));
    }

    #[test]
    fn kill_sigterm_on_dead_pid_does_not_panic() {
        kill_sigterm(4);
    }

    #[test]
    fn monotonic_now_ns_positive_and_monotonic() {
        let a = monotonic_now_ns();
        let b = monotonic_now_ns();
        assert!(a > 0);
        assert!(b >= a);
    }

    #[test]
    fn is_root_returns_sane_value() {
        // 不关心真假，只关心调用本身安全可用
        let _ = is_root();
    }
}

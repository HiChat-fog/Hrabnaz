//! 单例锁:防止两个ks实例同时attach eBPF重复采集。
//!
//! 用fcntl独占锁锁定一个文件(优先/run/ks.lock,无权限回退/tmp/ks.lock)。
//! 持有File到run结束即释放,无需显式解锁。

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;

/// 申请单例锁。已存在运行实例返回Err(含提示),拿到锁返回Ok(File)(需持有到退出)。
pub fn acquire() -> io::Result<File> {
    let candidates = ["/run/ks.lock", "/tmp/ks.lock"];
    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "无可用锁文件路径");

    for path in &candidates {
        let f = match OpenOptions::new().create(true).read(true).write(true).truncate(true).open(path) {
            Ok(f) => f,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        //非阻塞独占锁。 flock 语义在Linux下fcntl F_SETLK是进程级记录锁
        let ret = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_SETLK, &libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        }) };
        if ret == 0 {
            //写入当前pid便于排查
            use std::io::Write;
            let _ = (&f).write_all(format!("{}\n", std::process::id()).as_bytes());
            return Ok(f);
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(libc::EACCES) || e.raw_os_error() == Some(libc::EAGAIN) {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("ks已在运行(锁文件{}被占用),拒绝重复启动", path),
            ));
        }
        last_err = e;
    }
    Err(last_err)
}

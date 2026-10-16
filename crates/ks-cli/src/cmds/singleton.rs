use std::fs::{File, OpenOptions};
use std::io;

pub fn acquire() -> io::Result<File> {
    let candidates = ["/run/ks.lock", "/tmp/ks.lock"];
    let mut last_err = io::Error::new(io::ErrorKind::NotFound, "无可用锁文件路径");

    for path in &candidates {
        // 先加锁再截断（截断发生在下方锁成功之后），这里显式 truncate(false)
        let f = match OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
        {
            Ok(f) => f,
            Err(e) => {
                last_err = e;
                continue;
            }
        };
        if ks_engine::sys::try_lock_file(&f).is_ok() {
            use std::io::{Seek, Write};
            let mut f = f;
            let _ = f.seek(std::io::SeekFrom::Start(0));
            let _ = f.set_len(0);
            let _ = f.write_all(format!("{}\n", std::process::id()).as_bytes());
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

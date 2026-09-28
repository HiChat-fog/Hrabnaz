pub mod ui;
pub mod baseline;
pub mod correlation;
pub mod replay;
pub mod singleton;
pub mod start;
pub mod status;
pub mod stop;
pub mod watch;

/// 运行时状态文件路径（start 写 / status 读 / stop 读后 kill）。
/// root 时放 /run/kernelsentinel/（root-only 目录，防本地用户伪造/symlink 后诱导 stop 杀任意进程），
/// 非 root 回退 /tmp。三处共用此 helper，避免路径漂移
pub fn status_file_path() -> std::path::PathBuf {
    #[cfg(target_os = "linux")]
    {
        let is_root = unsafe { libc::geteuid() } == 0;
        if is_root {
            let run_dir = std::path::Path::new("/run/kernelsentinel");
            if std::fs::create_dir_all(run_dir).is_ok() {
                // 目录收紧为 0700，普通用户不可读写
                let _ = std::fs::set_permissions(run_dir, {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::Permissions::from_mode(0o700)
                });
                return run_dir.join("ks-status.json");
            }
        }
        std::path::PathBuf::from("/tmp/ks-status.json")
    }
    #[cfg(not(target_os = "linux"))]
    {
        std::path::PathBuf::from("./ks-status.json")
    }
}

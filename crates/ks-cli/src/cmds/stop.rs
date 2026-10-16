use anyhow::Result;
use colored::Colorize;
use super::ui::{banner, step};

/// kill 前校验目标进程身份：读 /proc/<pid>/ 的 comm 与 exe，
/// 防 PID 复用或伪造的状态文件把 SIGTERM 发给无关进程。
/// watchdog 子命令复用同一判定（非 Linux 平台恒 false）
pub fn verify_ks_process(pid: u32) -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        false
    }
    #[cfg(target_os = "linux")]
    {
        verify_ks_process_linux(pid)
    }
}

#[cfg(target_os = "linux")]
fn verify_ks_process_linux(pid: u32) -> bool {
    use std::fs;
    let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if comm != "kernelsentinel" && !comm.starts_with("kernelsentinel") {
        return false;
    }
    // exe 必须能解析且名称一致（排除已被 exec 掉的复用 pid）
    match fs::read_link(format!("/proc/{}/exe", pid)) {
        Ok(exe) => exe
            .file_name()
            .map(|n| n.to_string_lossy().starts_with("kernelsentinel"))
            .unwrap_or(false),
        Err(_) => false,
    }
}

pub async fn run() -> Result<()> {
    println!("{}", "正在安全关闭内核哨兵...".cyan().bold());
    println!();

    step(1, 3, "查找运行实例");

    let status_path = super::status_file_path();
    if status_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&status_path) {
            if let Ok(status) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(pid) = status.get("pid").and_then(|v| v.as_u64()) {
                    println!("      找到运行实例 PID: {}", pid.to_string().green().bold());

                    #[cfg(target_os = "linux")]
                    {
                        let pid = pid as u32;
                        if verify_ks_process(pid) {
                            ks_engine::sys::kill_sigterm(pid);
                            println!("      已发送 SIGTERM 信号");
                            banner("内核哨兵正在安全关闭");
                        } else {
                            println!(
                                "      {} PID {} 的 /proc 身份不是 kernelsentinel，拒绝 kill（状态文件可能是伪造/过期）",
                                "[WARN]".yellow(),
                                pid
                            );
                            println!("      如需强制清理请手动: kill {} ", pid);
                        }
                    }

                    #[cfg(not(target_os = "linux"))]
                    {
                        let _ = pid;
                        println!("      {} 非 Linux 环境，无法发送 SIGTERM", "[MOCK]".yellow());
                        println!("      提示: 请在运行实例窗口按 Ctrl+C 停止");
                        banner("请手动停止运行实例 (Ctrl+C)");
                    }

                    let _ = std::fs::remove_file(&status_path);
                    return Ok(());
                }
                println!("      {} 状态文件格式异常 (缺少 pid 字段)", "[WARN]".yellow());
            } else {
                println!("      {} 状态文件 JSON 解析失败", "[WARN]".yellow());
            }
        } else {
            println!("      {} 无法读取状态文件", "[WARN]".yellow());
        }
    }

    println!("      {} 未找到运行实例", "[WARN]".yellow());
    println!("      提示: 可能未启动或已通过 Ctrl+C 关闭");
    println!("      状态文件路径: {}", status_path.display());

    println!();
    banner("内核哨兵停止命令完成");
    println!("  取证日志已保存，可用 'replay' 命令回放");

    Ok(())
}

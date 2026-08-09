use anyhow::Result;
use std::path::Path;
use colored::Colorize;
use super::ui::{banner, step};

#[cfg(target_os = "linux")]
const STATUS_FILE: &str = "/tmp/ks-status.json";
#[cfg(not(target_os = "linux"))]
const STATUS_FILE: &str = "./ks-status.json";

pub async fn run() -> Result<()> {
    println!("{}", "正在安全关闭内核哨兵...".cyan().bold());
    println!();

    step(1, 3, "查找运行实例");

    let status_path = Path::new(STATUS_FILE);
    if status_path.exists() {
        if let Ok(content) = std::fs::read_to_string(status_path) {
            if let Ok(status) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(pid) = status.get("pid").and_then(|v| v.as_u64()) {
                    println!("      找到运行实例 PID: {}", pid.to_string().green().bold());

                    #[cfg(target_os = "linux")]
                    {
                        unsafe {
                            libc::kill(pid as i32, libc::SIGTERM);
                        }
                        println!("      已发送 SIGTERM 信号");
                        banner("内核哨兵正在安全关闭");
                    }

                    #[cfg(not(target_os = "linux"))]
                    {
                        println!("      {} 非 Linux 环境，无法发送 SIGTERM", "[MOCK]".yellow());
                        println!("      提示: 请在运行实例窗口按 Ctrl+C 停止");
                        banner("请手动停止运行实例 (Ctrl+C)");
                    }

                    let _ = std::fs::remove_file(status_path);
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
    println!("      状态文件路径: {}", STATUS_FILE);

    println!();
    banner("内核哨兵停止命令完成");
    println!("  取证日志已保存，可用 'replay' 命令回放");

    Ok(())
}

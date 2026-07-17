use anyhow::Result;
use std::path::Path;

#[cfg(target_os = "linux")]
const STATUS_FILE: &str = "/tmp/ks-status.json";
#[cfg(not(target_os = "linux"))]
const STATUS_FILE: &str = "./ks-status.json";

pub async fn run() -> Result<()> {
    println!("正在安全关闭内核哨兵...");
    println!();

    println!("[1/3] 查找运行实例...");

    let status_path = Path::new(STATUS_FILE);
    if status_path.exists() {
        if let Ok(content) = std::fs::read_to_string(status_path) {
            if let Ok(status) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(pid) = status.get("pid").and_then(|v| v.as_u64()) {
                    println!("      找到运行实例 PID: {}", pid);

                    #[cfg(target_os = "linux")]
                    {
                        unsafe {
                            libc::kill(pid as i32, libc::SIGTERM);
                        }
                        println!("      已发送 SIGTERM 信号");
                        println!();
                        println!("========================================");
                        println!(" 内核哨兵正在安全关闭...");
                        println!("========================================");
                    }

                    #[cfg(not(target_os = "linux"))]
                    {
                        println!("      [MOCK] 非 Linux 环境，无法发送 SIGTERM");
                        println!("      提示: 请在运行实例窗口按 Ctrl+C 停止");
                        println!();
                        println!("========================================");
                        println!(" 请手动停止运行实例 (Ctrl+C)");
                        println!("========================================");
                    }

                    let _ = std::fs::remove_file(status_path);
                    return Ok(());
                }
                println!("      [WARN] 状态文件格式异常 (缺少 pid 字段)");
            } else {
                println!("      [WARN] 状态文件 JSON 解析失败");
            }
        } else {
            println!("      [WARN] 无法读取状态文件");
        }
    }

    println!("      [WARN] 未找到运行实例");
    println!("      提示: 可能未启动或已通过 Ctrl+C 关闭");
    println!("      状态文件路径: {}", STATUS_FILE);

    println!();
    println!("========================================");
    println!(" 内核哨兵停止命令完成");
    println!("========================================");
    println!();
    println!("提示: 取证日志已保存，可用 'replay' 命令回放");

    Ok(())
}

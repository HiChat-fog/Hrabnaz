use anyhow::Result;
use colored::Colorize;
use super::ui::banner;

/// serve子命令为CLI-first声明,不启动Web服务。
///
/// CLI-first:检测与运维均通过CLI子命令完成,REST API仅作可选demo
/// (通过start --serve <port>与eBPF检测同进程启用),不绑定端口。
pub async fn run(port: u16) -> Result<()> {
    banner("内核哨兵 — CLI-first 模式（不启动 Web 服务）");
    println!();
    println!("内核哨兵以 CLI-first 交付：检测与运维均通过 CLI 子命令完成。");
    println!();
    println!("  {} kernelsentinel start", "检测主入口:".dimmed());
    println!("  {} kernelsentinel status [--watch]", "状态查看:".dimmed());
    println!("  {} kernelsentinel replay <file>", "取证回放:".dimmed());
    println!("  {} kernelsentinel baseline", "基线偏离:".dimmed());
    println!("  {} kernelsentinel correlation", "关联告警:".dimmed());
    println!("  {} kernelsentinel watch", "实时告警流:".dimmed());
    println!();
    println!("REST API 为可选 demo（不作为 serve 主入口，按申报书要求未绑定端口）:");
    println!("  启用方式: kernelsentinel start --serve {}", port);
    println!();
    Ok(())
}

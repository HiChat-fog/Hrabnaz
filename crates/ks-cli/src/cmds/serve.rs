use anyhow::Result;

/// 申报书line 51: `serve` 子命令为CLI-first声明，不启动Web服务。
///
/// CLI-first：检测与运维均通过CLI子命令完成，REST API仅作可选demo
/// （通过 `start --serve <port>` 与eBPF检测同进程启用），不绑定端口。
pub async fn run(port: u16) -> Result<()> {
    println!("╔══════════════════════════════════════════╗");
    println!("║  内核哨兵 — CLI-first 模式（不启动 Web 服务） ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("内核哨兵以 CLI-first 交付：检测与运维均通过 CLI 子命令完成。");
    println!();
    println!("  检测主入口:  kernelsentinel start");
    println!("  状态查看:    kernelsentinel status [--watch]");
    println!("  取证回放:    kernelsentinel replay <file>");
    println!("  基线偏离:    kernelsentinel baseline");
    println!("  关联告警:    kernelsentinel correlation");
    println!("  实时告警流:  kernelsentinel watch");
    println!();
    println!("REST API 为可选 demo（不作为 serve 主入口，按申报书要求未绑定端口）:");
    println!("  启用方式:    kernelsentinel start --serve {}", port);
    println!();
    Ok(())
}

use anyhow::Result;

pub async fn run(port: u16) -> Result<()> {
    println!("╔══════════════════════════════════════════╗");
    println!("║  内核哨兵 — 数据服务模式                   ║");
    println!("╚══════════════════════════════════════════╝");
    println!();
    println!("端口配置: localhost:{}", port);
    println!();
    println!("── 设计决策: CLI-first ──");
    println!();
    println!("  内核哨兵不提供 Web 大屏可视化界面。");
    println!("  原因:");
    println!("    1. 核心价值 = eBPF 内核探针 + 哈希链取证, 不在数据展示");
    println!("    2. 大屏会流于通用安全分析形态, 遮蔽内核级检测的独特创新");
    println!("    3. CLI 与内核安全运维场景天然匹配");
    println!("    4. replay 命令已提供攻击链可视化 + 哈希链校验");
    println!();
    println!("── 数据服务 (API) 扩展方向 ──");
    println!();
    println!("  当开发机到位后, 将实现 ks-server crate:");
    println!("    REST API:   7 个分组, 20+ 端点 (见 docs/api-design.md)");
    println!("    WebSocket:  实时告警推送 (供 SIEM/SOAR 消费)");
    println!("    认证:       JWT (Admin/Analyst/Viewer 三级权限)");
    println!("    目标:       不做独立前端, 而是做 API 数据源");
    println!("                接入已有安全平台 (Security Onion, Wazuh, etc.)");
    println!();
    println!("── 当前可用命令 ──");
    println!();
    println!("  kernelsentinel start       → 启动探针 + 实时告警输出");
    println!("  kernelsentinel replay <file> → 取证回放 (8 阶段分析)");
    println!("  kernelsentinel status       → 系统状态 (探针 + Map + 配置)");

    Ok(())
}
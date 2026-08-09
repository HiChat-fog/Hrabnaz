//! CLI 渲染工具集中放此处,各子命令复用,避免手写 ASCII 与颜色逻辑散落。
//!
//! 申报书第51行要求"表格对齐、颜色标注严重性",本模块用 colored 落地颜色,
//! 不引入重 TUI 框架(ratatui),保持 start 滚动日志流场景轻量。
//! 表格对齐由各命令按需用 comfy-table 构造(见 status.rs)。

use colored::*;
use comfy_table::{ContentArrangement, Table};

use ks_core::rule::Severity;

/// 按严重性上色文本(申报书第51行:颜色标注严重性)。
/// critical=红 high=橙黄 medium=黄 low=绿。
pub fn severity_colored(text: &str, sev: &str) -> ColoredString {
    match sev {
        "critical" => text.red().bold(),
        "high" => text.yellow(),
        "medium" => text.truecolor(204, 153, 0),
        "low" => text.green(),
        _ => text.normal(),
    }
}

/// 按 Severity 枚举上色,用于 ks-core::alert::Alert 直接来自引擎的场景。
pub fn severity_badge(s: &Severity) -> ColoredString {
    let label = match s {
        Severity::Critical => "● CRITICAL",
        Severity::High => "● HIGH",
        Severity::Medium => "● MEDIUM",
        Severity::Low => "● LOW",
    };
    match s {
        Severity::Critical => label.red().bold(),
        Severity::High => label.yellow(),
        Severity::Medium => label.truecolor(204, 153, 0),
        Severity::Low => label.green(),
    }
}

/// 顶部 banner,替代各命令里反复手写的 ╔═║ 框。
pub fn banner(title: &str) {
    let width = title.chars().map(|c| if c.is_ascii() { 2 } else { 4 }).sum::<usize>() + 6;
    let line = "═".repeat(width);
    println!("{}{}{}", "╔".cyan().bold(), line, "╗".cyan().bold());
    println!("{}  {}  {}", "║".cyan().bold(), title.cyan().bold(), "║".cyan().bold());
    println!("{}{}{}", "╚".cyan().bold(), line, "╝".cyan().bold());
}

/// 构造一个 UTF8 边框 comfy-table(申报书第51行:表格对齐)。
pub fn new_table() -> Table {
    let mut t = Table::new();
    t.set_content_arrangement(ContentArrangement::Disabled)
        .load_style(comfy_table::presets::UTF8_FULL);
    t
}

/// 启动步骤标签,统一进度行风格:start 的 [1/6]...[6/6]。
pub fn step(n: usize, total: usize, text: &str) {
    println!("{} {}", format!("[{}/{}]", n, total).cyan().bold(), text.bold());
}

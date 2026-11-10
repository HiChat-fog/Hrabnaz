use colored::*;
use comfy_table::{ContentArrangement, Table};

use hrabnaz_core::rule::Severity;

pub fn severity_colored(text: &str, sev: &str) -> ColoredString {
    match sev {
        "critical" => text.red().bold(),
        "high" => text.yellow(),
        "medium" => text.truecolor(204, 153, 0),
        "low" => text.green(),
        _ => text.normal(),
    }
}

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

/// 终端显示宽度：CJK/全角/韩文/常见 emoji 占两列，ASCII 与普通标点占一列。
/// 只用于画 banner 边框，不追求完整 Unicode 字素簇支持。
fn display_width(text: &str) -> usize {
    text.chars()
        .map(|c| match c as u32 {
            0x1100..=0x115F
            | 0x2E80..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE10..=0xFE19
            | 0xFE30..=0xFE6F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x1F300..=0x1FAFF
            | 0x20000..=0x3FFFD => 2,
            _ => 1,
        })
        .sum()
}

pub fn banner(title: &str) {
    // 标题两侧各留两个空格，边框长度必须等于标题显示宽度 + 4，否则右边框会错位
    let line = "═".repeat(display_width(title) + 4);
    println!("{}{}{}", "╔".cyan().bold(), line, "╗".cyan().bold());
    println!(
        "{}  {}  {}",
        "║".cyan().bold(),
        title.cyan().bold(),
        "║".cyan().bold()
    );
    println!("{}{}{}", "╚".cyan().bold(), line, "╝".cyan().bold());
}

pub fn new_table() -> Table {
    let mut t = Table::new();
    t.set_content_arrangement(ContentArrangement::Disabled)
        .load_style(comfy_table::presets::UTF8_FULL);
    t
}

pub fn step(n: usize, total: usize, text: &str) {
    println!(
        "{} {}",
        format!("[{}/{}]", n, total).cyan().bold(),
        text.bold()
    );
}

#[cfg(test)]
mod tests {
    use super::display_width;

    #[test]
    fn display_width_counts_wide_chars_as_two_columns() {
        assert_eq!(display_width("abc"), 3);
        assert_eq!(display_width("实时告警"), 8);
        assert_eq!(display_width("—"), 1, "em dash 是单列标点，不能按双列算");
        assert_eq!(display_width("A 实时 1s"), 1 + 1 + 4 + 1 + 2);
    }
}

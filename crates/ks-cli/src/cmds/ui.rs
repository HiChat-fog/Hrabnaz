use colored::*;
use comfy_table::{ContentArrangement, Table};

use ks_core::rule::Severity;

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

pub fn banner(title: &str) {
    let width = title.chars().map(|c| if c.is_ascii() { 2 } else { 4 }).sum::<usize>() + 6;
    let line = "═".repeat(width);
    println!("{}{}{}", "╔".cyan().bold(), line, "╗".cyan().bold());
    println!("{}  {}  {}", "║".cyan().bold(), title.cyan().bold(), "║".cyan().bold());
    println!("{}{}{}", "╚".cyan().bold(), line, "╝".cyan().bold());
}

pub fn new_table() -> Table {
    let mut t = Table::new();
    t.set_content_arrangement(ContentArrangement::Disabled)
        .load_style(comfy_table::presets::UTF8_FULL);
    t
}

pub fn step(n: usize, total: usize, text: &str) {
    println!("{} {}", format!("[{}/{}]", n, total).cyan().bold(), text.bold());
}

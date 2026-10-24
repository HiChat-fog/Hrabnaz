use anyhow::Result;
use chrono::TimeZone;
use ks_core::alert::Alert;
use ks_core::rule::Severity;
use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::time::Duration;

use super::ui::{banner, severity_badge};
use colored::Colorize;

/// seen 集合上限：只增不减的 HashSet 在长跑 watch 里会缓慢膨胀
const SEEN_CAP: usize = 10000;
/// 启动时回显日志中已有的最近 N 条告警（对齐旧版轮询 limit=20 的首屏行为）
const SEED_LIMIT: usize = 20;

/// 跟踪中的日志文件：路径 + 已消费偏移 + 文件身份（dev/ino）。
/// 轮转会 rename 旧文件并在**同一路径**新建文件——路径不变但 inode 变了，
/// 只看路径会把旧 offset 用到新文件上（新文件更小 → 永远读不到新告警）。
struct Tracked {
    path: PathBuf,
    offset: u64,
    dev: u64,
    ino: u64,
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum MinSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl MinSeverity {
    fn rank(self) -> u8 {
        match self {
            MinSeverity::Low => 0,
            MinSeverity::Medium => 1,
            MinSeverity::High => 2,
            MinSeverity::Critical => 3,
        }
    }

    fn accepts(self, sev: &Severity) -> bool {
        severity_rank(sev) >= self.rank()
    }
}

fn severity_rank(sev: &Severity) -> u8 {
    match sev {
        Severity::Low => 0,
        Severity::Medium => 1,
        Severity::High => 2,
        Severity::Critical => 3,
    }
}

#[derive(clap::Args, Debug)]
pub struct WatchArgs {
    /// 取证日志目录（start --log-dir 的值，events_*.jsonl 所在处）
    #[arg(short, long, default_value = "/var/log/ks")]
    pub log_dir: String,
    /// 轮询间隔（秒，≥1）
    #[arg(short, long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..))]
    pub interval: u64,
    /// follow 下新告警累计 N 条后停止；--no-follow 下最多输出 N 条（0 = 不限）
    #[arg(long, default_value_t = 0)]
    pub max: usize,
    /// 输出 JSONL（一行一个告警对象；follow 时不回显历史）
    #[arg(long, default_value_t = false)]
    pub json: bool,
    /// 显式跟随（默认行为；保留该 flag 便于脚本自描述）
    #[arg(long, default_value_t = false)]
    pub follow: bool,
    /// 读取当前已有告警后退出，不进入 tail
    #[arg(long = "no-follow", default_value_t = false, conflicts_with = "follow")]
    pub no_follow: bool,
    /// 只显示规则名匹配的告警（glob，可重复，多次为 OR）
    #[arg(long = "rule", value_name = "GLOB")]
    pub rules: Vec<String>,
    /// 只显示进程名匹配的告警（glob，可重复，多次为 OR）
    #[arg(long = "comm", value_name = "GLOB")]
    pub comms: Vec<String>,
    /// 最低严重级别
    #[arg(long, value_enum)]
    pub severity: Option<MinSeverity>,
    /// 只显示指定 PID 的告警（可重复，多次为 OR）
    #[arg(long = "pid", value_name = "PID")]
    pub pids: Vec<u32>,
    /// 只显示文件路径包含该子串的告警（可重复，多次为 OR）
    #[arg(long = "file", value_name = "SUBSTR")]
    pub files: Vec<String>,
}

/// 告警过滤：同一 flag 多次出现为 OR，不同 flag 之间为 AND。
struct WatchFilter {
    rules: Vec<String>,
    comms: Vec<String>,
    severity: Option<MinSeverity>,
    pids: HashSet<u32>,
    files: Vec<String>,
}

impl WatchFilter {
    fn new(args: &WatchArgs) -> Self {
        Self {
            rules: args.rules.clone(),
            comms: args.comms.clone(),
            severity: args.severity,
            pids: args.pids.iter().copied().collect(),
            files: args.files.clone(),
        }
    }

    fn is_empty(&self) -> bool {
        self.rules.is_empty()
            && self.comms.is_empty()
            && self.severity.is_none()
            && self.pids.is_empty()
            && self.files.is_empty()
    }

    fn describe(&self) -> String {
        let mut parts = Vec::new();
        if !self.rules.is_empty() {
            parts.push(format!("rule={}", self.rules.join("|")));
        }
        if !self.comms.is_empty() {
            parts.push(format!("comm={}", self.comms.join("|")));
        }
        if let Some(s) = self.severity {
            parts.push(format!("severity>={s:?}").to_lowercase());
        }
        if !self.pids.is_empty() {
            let mut pids: Vec<u32> = self.pids.iter().copied().collect();
            pids.sort_unstable();
            let pids: Vec<String> = pids.iter().map(ToString::to_string).collect();
            parts.push(format!("pid={}", pids.join("|")));
        }
        if !self.files.is_empty() {
            parts.push(format!("file={}", self.files.join("|")));
        }
        parts.join(" ")
    }

    fn matches(&self, a: &Alert) -> bool {
        let rule_ok = self.rules.is_empty()
            || self
                .rules
                .iter()
                .any(|p| glob_match(p, a.rule_name.as_str()));
        let comm_ok = self.comms.is_empty()
            || self
                .comms
                .iter()
                .any(|p| glob_match(p, a.process.comm.as_str()));
        let sev_ok = self.severity.is_none_or(|min| min.accepts(&a.severity));
        let pid_ok = self.pids.is_empty() || self.pids.contains(&a.process.pid);
        let file_ok = self.files.is_empty()
            || a.file
                .as_ref()
                .is_some_and(|f| self.files.iter().any(|s| f.path.contains(s.as_str())));
        rule_ok && comm_ok && sev_ok && pid_ok && file_ok
    }
}

/// 只支持 `*`（任意串）和 `?`（任意单字符），大小写敏感。
/// 用回溯法，避免为两个通配符引入 glob 依赖。
fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut mark = 0usize;
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if let Some(sp) = star {
            pi = sp + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// 活跃取证文件固定为 events_YYYYMMDD.jsonl。归档 events_YYYYMMDD_HHMMSS.jsonl
/// 在 ASCII 上排在同日活跃文件之后（'_' 0x5F > '.' 0x2E），旧实现"按名字排序取
/// 最大"会在轮转→压缩窗口（压缩被跳过/失败时甚至是永久）把归档当成最新文件，
/// 导致 watch 停报。
fn is_active_log_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("events_") else {
        return false;
    };
    let Some(date) = rest.strip_suffix(".jsonl") else {
        return false;
    };
    date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit())
}

/// 目录里最新的活跃文件（文件名带日期，排序即时间序；归档与压缩文件不参与）
fn latest_log(dir: &str) -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(is_active_log_name)
        })
        .collect();
    candidates.sort();
    candidates.pop()
}

fn print_alert(a: &Alert) {
    let mitre = a
        .mitre
        .as_ref()
        .map(|m| format!(" | MITRE {}/{}", m.tactic, m.technique))
        .unwrap_or_default();
    // 告警 timestamp_ns 是单调时钟；有 btime 时换回墙钟，避免历史告警显示成当前时间
    let ts = ks_core::time::epoch_ms_from_monotonic_ns(a.timestamp_ns)
        .and_then(|ms| chrono::Local.timestamp_millis_opt(ms).single())
        .unwrap_or_else(chrono::Local::now)
        .format("%H:%M:%S")
        .to_string();
    println!(
        "  {} {} {} — PID {}{}",
        ts.dimmed(),
        severity_badge(&a.severity),
        a.title.bold(),
        a.process.pid,
        mitre.dimmed()
    );
}

/// 从一行 JSON 解析告警：子串预筛避免全量 JSON parse，剥离 forensic 附加字段后再反序列化
fn parse_alert_line(line: &str) -> Option<Alert> {
    if !line.contains("\"type\":\"alert\"") {
        return None;
    }
    let mut v: serde_json::Value = serde_json::from_str(line).ok()?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("type");
        obj.remove("prev_hash");
        obj.remove("hash");
    }
    serde_json::from_value(v).ok()
}

/// 自 offset 起读完整行，返回 (消费的字节数, 完整行列表)。
/// 半截行（正在写入）不消费，留待下次 tail。
fn read_new_lines(file: &mut File, offset: u64) -> Result<(u64, Vec<String>)> {
    file.seek(SeekFrom::Start(offset))?;
    let mut reader = BufReader::new(file);
    let mut consumed = 0u64;
    let mut lines = Vec::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf)?;
        if n == 0 {
            break;
        }
        if buf.last() != Some(&b'\n') {
            break;
        }
        consumed += n as u64;
        buf.pop();
        lines.push(String::from_utf8_lossy(&buf).into_owned());
    }
    Ok((consumed, lines))
}

pub async fn run(args: &WatchArgs) -> Result<()> {
    let json_mode = args.json;
    let filter = WatchFilter::new(args);
    let follow = !args.no_follow;
    if !json_mode {
        banner(&format!(
            "实时告警监控 — 每 {}s 轮询取证日志",
            args.interval
        ));
        println!("  日志目录: {}", args.log_dir.dimmed());
        if !filter.is_empty() {
            println!("  过滤:     {}", filter.describe());
        }
        println!(
            "  模式:     {}",
            if follow {
                "follow（Ctrl+C 退出）"
            } else {
                "一次性读取"
            }
        );
        println!();
    }

    let mut seen: HashSet<uuid::Uuid> = HashSet::new();
    let mut seen_order: VecDeque<uuid::Uuid> = VecDeque::new();
    let mut count: usize = 0;
    let mut tracked: Option<Tracked> = None;

    // 启动时流式扫描日志：只保留最近 N 条告警用于回显 + 全量 id 进 seen（防 tail 重复），
    // 不整文件驻留内存（长跑日志可达百 MB 级）
    let mut matched_seed = 0usize;
    if let Some(path) = latest_log(&args.log_dir) {
        let mut total = 0usize;
        let mut recent: VecDeque<Alert> = VecDeque::new();
        let mut end_offset = 0u64;
        if let Ok(mut file) = File::open(&path) {
            let mut reader = BufReader::new(&mut file);
            let mut line = String::new();
            'seed: loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        end_offset += n as u64;
                        if let Some(a) = parse_alert_line(line.trim_end_matches(['\n', '\r'])) {
                            total += 1;
                            if seen.insert(a.id) {
                                seen_order.push_back(a.id);
                                if seen_order.len() > SEEN_CAP {
                                    if let Some(old) = seen_order.pop_front() {
                                        seen.remove(&old);
                                    }
                                }
                            }
                            if filter.matches(&a) {
                                if !follow {
                                    if json_mode {
                                        if let Ok(s) = serde_json::to_string(&a) {
                                            println!("{s}");
                                        }
                                    } else {
                                        print_alert(&a);
                                    }
                                    matched_seed += 1;
                                    if args.max > 0 && matched_seed >= args.max {
                                        break 'seed;
                                    }
                                } else if !json_mode {
                                    if recent.len() == SEED_LIMIT {
                                        recent.pop_front();
                                    }
                                    recent.push_back(a);
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(meta) = file.metadata() {
                tracked = Some(Tracked {
                    path: path.clone(),
                    offset: end_offset,
                    dev: meta.dev(),
                    ino: meta.ino(),
                });
            }
        }
        if !follow {
            if !json_mode {
                println!();
                println!("共输出 {} 条匹配告警（未进入 follow）", matched_seed);
            }
            return Ok(());
        }
        if total > 0 && !json_mode {
            println!(
                "  已有 {} 条历史告警，过滤后回显最近 {} 条:",
                total,
                recent.len()
            );
            for a in &recent {
                print_alert(a);
            }
            println!();
        }
    } else {
        if !json_mode {
            println!(
                "  ({} 下暂无 events_*.jsonl — start 产生日志后自动跟上)",
                args.log_dir
            );
        }
        if !follow {
            return Ok(());
        }
    }

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                if !json_mode {
                    println!();
                    println!("停止监控 (共显示 {} 条新告警)", count);
                }
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(args.interval)) => {
                // 换日/换文件：活跃文件路径变化则切过去从头读
                if let Some(latest) = latest_log(&args.log_dir) {
                    let need_reset = match &tracked {
                        Some(t) => t.path != latest,
                        None => true,
                    };
                    if need_reset {
                        tracked = Some(Tracked {
                            path: latest,
                            offset: 0,
                            dev: 0,
                            ino: 0,
                        });
                    }
                }
                let Some(tr) = tracked.as_mut() else {
                    continue;
                };
                let Ok(mut file) = File::open(&tr.path) else {
                    continue;
                };
                // 同一路径下文件被轮转替换（inode 变化）或被截断时，旧 offset 无意义，
                // 从头重读（告警按 id 去重，已显示过的不会重复）
                if let Ok(meta) = file.metadata() {
                    if tr.ino == 0
                        || meta.dev() != tr.dev
                        || meta.ino() != tr.ino
                        || meta.len() < tr.offset
                    {
                        tr.offset = 0;
                        tr.dev = meta.dev();
                        tr.ino = meta.ino();
                    }
                }
                let (consumed, lines) = match read_new_lines(&mut file, tr.offset) {
                    Ok(r) => r,
                    Err(_) => continue,
                };
                tr.offset += consumed;
                for line in &lines {
                    let Some(a) = parse_alert_line(line) else {
                        continue;
                    };
                    if !seen.insert(a.id) {
                        continue;
                    }
                    seen_order.push_back(a.id);
                    if seen_order.len() > SEEN_CAP {
                        if let Some(old) = seen_order.pop_front() {
                            seen.remove(&old);
                        }
                    }
                    if !filter.matches(&a) {
                        continue;
                    }
                    count += 1;
                    if json_mode {
                        if let Ok(s) = serde_json::to_string(&a) {
                            println!("{s}");
                        }
                    } else {
                        print_alert(&a);
                    }
                    if args.max > 0 && count >= args.max {
                        if !json_mode {
                            println!();
                            println!("已达 --max {} 上限，停止监控", args.max);
                        }
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 只有"当前世代"的活跃文件参与 tail：归档名带 _HHMMSS 后缀，不能匹配
    #[test]
    fn active_log_name_matches_only_current_generation() {
        assert!(is_active_log_name("events_20261016.jsonl"));
        assert!(!is_active_log_name("events_20261016_172533.jsonl"));
        assert!(!is_active_log_name("events_20261016_172533.jsonl.gz"));
        assert!(!is_active_log_name("chain_head.log"));
        assert!(!is_active_log_name("events_short.jsonl"));
        assert!(!is_active_log_name("events_20261016.jsonl.bak"));
    }

    fn alert(rule: &str, comm: &str, severity: Severity, pid: u32, file: Option<&str>) -> Alert {
        let mut a = Alert::new(
            severity,
            0,
            "test".into(),
            rule.into(),
            ks_core::alert::ProcessInfo {
                pid,
                ppid: 1,
                comm: comm.into(),
                uid: 0,
                exe_path: None,
                cmdline: None,
            },
        );
        a.file = file.map(|path| ks_core::alert::FileInfo {
            path: path.into(),
            operation: ks_core::alert::FileOperation::Write,
            bytes: None,
        });
        a
    }

    fn empty_args() -> WatchArgs {
        WatchArgs {
            log_dir: "/nonexistent".into(),
            interval: 1,
            max: 0,
            json: false,
            follow: false,
            no_follow: false,
            rules: Vec::new(),
            comms: Vec::new(),
            severity: None,
            pids: Vec::new(),
            files: Vec::new(),
        }
    }

    #[test]
    fn glob_supports_star_question_and_multibyte_text() {
        assert!(glob_match("", ""));
        assert!(glob_match("*", ""));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(glob_match("a**b", "ab"));
        assert!(glob_match("?", "x"));
        assert!(!glob_match("?", ""));
        assert!(!glob_match("a?c", "abbc"));
        assert!(!glob_match("abc", "abcd"));
        assert!(!glob_match("SSH*", "ssh"), "glob 大小写敏感");
        assert!(glob_match("*勒索*", "检测到勒索软件"), "按字符而非字节匹配");
    }

    #[test]
    fn same_flag_is_or_and_cross_flag_is_and() {
        let mut args = empty_args();
        args.rules = vec!["SSH*".into(), "*Webshell*".into()];
        args.comms = vec!["sshd".into()];
        let f = WatchFilter::new(&args);

        assert!(f.matches(&alert("SSH Brute Force", "sshd", Severity::High, 100, None)));
        assert!(f.matches(&alert("PHP Webshell", "sshd", Severity::High, 100, None)));
        assert!(
            !f.matches(&alert("PHP Webshell", "curl", Severity::High, 100, None)),
            "不同 flag 之间必须是 AND"
        );
        assert!(
            !f.matches(&alert("Other Rule", "sshd", Severity::High, 100, None)),
            "规则不匹配时 comm 再匹配也不能通过"
        );
    }

    #[test]
    fn severity_is_a_floor_pid_is_exact_and_file_requires_event() {
        let mut args = empty_args();
        args.severity = Some(MinSeverity::High);
        args.pids = vec![100, 200];
        args.files = vec!["/etc/shadow".into()];
        let f = WatchFilter::new(&args);

        assert!(f.matches(&alert(
            "r",
            "c",
            Severity::Critical,
            200,
            Some("/etc/shadow")
        )));
        assert!(!f.matches(&alert("r", "c", Severity::Medium, 200, Some("/etc/shadow"))));
        assert!(!f.matches(&alert("r", "c", Severity::High, 300, Some("/etc/shadow"))));
        assert!(!f.matches(&alert("r", "c", Severity::High, 200, Some("/etc/passwd"))));
        assert!(
            !f.matches(&alert("r", "c", Severity::High, 200, None)),
            "--file 不能匹配没有文件上下文的告警"
        );
    }

    #[test]
    fn empty_filter_accepts_everything_and_describes_cleanly() {
        let args = empty_args();
        let f = WatchFilter::new(&args);
        assert!(f.is_empty());
        assert!(f.describe().is_empty());
        assert!(f.matches(&alert("any", "any", Severity::Low, 1, None)));

        let mut args = empty_args();
        args.rules = vec!["SSH*".into()];
        args.comms = vec!["sshd".into()];
        args.severity = Some(MinSeverity::High);
        args.pids = vec![42];
        args.files = vec!["/etc".into()];
        let desc = WatchFilter::new(&args).describe();
        for needle in [
            "rule=SSH*",
            "comm=sshd",
            "severity>=high",
            "pid=42",
            "file=/etc",
        ] {
            assert!(desc.contains(needle), "describe 缺少 {needle}: {desc}");
        }
    }

    #[test]
    fn parse_alert_line_ignores_non_alerts_and_strips_forensic_fields() {
        assert!(parse_alert_line("{\"type\":\"event\",\"pid\":1}").is_none());
        assert!(parse_alert_line("not json").is_none());

        let a = alert("r", "c", Severity::High, 7, None);
        let mut v = serde_json::to_value(&a).unwrap();
        v["type"] = serde_json::json!("alert");
        v["prev_hash"] = serde_json::json!("prev");
        v["hash"] = serde_json::json!("hash");
        let parsed = parse_alert_line(&serde_json::to_string(&v).unwrap()).unwrap();
        assert_eq!(parsed.id, a.id);
        assert_eq!(parsed.rule_name, "r");
    }

    /// 未压缩归档（轮转→压缩窗口内，或压缩被跳过/失败后长期存在）不能顶替活跃文件
    #[test]
    fn latest_log_prefers_active_over_uncompressed_archive() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("events_20261015.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("events_20261016.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("events_20261016_172533.jsonl"), "").unwrap();
        std::fs::write(dir.path().join("events_20261016_172533.jsonl.gz"), "").unwrap();
        let latest = latest_log(dir.path().to_str().unwrap()).unwrap();
        assert_eq!(
            latest.file_name().unwrap().to_str().unwrap(),
            "events_20261016.jsonl",
            "同日未压缩归档排序在活跃文件之后，旧实现会误选归档导致 watch 停报"
        );
    }
}

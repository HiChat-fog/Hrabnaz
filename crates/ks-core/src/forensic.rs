use crate::alert::Alert;
use crate::event::DecodedEvent;
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{read_dir, remove_file, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

/// argv 中敏感值的脱敏正则（文档"已知安全缺口 #8：取证日志可能含敏感 argv"）：
/// password=xxx / --token xxx / api_key: xxx 等形式，值替换为 ***
static SECRET_VALUE_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();

fn secret_value_re() -> &'static regex::Regex {
    SECRET_VALUE_RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)\b(password|passwd|pwd|passphrase|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|authorization|credentials?)(["']?\s*[=:]\s*["']?)([^\s"',;]+)"#,
        )
        .expect("secret 正则编译失败")
    })
}

/// 空格分隔的长选项形式：--password hunter2 / --api-key xxx
static SECRET_FLAG_RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();

fn secret_flag_re() -> &'static regex::Regex {
    SECRET_FLAG_RE.get_or_init(|| {
        regex::Regex::new(
            r#"(?i)((?:--?)(?:password|passwd|pwd|passphrase|token|secret|api[_-]?key|access[_-]?key))\s+([^\s-][^\s]*)"#,
        )
        .expect("secret flag 正则编译失败")
    })
}

/// 脱敏一条 argv/命令行：保留键名，值替换为 ***
pub fn sanitize_secret(value: &str) -> String {
    let s = secret_value_re()
        .replace_all(value, "${1}${2}***")
        .into_owned();
    secret_flag_re().replace_all(&s, "${1} ***").into_owned()
}

/// 递归脱敏 JSON 记录中 args/cmdline 字段的字符串值（forensic 写路径统一入口）
fn scrub_sensitive(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if matches!(k.as_str(), "args" | "cmdline") {
                    if let serde_json::Value::String(s) = v {
                        *s = sanitize_secret(s);
                    }
                } else {
                    scrub_sensitive(v);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for v in items {
                scrub_sensitive(v);
            }
        }
        _ => {}
    }
}

pub trait HashAlgorithm: Send + Sync {
    fn hash(&self, data: &str) -> String;
}

struct Sha256Hash;

impl HashAlgorithm for Sha256Hash {
    fn hash(&self, data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub max_file_size: u64,
    pub retain_days: u32,
    pub compress_archives: bool,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024,
            retain_days: 30,
            compress_archives: true,
        }
    }
}

pub struct ForensicLogger {
    writer: BufWriter<File>,
    path: PathBuf,
    prev_hash: String,
    event_count: u64,
    alert_count: u64,
    last_flush_count: u64,
    hasher: Box<dyn HashAlgorithm>,
    current_file_size: u64,
    rotation_config: RotationConfig,
    log_dir: PathBuf,
    /// 上一次外落 chain_head 的 (event_count, hash, file)：同一链尾重复 flush 不重复写行。
    /// 旧实现 Drop/显式 flush 各外落一次，chain_head.log 出现同秒同 seq 的重复行
    last_exported: Option<(u64, String, String)>,
    /// 当前活跃文件对应的日期（events_YYYYMMDD.jsonl 的日期），跨天滚动判定用
    file_date: String,
    /// 上次跨天检查的 epoch 秒（10s 节流，避免每事件都做 Local::now 时区换算）
    last_date_check_secs: u64,
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 取证记录 schema 版本（事件与告警记录都带 `schema_version`）。
/// 破坏性字段变更时递增；新增可选字段不递增（消费方必须容忍未知字段）。
pub const SCHEMA_VERSION: u64 = 1;

/// 取证目录/文件的权限契约：目录 0700、文件 0600（敏感数据不可被本地普通用户读取）。
/// root 引擎不受影响；前端（Hliðskjálf）需以 root 或受权身份读取。
#[cfg(unix)]
fn ensure_private_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::create_dir_all(dir) {
        log::warn!("创建取证目录失败 {}: {}", dir.display(), e);
        return;
    }
    if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
        log::warn!("收紧取证目录权限失败 {}: {}", dir.display(), e);
    }
}

/// 把升级前遗留的宽权限文件收紧到 0600（只动 events_* 与 chain_head.log）
#[cfg(unix)]
fn tighten_existing_files(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !(name.starts_with("events_") || name == "chain_head.log") {
            continue;
        }
        let path = entry.path();
        if let Ok(md) = entry.metadata() {
            if md.is_file() && md.permissions().mode() & 0o077 != 0 {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

/// 私有打开（0600）——活跃日志/归档/链尾统一入口
fn open_private(path: &Path, append: bool) -> std::io::Result<File> {
    let mut opts = OpenOptions::new();
    if append {
        opts.create(true).append(true);
    } else {
        opts.create(true).truncate(true).write(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// 活跃日志文件名 events_YYYYMMDD.jsonl → 日期串；其他命名返回 None。
/// 归档 events_YYYYMMDD_HHMMSS.jsonl 含下划线，不匹配，避免误判。
fn parse_active_file_date(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("events_")?;
    let date = rest.strip_suffix(".jsonl")?;
    (date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit())).then_some(date)
}

/// 统一打开取证日志（支持 .jsonl 与 .jsonl.gz 归档）——回放与链校验共用。
/// 归档默认 gzip 压缩，消费方不应被迫自己解压后才能校验。
pub fn open_log_reader(path: &Path) -> Result<Box<dyn BufRead>> {
    let file = File::open(path)?;
    if path.extension().and_then(|e| e.to_str()) == Some("gz") {
        Ok(Box::new(BufReader::new(flate2::read::MultiGzDecoder::new(
            file,
        ))))
    } else {
        Ok(Box::new(BufReader::new(file)))
    }
}

impl ForensicLogger {
    pub fn new(path: PathBuf) -> Result<Self> {
        Self::with_rotation(path, RotationConfig::default())
    }

    pub fn with_rotation(path: PathBuf, config: RotationConfig) -> Result<Self> {
        let log_dir = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("无法获取日志目录"))?
            .to_path_buf();
        #[cfg(unix)]
        {
            ensure_private_dir(&log_dir);
            tighten_existing_files(&log_dir);
        }

        let file_exists = path.exists() && path.metadata().map(|m| m.len() > 0).unwrap_or(false);
        let current_file_size = if file_exists {
            path.metadata().map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };

        let file = open_private(&path, true)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        let (prev_hash, event_count) = if file_exists {
            Self::recover_chain_state(&path)?
        } else {
            (GENESIS_HASH.to_string(), 0)
        };

        if let Err(e) = cleanup_old_archives(&log_dir, config.retain_days) {
            log::warn!("清理过期归档失败: {}", e);
        }

        // 活跃文件日期：从 events_YYYYMMDD.jsonl 解析；非该命名（单测临时文件）视为
        // "就是今天"，避免测试用的任意文件名被跨天滚动误触发
        let file_date = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(parse_active_file_date)
            .map(|d| d.to_string())
            .unwrap_or_else(|| chrono::Local::now().format("%Y%m%d").to_string());
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            writer: BufWriter::with_capacity(65536, file),
            path,
            prev_hash,
            event_count,
            alert_count: 0,
            last_flush_count: event_count,
            hasher: Box::new(Sha256Hash),
            current_file_size,
            rotation_config: config,
            log_dir,
            last_exported: None,
            file_date,
            last_date_check_secs: now_secs,
        })
    }

    fn recover_chain_state(path: &PathBuf) -> Result<(String, u64)> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut last_hash: Option<String> = None;
        let mut last_event_seq: Option<u64> = None;
        for line in reader.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            let Ok(record) = serde_json::from_str::<serde_json::Value>(&line) else {
                continue;
            };
            // 链尾 = 文件里最后一条带 hash 的记录，**事件或告警都算**。
            // 告警同样参与哈希链；旧实现只认带 seq 的事件行，最后一条是告警时
            // 恢复出过期 prev_hash，重启后首条记录锚错位置（真机实测断链两次）
            if let Some(hash) = record.get("hash").and_then(|v| v.as_str()) {
                last_hash = Some(hash.to_string());
            }
            // 事件计数/seq 播种只看事件行（告警没有 seq）
            if let Some(seq) = record.get("seq").and_then(|v| v.as_u64()) {
                last_event_seq = Some(seq);
            }
        }
        match last_hash {
            None => Ok((GENESIS_HASH.to_string(), 0)),
            Some(hash) => Ok((hash, last_event_seq.unwrap_or(0))),
        }
    }

    fn maybe_rotate(&mut self) -> Result<()> {
        if self.current_file_size < self.rotation_config.max_file_size {
            return Ok(());
        }
        self.writer.flush()?;

        let archive_name = format!(
            "events_{}.jsonl",
            chrono::Local::now().format("%Y%m%d_%H%M%S")
        );
        let archive_path = self.log_dir.join(&archive_name);
        std::fs::rename(&self.path, &archive_path)?;

        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.writer = BufWriter::with_capacity(65536, new_file);
        self.current_file_size = 0;
        log::info!("日志轮转: 归档至 {}", archive_path.display());
        if let Err(e) = cleanup_old_archives(&self.log_dir, self.rotation_config.retain_days) {
            log::warn!("归档清理失败: {}", e);
        }

        if self.rotation_config.compress_archives {
            let gzip_path = archive_path.with_extension("jsonl.gz");
            let src = archive_path.clone();
            // 单例压缩线程 + 有界通道：旧实现每次轮转 std::thread::spawn 分离线程
            // 无并发上限，高频轮转会堆积线程；且 remove_file 失败被吞，留下 .jsonl/.gz 双份
            spawn_gzip_worker(src, gzip_path);
        }
        // 每个归档边界外落一次链尾锚点（有界：一次/轮转，约 10 分钟级）
        self.export_chain_head();
        Ok(())
    }

    /// 跨天滚动检查（10s 节流）：文件名 events_YYYYMMDD.jsonl 的日期是写入口径，
    /// 进程跨天继续写旧名文件会让"按天"语义失真（README/replay 都按天描述）。
    fn maybe_rollover_day(&mut self) -> Result<()> {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now_secs.saturating_sub(self.last_date_check_secs) < 10 {
            return Ok(());
        }
        self.last_date_check_secs = now_secs;
        let today = chrono::Local::now().format("%Y%m%d").to_string();
        if today != self.file_date {
            self.rollover_to_date(&today)?;
        }
        Ok(())
    }

    /// 跨天滚动：昨天的活跃文件轮转为归档，新建 events_<today>.jsonl 继续写。
    /// 链不重置：prev_hash 跨文件延续（新文件首条 anchored）；seq/event_count 也不
    /// 重置（同一进程内计数），消费方在文件内看到的序号保持单调。
    fn rollover_to_date(&mut self, today: &str) -> Result<()> {
        self.writer.flush()?;
        let now_tag = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let archive_path = self.log_dir.join(format!("events_{}.jsonl", now_tag));
        std::fs::rename(&self.path, &archive_path)?;

        let new_path = self.log_dir.join(format!("events_{}.jsonl", today));
        // 防御：今天的同名文件已存在（异常场景）时先移走——两条不同的链混进同一
        // 文件会让链校验必然断裂
        if new_path.exists() && new_path.metadata().map(|m| m.len() > 0).unwrap_or(false) {
            let aside = self.log_dir.join(format!("events_{}_pre.jsonl", now_tag));
            if let Err(e) = std::fs::rename(&new_path, &aside) {
                log::warn!(
                    "跨天滚动: 移走同名旧文件失败: {} — {}",
                    new_path.display(),
                    e
                );
            }
        }
        let new_file = open_private(&new_path, true)?;
        self.writer = BufWriter::with_capacity(65536, new_file);
        self.path = new_path;
        self.file_date = today.to_string();
        self.current_file_size = 0;
        self.export_chain_head();
        log::info!("跨天滚动: 归档至 {}", archive_path.display());

        if self.rotation_config.compress_archives {
            let gzip_path = archive_path.with_extension("jsonl.gz");
            spawn_gzip_worker(archive_path, gzip_path);
        }
        Ok(())
    }

    pub fn log_event(&mut self, event: &DecodedEvent) -> Result<()> {
        self.maybe_rollover_day()?;
        self.event_count += 1;

        let mut record = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "type": "event",
            "seq": event.seq, "timestamp_ns": event.header.timestamp_ns,
            "event_type": event.header.event_type,
            "event_type_name": crate::event::event_type_name(event.header.event_type),
            "pid": event.header.pid,
            "tid": event.header.tid, "uid": event.header.uid, "ppid": event.header.ppid,
            "comm": event.comm, "syscall_nr": event.header.syscall_nr, "retval": event.header.retval,
        });
        // 墙钟侧车：btime+monotonic 换算（btime 在 OnceLock 缓存，热路径零 IO）。
        // 换算不出来（无 /proc/stat）时省略字段，消费方退回 timestamp_ns 单调钟
        if let Some(epoch_ms) = crate::time::epoch_ms_from_monotonic_ns(event.header.timestamp_ns) {
            record["epoch_ms"] = serde_json::json!(epoch_ms);
        }

        if let Some(ref f) = event.filename {
            record["filename"] = serde_json::Value::String(f.clone());
        }
        if let Some(ref a) = event.args {
            record["args"] = serde_json::Value::String(a.clone());
        }
        if let Some(ref s) = event.saddr {
            record["saddr"] = serde_json::Value::String(s.clone());
        }
        if let Some(ref d) = event.daddr {
            record["daddr"] = serde_json::Value::String(d.clone());
        }
        if let Some(p) = event.sport {
            record["sport"] = serde_json::json!(p);
        }
        if let Some(p) = event.dport {
            record["dport"] = serde_json::json!(p);
        }
        if let Some(ref p) = event.proto {
            record["proto"] = serde_json::Value::String(p.clone());
        }
        if let Some(p) = event.target_pid {
            record["target_pid"] = serde_json::json!(p);
        }
        if let Some(s) = event.signal {
            record["signal"] = serde_json::json!(s);
        }
        if let Some(b) = event.file_bytes {
            record["file_bytes"] = serde_json::json!(b);
        }

        // 脱敏必须在哈希之前：保证链校验时重算的内容与落盘内容一致
        scrub_sensitive(&mut record);

        let btree: BTreeMap<String, serde_json::Value> = record
            .as_object()
            .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let json_str = serde_json::to_string(&btree)?;
        let current_hash = self.hasher.hash(&json_str);

        record["prev_hash"] = serde_json::Value::String(self.prev_hash.clone());
        record["hash"] = serde_json::Value::String(current_hash.clone());

        let line = serde_json::to_string(&record)?;
        let line_bytes = line.len() as u64 + 1;
        writeln!(self.writer, "{}", line)?;

        self.prev_hash = current_hash;
        self.current_file_size += line_bytes;

        if self.event_count - self.last_flush_count >= 1000 {
            self.flush()?;
        }
        self.maybe_rotate()?;
        Ok(())
    }

    pub fn log_alert(&mut self, alert: &Alert) -> Result<()> {
        self.maybe_rollover_day()?;
        self.alert_count += 1;
        let mut record = serde_json::to_value(alert)?;
        record["schema_version"] = serde_json::json!(SCHEMA_VERSION);
        record["type"] = serde_json::Value::String("alert".to_string());
        if let Some(epoch_ms) = crate::time::epoch_ms_from_monotonic_ns(alert.timestamp_ns) {
            record["epoch_ms"] = serde_json::json!(epoch_ms);
        }

        // 告警的 process.cmdline 同样可能携带 argv 里的明文密码
        scrub_sensitive(&mut record);

        let btree: BTreeMap<String, serde_json::Value> = record
            .as_object()
            .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let json_str = serde_json::to_string(&btree)?;
        let current_hash = self.hasher.hash(&json_str);

        record["prev_hash"] = serde_json::Value::String(self.prev_hash.clone());
        record["hash"] = serde_json::Value::String(current_hash.clone());

        let line = serde_json::to_string(&record)?;
        writeln!(self.writer, "{}", line)?;
        self.prev_hash = current_hash;
        self.current_file_size += line.len() as u64 + 1;
        self.writer.flush()?;
        // 不重置 last_flush_count：告警高频时若跟着重置，"每 1000 条事件 flush
        // 并外落链尾"的条件会被永久推迟（真机实测 chain_head.log 冻结 90+ 分钟）。
        // 告警只负责把数据 flush 到 OS 保证实时可见，链尾外落交给事件节奏 + 轮转边界。
        self.maybe_rotate()?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.last_flush_count = self.event_count;
        self.export_chain_head();
        Ok(())
    }

    /// 链尾哈希外落（文档缺口 #6"无链尾外报"）：flush 时把链尾 hash 追加
    /// 写到日志目录下的独立文件 chain_head.log。取证日志被整批删除/篡改时，
    /// 该文件仍保留可对照的哈希记录（replay 验证结果可与之外部比对）。
    /// 追加式且带时间戳，攻击者无法在不留痕迹的情况下"回填"历史链尾。
    /// 同一 (event_count, hash, file) 重复 flush 只写一次（旧实现 Drop+显式 flush
    /// 各写一行，留下同秒同 seq 的重复行）。
    fn export_chain_head(&mut self) {
        let head_path = self.log_dir.join("chain_head.log");
        let file_name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("?")
            .to_string();
        let key = (self.event_count, self.prev_hash.clone(), file_name.clone());
        if self.last_exported.as_ref() == Some(&key) {
            return;
        }
        let line = format!(
            "{} seq={} hash={} file={}\n",
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            self.event_count,
            self.prev_hash,
            file_name,
        );
        let write_res =
            open_private(&head_path, true).and_then(|mut f| f.write_all(line.as_bytes()));
        if let Err(e) = write_res {
            // 外落失败不影响主取证链路
            log::debug!("chain_head 外落失败: {} — {}", head_path.display(), e);
        } else {
            self.last_exported = Some(key);
        }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
    pub fn event_count(&self) -> u64 {
        self.event_count
    }
    pub fn alert_count(&self) -> u64 {
        self.alert_count
    }
    pub fn chain_tail_hash(&self) -> &str {
        &self.prev_hash
    }

    pub fn verify_chain(path: &Path) -> Result<ChainVerification> {
        // 流式逐行校验：旧实现 read_to_string 把 100MB+ 整个日志读进内存；
        // .jsonl.gz 归档与活跃 .jsonl 共用同一读取入口
        let reader = open_log_reader(path)?;
        let mut prev_hash = GENESIS_HASH.to_string();
        let mut total_records = 0u64;
        let mut broken_at: Option<u64> = None;
        let mut anchored = false;
        let hasher = Sha256Hash;

        for line in reader.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            total_records += 1;

            // 解析失败的行（半行：引擎被 kill 于 write 中途，或 replay 读到正在写的活动文件
            // 的写入瞬间）计入 broken_at 而非整体报错——取证工具的本分是"报告问题位置"，
            // 让使用者能定位到行号，而不是一条 JSON 异常吞掉整份校验结论
            let record: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => {
                    if broken_at.is_none() {
                        broken_at = Some(total_records);
                    }
                    prev_hash = String::new();
                    continue;
                }
            };
            let stored_prev = record
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let stored_hash = record.get("hash").and_then(|v| v.as_str()).unwrap_or("");

            // 校验语义 = "文件内连续性 + 逐条自身哈希"（ROADMAP H-1.1）：
            // 首条 prev_hash 不要求等于创世值——日志按天滚动/重启续链后首条锚指向前代
            // 文件（常被轮转清理），非创世只说明"锚定于上一世代"，不是篡改；
            // 第二条起 prev_hash 必须等于前一条 hash（文件内连续，删/插记录在此暴露），
            // 每条自身哈希必须与重算一致（改内容在此暴露）。
            if total_records == 1 {
                if stored_prev != GENESIS_HASH {
                    anchored = true;
                }
            } else if stored_prev != prev_hash && broken_at.is_none() {
                broken_at = Some(total_records);
            }

            let mut clean = record.clone();
            if let Some(m) = clean.as_object_mut() {
                m.remove("hash");
                m.remove("prev_hash");
            }
            let btree: BTreeMap<String, serde_json::Value> = match clean.as_object() {
                Some(obj) => obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                None => {
                    let recomputed =
                        hasher.hash(&serde_json::to_string(&clean).unwrap_or_default());
                    if recomputed != stored_hash && broken_at.is_none() {
                        broken_at = Some(total_records);
                    }
                    prev_hash = stored_hash.to_string();
                    continue;
                }
            };
            let deterministic_json = serde_json::to_string(&btree)?;
            let recomputed = hasher.hash(&deterministic_json);
            if recomputed != stored_hash && broken_at.is_none() {
                broken_at = Some(total_records);
            }
            prev_hash = stored_hash.to_string();
        }

        Ok(ChainVerification {
            total_records,
            is_valid: broken_at.is_none(),
            broken_at,
            anchored,
        })
    }
}

#[derive(Debug)]
pub struct ChainVerification {
    pub total_records: u64,
    pub is_valid: bool,
    pub broken_at: Option<u64>,
    /// 首条 prev_hash 非创世值：文件锚定于上一世代（按天滚动/重启续链的正常形态），
    /// 不是篡改证据。真篡改由文件内连续性 + 逐条自身哈希两道检查兜住
    pub anchored: bool,
}

impl Drop for ForensicLogger {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            log::error!("取证日志 flush 失败 (drop): {}", e);
        }
    }
}

fn compress_gzip(src: &Path, dst: &Path) -> Result<()> {
    let input = File::open(src)?;
    let output = open_private(dst, false)?;
    let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
    let mut reader = BufReader::new(input);
    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;
    Ok(())
}

/// 归档压缩 worker：进程内单线程 + 有界通道(8)。
/// 通道满时跳过该次压缩并 warn（.jsonl 归档仍保留，清理任务会按保留期回收），
/// 避免 rotate 热路径阻塞、也避免线程无界堆积
fn spawn_gzip_worker(src: std::path::PathBuf, dst: std::path::PathBuf) {
    use std::sync::mpsc;
    use std::sync::OnceLock;
    static WORKER: OnceLock<mpsc::SyncSender<(std::path::PathBuf, std::path::PathBuf)>> =
        OnceLock::new();
    let tx = WORKER.get_or_init(|| {
        let (tx, rx) = mpsc::sync_channel::<(std::path::PathBuf, std::path::PathBuf)>(8);
        std::thread::Builder::new()
            .name("ks-gzip-rotate".into())
            .spawn(move || {
                while let Ok((src, dst)) = rx.recv() {
                    match compress_gzip(&src, &dst) {
                        Ok(()) => {
                            if let Err(e) = remove_file(&src) {
                                log::warn!(
                                    "压缩后删除归档 {} 失败: {} (双份归档,由保留期清理回收)",
                                    src.display(),
                                    e
                                );
                            } else {
                                log::info!("归档已压缩: {}", dst.display());
                            }
                        }
                        Err(e) => log::warn!("压缩归档失败: {} — {}", src.display(), e),
                    }
                }
            })
            .expect("spawn gzip worker");
        tx
    });
    if tx.try_send((src, dst)).is_err() {
        log::warn!("压缩队列已满,本次归档暂不压缩 (保留 .jsonl 由清理任务回收)");
    }
}

fn cleanup_old_archives(log_dir: &Path, retain_days: u32) -> Result<()> {
    let cutoff = chrono::Local::now() - chrono::Duration::days(retain_days as i64);
    let cutoff_secs = cutoff.timestamp();
    for entry in read_dir(log_dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path.file_name().unwrap_or_default().to_string_lossy();
        if name.starts_with("events_") && (name.ends_with(".jsonl.gz") || name.ends_with(".jsonl"))
        {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    let mod_secs = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    if mod_secs < cutoff_secs {
                        remove_file(&path)?;
                        log::info!("清理过期归档: {}", path.display());
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
    use crate::event::EventHeader;
    use tempfile::TempDir;

    #[test]
    fn test_sanitize_secret_kv_forms() {
        assert_eq!(
            sanitize_secret("mysql -u root -password=hunter2 -h db"),
            "mysql -u root -password=*** -h db"
        );
        assert_eq!(
            sanitize_secret("export API_KEY=abcd1234 && run"),
            "export API_KEY=*** && run"
        );
        assert_eq!(
            sanitize_secret("psql --dbname x --token: my-secret-token"),
            "psql --dbname x --token: ***"
        );
    }

    #[test]
    fn test_sanitize_secret_flag_form() {
        assert_eq!(
            sanitize_secret("kubectl create secret --password hunter2 --ns prod"),
            "kubectl create secret --password *** --ns prod"
        );
    }

    #[test]
    fn test_sanitize_keeps_normal_args() {
        let normal = "gcc -O2 -o app main.c && tar -czf backup.tar.gz /data";
        assert_eq!(sanitize_secret(normal), normal);
        // 普通单词不能被误伤
        assert_eq!(
            sanitize_secret("ls -la --color=auto"),
            "ls -la --color=auto"
        );
    }

    #[test]
    fn test_scrub_sensitive_walks_json() {
        let mut v: serde_json::Value = serde_json::json!({
            "pid": 1,
            "args": "python -c 'token=abcdef'",
            "process": { "cmdline": "curl -H 'Authorization: Bearer xyz' http://x" },
            "comm": "bash"
        });
        scrub_sensitive(&mut v);
        assert_eq!(v["args"], "python -c 'token=***'");
        assert!(v["process"]["cmdline"].as_str().unwrap().contains("***"));
        assert_eq!(v["comm"], "bash");
    }

    fn make_event(seq: u64, pid: u32) -> DecodedEvent {
        let mut comm = [0u8; 16];
        comm[..4].copy_from_slice(b"test");
        DecodedEvent {
            seq,
            comm: "test".to_string(),
            header: EventHeader {
                event_type: 2,
                _pad1: 0,
                timestamp_ns: seq * 1_000_000_000,
                pid,
                tid: 0,
                uid: 0,
                ppid: 0,
                comm,
                syscall_nr: 0,
                _pad2: 0,
                retval: 0,
            },
            filename: None,
            args: None,
            saddr: None,
            daddr: None,
            sport: None,
            dport: None,
            proto: None,
            target_pid: None,
            signal: None,
            file_bytes: None,
            module_name: None,
            prog_name: None,
            source_ns_inum: None,
            target_ns_inum: None,
            cap_eff: None,
            action: None,
        }
    }

    #[test]
    fn test_forensic_log_write_and_recover() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        {
            let mut logger = ForensicLogger::new(path.clone()).unwrap();
            logger.log_event(&make_event(1, 100)).unwrap();
            logger.log_event(&make_event(2, 200)).unwrap();
            logger.flush().unwrap();
        }
        let (hash, seq) = ForensicLogger::recover_chain_state(&path).unwrap();
        assert_eq!(seq, 2);
        assert_ne!(hash, GENESIS_HASH);
        {
            let logger = ForensicLogger::new(path.clone()).unwrap();
            assert_eq!(logger.chain_tail_hash(), hash);
        }
    }

    #[test]
    fn test_chain_verification_valid() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        {
            let mut logger = ForensicLogger::new(path.clone()).unwrap();
            for i in 1..=10 {
                logger.log_event(&make_event(i, 100)).unwrap();
            }
            logger.flush().unwrap();
        }
        let result = ForensicLogger::verify_chain(&path).unwrap();
        assert!(result.is_valid);
        assert_eq!(result.total_records, 10);
    }

    #[test]
    fn test_chain_verification_valid_mixed_events_and_alerts() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        {
            let mut logger = ForensicLogger::new(path.clone()).unwrap();
            for i in 1..=5 {
                logger.log_event(&make_event(i, 100)).unwrap();
            }
            let alert = crate::alert::Alert {
                id: uuid::Uuid::new_v4(),
                timestamp_ns: 123456789,
                severity: crate::rule::Severity::High,
                title: "test alert".to_string(),
                description: "desc".to_string(),
                rule_name: "test_rule".to_string(),
                process: crate::alert::ProcessInfo {
                    pid: 100,
                    ppid: 1,
                    comm: "test".to_string(),
                    uid: 0,
                    exe_path: Some("/usr/bin/test".to_string()),
                    cmdline: None,
                },
                network: None,
                file: None,
                event_ids: vec![1, 2],
                mitre: Some(crate::alert::MitreInfo {
                    tactic: "TA0002".to_string(),
                    technique: "T1059".to_string(),
                    sub_technique: None,
                }),
                status: crate::alert::AlertStatus::New,
                feedback: None,
            };
            logger.log_alert(&alert).unwrap();
            logger.log_event(&make_event(6, 200)).unwrap();
            logger.flush().unwrap();
        }
        let result = ForensicLogger::verify_chain(&path).unwrap();
        assert!(
            result.is_valid,
            "混合事件+告警链应有效, 却在第 {:?} 条断裂",
            result.broken_at
        );
    }

    #[test]
    fn test_genesis_hash() {
        assert_eq!(GENESIS_HASH.len(), 64);
        assert!(GENESIS_HASH.chars().all(|c| c == '0'));
    }

    #[test]
    fn test_log_rotation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let config = RotationConfig {
            max_file_size: 500,
            retain_days: 30,
            compress_archives: false,
        };
        {
            let mut logger = ForensicLogger::with_rotation(path.clone(), config).unwrap();
            for i in 1..=50 {
                logger.log_event(&make_event(i, 100)).unwrap();
            }
            logger.flush().unwrap();
        }
        assert!(path.exists());
    }

    /// 手工追加一条链记录：与 log_event 相同的规范化哈希
    /// （clean 记录去 hash/prev_hash 后按 BTreeMap 序列化再 SHA-256）。
    /// 返回该条 hash，供下一条续链
    fn append_chained_record(
        path: &Path,
        mut record: serde_json::Value,
        prev_hash: &str,
    ) -> String {
        use std::io::Write as _;
        record["prev_hash"] = serde_json::Value::String(prev_hash.to_string());
        let mut clean = record.clone();
        if let Some(m) = clean.as_object_mut() {
            m.remove("hash");
            m.remove("prev_hash");
        }
        let btree: BTreeMap<String, serde_json::Value> = clean
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_string(&btree).unwrap().as_bytes());
        let hash = format!("{:x}", hasher.finalize());
        record["hash"] = serde_json::Value::String(hash.clone());
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(f, "{}", serde_json::to_string(&record).unwrap()).unwrap();
        hash
    }

    /// 读文件最后一条记录的 hash（链尾），供跨文件续链测试用
    fn chain_tail_of(path: &Path) -> String {
        let f = File::open(path).unwrap();
        let last = BufReader::new(f)
            .lines()
            .map_while(Result::ok)
            .filter(|l| !l.trim().is_empty())
            .last()
            .expect("文件至少应有一条记录");
        serde_json::from_str::<serde_json::Value>(&last)
            .unwrap()
            .get("hash")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string()
    }

    fn plain_record(seq: u64) -> serde_json::Value {
        serde_json::json!({
            "seq": seq, "timestamp_ns": seq * 1_000_000_000, "event_type": 2,
            "pid": 100, "tid": 0, "uid": 0, "ppid": 1, "comm": "test",
            "syscall_nr": 0, "retval": 0,
        })
    }

    /// H-1.1 单测①：跨文件续链（首条 prev_hash 锚指上一世代）应通过且 anchored=true
    #[test]
    fn test_verify_anchored_cross_file_continuation_passes() {
        let dir = TempDir::new().unwrap();
        // 世代 1：正常创世链
        let prev_file = dir.path().join("events_gen1.jsonl");
        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=3 {
            prev = append_chained_record(&prev_file, plain_record(i), &prev);
        }
        // 世代 2（按天滚动后的新文件）：首条锚指向 gen1 的链尾
        let cur_file = dir.path().join("events_gen2.jsonl");
        let mut prev = chain_tail_of(&prev_file);
        for i in 4..=7 {
            prev = append_chained_record(&cur_file, plain_record(i), &prev);
        }
        let v = ForensicLogger::verify_chain(&cur_file).unwrap();
        assert!(
            v.is_valid,
            "锚定文件应通过校验, 却在第 {:?} 条断裂",
            v.broken_at
        );
        assert!(v.anchored, "首条 prev_hash 非创世应标注 anchored");
        assert_eq!(v.total_records, 4);
    }

    /// H-1.1 单测②：真篡改仍能精确定位（内容改动 → 自身哈希不匹配）
    #[test]
    fn test_verify_anchored_file_detects_content_tamper() {
        let dir = TempDir::new().unwrap();
        let cur_file = dir.path().join("events_gen2.jsonl");
        let mut prev = String::from("aa11"); // 任意上一世代链尾
        for i in 4..=6 {
            prev = append_chained_record(&cur_file, plain_record(i), &prev);
        }
        // 篡改第 2 条内容（pid 100→999），hash 保持不变
        let content = std::fs::read_to_string(&cur_file).unwrap();
        let tampered: Vec<String> = content
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if i == 1 {
                    l.replace(r#""pid":100"#, r#""pid":999"#)
                } else {
                    l.to_string()
                }
            })
            .collect();
        std::fs::write(&cur_file, tampered.join("\n") + "\n").unwrap();
        let v = ForensicLogger::verify_chain(&cur_file).unwrap();
        assert!(!v.is_valid);
        assert_eq!(
            v.broken_at,
            Some(2),
            "内容篡改应在第 2 条被自身哈希检查定位"
        );
    }

    /// H-1.1 单测③：文件内删/插记录仍被文件内连续性检查抓住
    #[test]
    fn test_verify_anchored_file_detects_record_deletion() {
        let dir = TempDir::new().unwrap();
        let cur_file = dir.path().join("events_gen2.jsonl");
        let mut prev = String::from("bb22");
        for i in 4..=6 {
            prev = append_chained_record(&cur_file, plain_record(i), &prev);
        }
        // 删除第 2 条：第 3 条的 prev_hash 将对不上第 1 条的 hash
        let content = std::fs::read_to_string(&cur_file).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let kept: Vec<&str> = lines
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| *l)
            .collect();
        std::fs::write(&cur_file, kept.join("\n") + "\n").unwrap();
        let v = ForensicLogger::verify_chain(&cur_file).unwrap();
        assert!(!v.is_valid);
        assert_eq!(
            v.broken_at,
            Some(2),
            "删记录应在缺口后第一条被连续性检查定位"
        );
    }

    /// H-1.1 单测④：创世链语义不变——正常单文件链通过且不标注 anchored
    #[test]
    fn test_verify_genesis_file_not_anchored() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=3 {
            prev = append_chained_record(&path, plain_record(i), &prev);
        }
        let v = ForensicLogger::verify_chain(&path).unwrap();
        assert!(v.is_valid);
        assert!(!v.anchored, "创世链不应标注 anchored");
    }

    /// 半行（写入中途被 kill / 活动文件截断读）计入 broken_at 而非整体 Err，
    /// replay 能定位到行号而不是"校验命令本身失败"
    #[test]
    fn test_verify_torn_line_reports_position_not_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        let mut prev = GENESIS_HASH.to_string();
        for i in 1..=3 {
            prev = append_chained_record(&path, plain_record(i), &prev);
        }
        // 追加半行（截断的 JSON）
        {
            use std::io::Write as _;
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"{\"seq\":4,\"comm\":\"te").unwrap();
        }
        let v = ForensicLogger::verify_chain(&path).unwrap();
        assert!(!v.is_valid);
        assert_eq!(v.broken_at, Some(4), "半行应作为第 4 条记录断裂报告");
    }

    fn make_alert() -> crate::alert::Alert {
        crate::alert::Alert {
            id: uuid::Uuid::new_v4(),
            timestamp_ns: 123456789,
            severity: crate::rule::Severity::High,
            title: "test alert".to_string(),
            description: "desc".to_string(),
            rule_name: "test_rule".to_string(),
            process: crate::alert::ProcessInfo {
                pid: 100,
                ppid: 1,
                comm: "test".to_string(),
                uid: 0,
                exe_path: None,
                cmdline: None,
            },
            network: None,
            file: None,
            event_ids: vec![],
            mitre: None,
            status: crate::alert::AlertStatus::New,
            feedback: None,
        }
    }

    /// 链尾外落不能被高频告警饿死：告警只 flush 数据、不重置"每 1000 条事件外落
    /// 一次"的计数（旧实现每次告警把计数归零且不外落，真机曾冻结 90+ 分钟）
    #[test]
    fn test_chain_head_not_starved_by_frequent_alerts() {
        let dir = TempDir::new().unwrap();
        let log_dir = dir.path().to_path_buf();
        let path = log_dir.join("events_20200101.jsonl");
        let config = RotationConfig {
            max_file_size: u64::MAX,
            retain_days: 30,
            compress_archives: false,
        };
        let mut logger = ForensicLogger::with_rotation(path, config).unwrap();
        for i in 1..=999u64 {
            logger.log_event(&make_event(i, 100)).unwrap();
        }
        for _ in 0..20 {
            logger.log_alert(&make_alert()).unwrap();
        }
        // 第 1000 条事件必须触发外落
        logger.log_event(&make_event(1000, 100)).unwrap();
        let head = std::fs::read_to_string(log_dir.join("chain_head.log")).unwrap();
        assert!(
            !head.trim().is_empty(),
            "告警密集时 1000 条事件后 chain_head 必须已外落（旧实现被告警重置计数而永不外落）"
        );
    }

    /// 同一链尾重复 flush（显式 flush + Drop）只外落一次
    #[test]
    fn test_chain_head_dedupes_repeated_flush() {
        let dir = TempDir::new().unwrap();
        let log_dir = dir.path().to_path_buf();
        let path = log_dir.join("test.jsonl");
        let mut logger = ForensicLogger::new(path).unwrap();
        logger.log_event(&make_event(1, 100)).unwrap();
        logger.flush().unwrap();
        logger.flush().unwrap();
        drop(logger); // Drop 再 flush 一次
        let content = std::fs::read_to_string(log_dir.join("chain_head.log")).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(lines.len(), 1, "重复 flush 不应重复外落链尾: {:?}", lines);
    }

    /// 跨天滚动：旧文件归档、新文件按当天日期命名、链跨文件延续（anchored）、
    /// 序号不重置
    #[test]
    fn test_daily_rollover_creates_dated_file_and_keeps_chain() {
        let dir = TempDir::new().unwrap();
        let log_dir = dir.path().to_path_buf();
        let path = log_dir.join("events_20200101.jsonl");
        let config = RotationConfig {
            max_file_size: u64::MAX,
            retain_days: 30,
            compress_archives: false,
        };
        let mut logger = ForensicLogger::with_rotation(path.clone(), config).unwrap();
        for i in 1..=5u64 {
            logger.log_event(&make_event(i, 100)).unwrap();
        }
        let old_tail = logger.chain_tail_hash().to_string();

        logger.rollover_to_date("20200102").unwrap();
        assert!(!path.exists(), "旧活跃文件应已轮转为归档");
        let new_path = log_dir.join("events_20200102.jsonl");
        assert!(new_path.exists(), "应新建当天命名的活跃文件");

        logger.log_event(&make_event(6, 100)).unwrap();
        logger.flush().unwrap();

        // 新文件首条 prev_hash 锚定旧文件链尾
        let first = std::fs::read_to_string(&new_path)
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .to_string();
        let rec: serde_json::Value = serde_json::from_str(&first).unwrap();
        assert_eq!(
            rec["prev_hash"].as_str().unwrap(),
            old_tail,
            "新文件首条应锚定上一世代的链尾"
        );
        assert_eq!(rec["seq"].as_u64().unwrap(), 6, "序列号跨文件不重置");

        let v = ForensicLogger::verify_chain(&new_path).unwrap();
        assert!(v.is_valid, "跨天滚动后新文件链应连续: {:?}", v.broken_at);
        assert!(v.anchored, "新文件首条应锚定上一世代");

        // 旧内容已在归档文件中
        let archives: Vec<std::ffi::OsString> = std::fs::read_dir(&log_dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .filter(|n| {
                let s = n.to_string_lossy();
                s.starts_with("events_") && s != "events_20200102.jsonl"
            })
            .collect();
        assert!(!archives.is_empty(), "旧文件应成为归档");
    }

    /// 墙钟侧车：事件与告警记录都带 epoch_ms，且换算值参与哈希前内容一致
    /// （Linux 上 /proc/stat 必有 btime；make_event 的 timestamp_ns=seq 秒）
    #[test]
    fn test_records_carry_epoch_ms_wallclock() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events_20200101.jsonl");
        let mut logger = ForensicLogger::new(path.clone()).unwrap();
        logger.log_event(&make_event(1, 100)).unwrap();
        let alert = make_alert();
        logger.log_alert(&alert).unwrap();
        logger.flush().unwrap();
        drop(logger);

        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let ev = &lines[0];
        let al = &lines[1];

        // 侧车换算与 ks_core 公式一致：epoch = btime*1000 + mono_ms
        let expected_event_ms = crate::time::epoch_ms_from_monotonic_ns(1_000_000_000).unwrap();
        assert_eq!(
            ev["epoch_ms"].as_i64().unwrap(),
            expected_event_ms,
            "事件 epoch_ms 应等于 btime+monotonic 换算值"
        );
        assert_eq!(
            al["epoch_ms"].as_i64().unwrap(),
            crate::time::epoch_ms_from_monotonic_ns(alert.timestamp_ns).unwrap(),
            "告警 epoch_ms 应与其 timestamp_ns 同源"
        );
        // 双字段并存：单调钟仍是取证序权威
        assert!(ev.get("timestamp_ns").is_some());
        assert!(al.get("timestamp_ns").is_some());
    }

    /// 重启恢复：文件最后一条是告警时，新会话首条记录必须锚定到该告警的 hash。
    /// 旧实现恢复时跳过告警行，重启后首条事件锚到更早的事件 hash —— 链在此断裂
    /// （真机 2026-10-17 两次重启均命中：断点前最后一条恰为告警）。
    #[test]
    fn test_restart_after_alert_keeps_chain_continuous() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("events_20200101.jsonl");
        {
            let mut logger = ForensicLogger::new(path.clone()).unwrap();
            logger.log_event(&make_event(1, 100)).unwrap();
            logger.log_alert(&make_alert()).unwrap(); // 链尾是告警
            logger.flush().unwrap();
        }

        let alert_hash = {
            let content = std::fs::read_to_string(&path).unwrap();
            let last: serde_json::Value =
                serde_json::from_str(content.lines().last().unwrap()).unwrap();
            assert_eq!(last["type"].as_str(), Some("alert"));
            last["hash"].as_str().unwrap().to_string()
        };

        // 模拟重启：重开同一文件并写一条事件
        {
            let mut logger = ForensicLogger::new(path.clone()).unwrap();
            logger.log_event(&make_event(2, 100)).unwrap();
            logger.flush().unwrap();
        }

        let v = ForensicLogger::verify_chain(&path).unwrap();
        assert!(v.is_valid, "重启后链应连续: {:?}", v.broken_at);
        assert_eq!(v.total_records, 3);

        let content = std::fs::read_to_string(&path).unwrap();
        let last: serde_json::Value =
            serde_json::from_str(content.lines().last().unwrap()).unwrap();
        assert_eq!(
            last["prev_hash"].as_str(),
            Some(alert_hash.as_str()),
            "新会话首条必须锚定链尾告警的 hash，而不是更早的事件"
        );
    }

    /// 契约 v1：事件与告警记录都带 schema_version/type；事件带可读 event_type_name，
    /// 数值 event_type 保留。
    #[test]
    fn test_records_carry_contract_v1_fields() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("events_20200101.jsonl");
        let mut logger = ForensicLogger::new(path.clone()).unwrap();
        let ev = make_event(1, 100);
        logger.log_event(&ev).unwrap();
        logger.log_alert(&make_alert()).unwrap();
        logger.flush().unwrap();
        drop(logger);

        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        let event = &lines[0];
        let alert = &lines[1];

        assert_eq!(event["schema_version"].as_u64(), Some(SCHEMA_VERSION));
        assert_eq!(event["type"].as_str(), Some("event"));
        assert_eq!(
            event["event_type_name"].as_str(),
            Some(crate::event::event_type_name(ev.header.event_type)),
            "event_type_name 必须与数值同源"
        );
        assert_eq!(
            event["event_type"].as_u64(),
            Some(u64::from(ev.header.event_type)),
            "数值 event_type 保留（内核/调试用）"
        );

        assert_eq!(alert["schema_version"].as_u64(), Some(SCHEMA_VERSION));
        assert_eq!(alert["type"].as_str(), Some("alert"));

        // 新字段参与哈希前内容：链仍然自洽
        let v = ForensicLogger::verify_chain(&path).unwrap();
        assert!(v.is_valid, "契约字段加入后链应仍可校验: {:?}", v.broken_at);
    }

    /// 权限契约：目录 0700、活跃日志/链尾 0600（敏感数据不可被本地普通用户读取）
    #[cfg(unix)]
    #[test]
    fn test_forensic_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();
        let log_dir = dir.path().join("logs");
        let path = log_dir.join("events_20200101.jsonl");
        let mut logger = ForensicLogger::new(path.clone()).unwrap();
        logger.log_event(&make_event(1, 100)).unwrap();
        logger.flush().unwrap();
        drop(logger);

        let dir_mode = std::fs::metadata(&log_dir).unwrap().permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        let head_mode = std::fs::metadata(log_dir.join("chain_head.log"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "取证目录应为 0700");
        assert_eq!(file_mode, 0o600, "活跃日志应为 0600");
        assert_eq!(head_mode, 0o600, "chain_head.log 应为 0600");
    }

    /// .jsonl.gz 归档必须能被链校验直接读取（归档默认 gzip 压缩）
    #[test]
    fn test_verify_chain_supports_gz_archive() {
        use std::io::Write as _;
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("events_20200101.jsonl");
        let mut logger = ForensicLogger::new(path.clone()).unwrap();
        for i in 1..=5u64 {
            logger.log_event(&make_event(i, 100)).unwrap();
        }
        logger.flush().unwrap();
        drop(logger);

        let raw = std::fs::read(&path).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&raw).unwrap();
        let gz_path = dir.path().join("events_20200101_120000.jsonl.gz");
        std::fs::write(&gz_path, encoder.finish().unwrap()).unwrap();

        let v = ForensicLogger::verify_chain(&gz_path).unwrap();
        assert!(v.is_valid, "gz 归档应可校验: {:?}", v.broken_at);
        assert_eq!(v.total_records, 5);
    }
}

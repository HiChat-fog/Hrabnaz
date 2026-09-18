use crate::aggregator::DecodedEvent;
use anyhow::Result;
use ks_core::alert::Alert;
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
    let s = secret_value_re().replace_all(value, "${1}${2}***").into_owned();
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
}

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

impl ForensicLogger {
    pub fn new(path: PathBuf) -> Result<Self> {
        Self::with_rotation(path, RotationConfig::default())
    }

    pub fn with_rotation(path: PathBuf, config: RotationConfig) -> Result<Self> {
        let log_dir = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("无法获取日志目录"))?
            .to_path_buf();

        let file_exists = path.exists() && path.metadata().map(|m| m.len() > 0).unwrap_or(false);
        let current_file_size = if file_exists {
            path.metadata().map(|m| m.len()).unwrap_or(0)
        } else {
            0
        };

        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        let (prev_hash, event_count) = if file_exists {
            Self::recover_chain_state(&path)?
        } else {
            (GENESIS_HASH.to_string(), 0)
        };

        if let Err(e) = cleanup_old_archives(&log_dir, config.retain_days) {
            log::warn!("清理过期归档失败: {}", e);
        }

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
        })
    }

    fn recover_chain_state(path: &PathBuf) -> Result<(String, u64)> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut last_event_line = String::new();
        for line in reader.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            // 严格按"可解析 JSON 且含顶层 seq 数字字段"识别事件行。
            // 旧实现 line.contains("\"seq\"") 子串匹配：description 含 "sequence"
            // 的告警行会被误认成链尾，恢复出错误 prev_hash，哈希链从此静默断裂
            let is_event_line = serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .filter(|v| v.get("seq").and_then(|s| s.as_u64()).is_some())
                .is_some();
            if is_event_line {
                last_event_line = line;
            }
        }
        if last_event_line.is_empty() {
            return Ok((GENESIS_HASH.to_string(), 0));
        }
        let record: serde_json::Value = serde_json::from_str(&last_event_line)
            .map_err(|e| anyhow::anyhow!("最后记录 JSON 解析失败 — {}", e))?;
        let hash = record
            .get("hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("最后记录缺少 hash 字段"))?
            .to_string();
        let seq = record
            .get("seq")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| anyhow::anyhow!("最后记录缺少 seq 字段"))?;
        Ok((hash, seq))
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
        Ok(())
    }

    pub fn log_event(&mut self, event: &DecodedEvent) -> Result<()> {
        self.event_count += 1;

        let mut record = serde_json::json!({
            "seq": event.seq, "timestamp_ns": event.header.timestamp_ns,
            "event_type": event.header.event_type, "pid": event.header.pid,
            "tid": event.header.tid, "uid": event.header.uid, "ppid": event.header.ppid,
            "comm": event.comm, "syscall_nr": event.header.syscall_nr, "retval": event.header.retval,
        });

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
        self.alert_count += 1;
        let mut record = serde_json::to_value(alert)?;
        record["type"] = serde_json::Value::String("alert".to_string());

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
        self.last_flush_count = self.event_count;
        self.maybe_rotate()?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.last_flush_count = self.event_count;
        self.export_chain_head();
        Ok(())
    }

    /// 链尾哈希外落（文档缺口 #6"无链尾外报"）：每次 flush 把链尾 hash 追加
    /// 写到日志目录下的独立文件 chain_head.log。取证日志被整批删除/篡改时，
    /// 该文件仍保留可对照的哈希记录（replay 验证结果可与之外部比对）。
    /// 追加式且带时间戳，攻击者无法在不留痕迹的情况下"回填"历史链尾
    fn export_chain_head(&self) {
        let head_path = self.log_dir.join("chain_head.log");
        let line = format!(
            "{} seq={} hash={} file={}\n",
            chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            self.event_count,
            self.prev_hash,
            self.path.file_name().and_then(|n| n.to_str()).unwrap_or("?"),
        );
        let write_res = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&head_path)
            .and_then(|mut f| f.write_all(line.as_bytes()));
        if let Err(e) = write_res {
            // 外落失败不影响主取证链路
            log::debug!("chain_head 外落失败: {} — {}", head_path.display(), e);
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

    pub fn verify_chain(path: &PathBuf) -> Result<ChainVerification> {
        // 流式逐行校验：旧实现 read_to_string 把 100MB+ 整个日志读进内存
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut prev_hash = GENESIS_HASH.to_string();
        let mut total_records = 0u64;
        let mut broken_at: Option<u64> = None;
        let hasher = Sha256Hash;

        for line in reader.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            total_records += 1;

            let record: serde_json::Value = serde_json::from_str(&line)?;
            let stored_prev = record
                .get("prev_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let stored_hash = record.get("hash").and_then(|v| v.as_str()).unwrap_or("");

            if stored_prev != prev_hash && broken_at.is_none() {
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
        })
    }
}

#[derive(Debug)]
pub struct ChainVerification {
    pub total_records: u64,
    pub is_valid: bool,
    pub broken_at: Option<u64>,
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
    let output = File::create(dst)?;
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
    use ks_core::event::EventHeader;
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
        assert_eq!(sanitize_secret("ls -la --color=auto"), "ls -la --color=auto");
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
            let alert = ks_core::alert::Alert {
                id: uuid::Uuid::new_v4(),
                timestamp_ns: 123456789,
                severity: ks_core::rule::Severity::High,
                title: "test alert".to_string(),
                description: "desc".to_string(),
                rule_name: "test_rule".to_string(),
                process: ks_core::alert::ProcessInfo {
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
                mitre: Some(ks_core::alert::MitreInfo {
                    tactic: "TA0002".to_string(),
                    technique: "T1059".to_string(),
                    sub_technique: None,
                }),
                status: ks_core::alert::AlertStatus::New,
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
}

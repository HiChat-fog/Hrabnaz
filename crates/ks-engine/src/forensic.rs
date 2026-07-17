//! JSONL 格式取证日志，带 SHA-256 哈希链防篡改。
//! 支持自动轮转（按大小）+ gzip 归档 + 过期清理。

use crate::aggregator::DecodedEvent;
use anyhow::Result;
use ks_core::alert::Alert;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{read_dir, remove_file, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

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
    /// 创建日志记录器，若文件已存在则从末尾恢复哈希链
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

    /// 从已有日志恢复链尾哈希和事件计数
    /// 跳过 alert 记录（只有 event 记录才有 seq 字段）
    fn recover_chain_state(path: &PathBuf) -> Result<(String, u64)> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut last_event_line = String::new();
        for line in reader.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            // 只保留含 "seq" 的行（event 记录），跳过 alert 记录
            if line.contains("\"seq\"") {
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

    /// 当前文件超过 max_file_size 时做轮转：重命名 → 压缩 → 开新文件
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

        if self.rotation_config.compress_archives {
            let gzip_path = archive_path.with_extension("jsonl.gz");
            let src = archive_path.clone();
            std::thread::spawn(move || {
                if let Err(e) = compress_gzip(&src, &gzip_path) {
                    log::warn!("压缩归档失败: {} — {}", src.display(), e);
                } else {
                    let _ = remove_file(&src);
                    log::info!("归档已压缩: {}", gzip_path.display());
                }
            });
        }
        Ok(())
    }

    /// 记录事件
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

        // 用 BTreeMap 做序列化保证 key 排序一致，verify_chain 才不会因为 key 顺序不同报假错
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

    /// 记录告警
    pub fn log_alert(&mut self, alert: &Alert) -> Result<()> {
        self.alert_count += 1;
        let mut record = serde_json::to_value(alert)?;

        let json_str = serde_json::to_string(&record)?;
        let current_hash = self.hasher.hash(&json_str);

        record["prev_hash"] = serde_json::Value::String(self.prev_hash.clone());
        record["hash"] = serde_json::Value::String(current_hash.clone());
        record["type"] = serde_json::Value::String("alert".to_string());

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
        Ok(())
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

    /// 从头校验日志链完整性
    pub fn verify_chain(path: &PathBuf) -> Result<ChainVerification> {
        let content = std::fs::read_to_string(path)?;
        let mut prev_hash = GENESIS_HASH.to_string();
        let mut total_records = 0u64;
        let mut broken_at: Option<u64> = None;
        let hasher = Sha256Hash;

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            total_records += 1;

            let record: serde_json::Value = serde_json::from_str(line)?;
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

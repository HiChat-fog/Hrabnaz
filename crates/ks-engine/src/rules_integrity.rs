//! 规则文件完整性校验（H-1.5）。
//!
//! 威胁模型（ROADMAP H-1.5）：root 可篡改 YAML 把 enforce 改 audit——root 在威胁
//! 模型内是管理者，纵深上仍应有防线。做法是目录级指纹 + 部署方保管的基线比对：
//!
//! - `digest_rules_dir()`：`*.yml/*.yaml` 文件名排序后逐文件拼
//!   `"文件名\nsha256(内容)\n"` 再取一次 SHA-256。文件名参与指纹，删文件/加文件
//!   必然改变指纹；单文件改一个字节也改变指纹。
//! - `KS_RULES_DIGEST` 环境变量存部署基线（部署方用 `ks rules-digest` 生成），
//!   启动/热加载时不一致产生一条高severity审计告警写取证日志（哈希链内留痕）；
//!   `KS_RULES_DIGEST_STRICT=1` 时直接拒绝启动——由部署方按场景选软硬两种响应。
//! - 无论有无基线，每次检查都在取证日志目录追加 `rules_integrity.log` 快照
//!   （时间戳+指纹+逐文件哈希）：基线丢失时部署方仍有历史对照可回溯。

use anyhow::Result;
use ks_core::alert::Alert;
use ks_core::rule::Severity;
use sha2::{Digest, Sha256};
use std::path::Path;

pub struct RulesIntegrity {
    pub combined_digest: String,
    /// (文件名, 单文件 SHA-256)，文件名序
    pub files: Vec<(String, String)>,
}

pub enum RulesIntegrityVerdict {
    /// 未设置 KS_RULES_DIGEST（软模式：只落快照不比对）
    NoBaseline,
    Match,
    Mismatch {
        baseline: String,
        current: String,
    },
}

/// 目录规则集指纹。目录不存在/无规则文件时返回 Err（调用方决定是否 fatal）。
pub fn digest_rules_dir(dir: &Path) -> Result<RulesIntegrity> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        .collect();
    if names.is_empty() {
        anyhow::bail!("{} 下没有 .yml/.yaml 规则文件", dir.display());
    }
    names.sort();

    let mut hasher = Sha256::new();
    let mut files = Vec::new();
    for name in &names {
        let content = std::fs::read(dir.join(name))?;
        let mut h = Sha256::new();
        h.update(&content);
        let fhash = format!("{:x}", h.finalize());
        hasher.update(name.as_bytes());
        hasher.update(b"\n");
        hasher.update(fhash.as_bytes());
        hasher.update(b"\n");
        files.push((name.clone(), fhash));
    }

    Ok(RulesIntegrity {
        combined_digest: format!("{:x}", hasher.finalize()),
        files,
    })
}

/// 检查 + 落快照。比对的基线来自 `KS_RULES_DIGEST`。
/// 快照写入 `log_dir/rules_integrity.log`（追加式，带时间戳）。
pub fn check_and_record(
    rules_dir: &Path,
    log_dir: &Path,
) -> Result<(RulesIntegrity, RulesIntegrityVerdict)> {
    let integrity = digest_rules_dir(rules_dir)?;

    let verdict = match std::env::var("KS_RULES_DIGEST") {
        Err(_) => RulesIntegrityVerdict::NoBaseline,
        Ok(baseline) if baseline == integrity.combined_digest => RulesIntegrityVerdict::Match,
        Ok(baseline) => RulesIntegrityVerdict::Mismatch {
            baseline,
            current: integrity.combined_digest.clone(),
        },
    };

    append_snapshot(log_dir, &integrity, &verdict);
    Ok((integrity, verdict))
}

/// 基线不一致时生成审计告警（写取证哈希链留痕，规则名固定 rules_integrity_mismatch）
pub fn mismatch_alert(verdict: &RulesIntegrityVerdict) -> Option<Alert> {
    let RulesIntegrityVerdict::Mismatch { baseline, current } = verdict else {
        return None;
    };
    let mut alert = Alert::new(
        Severity::High,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
        "规则集完整性校验失败: 规则文件与部署基线不一致".to_string(),
        "rules_integrity_mismatch".to_string(),
        ks_core::alert::ProcessInfo {
            pid: std::process::id(),
            ppid: 0,
            comm: "kernelsentinel".to_string(),
            uid: 0,
            exe_path: None,
            cmdline: None,
        },
    );
    alert.description = format!(
        "规则文件内容与 KS_RULES_DIGEST 基线不一致 (基线={} 当前={})。\
         可能是运维正常变更，也可能是规则被篡改（enforce 被降级为 audit）。\
         正常变更请更新部署基线并重启。",
        &baseline[..baseline.len().min(16)],
        &current[..current.len().min(16)],
    );
    alert.mitre = Some(ks_core::alert::MitreInfo {
        tactic: "TA0005".to_string(),
        technique: "T1562.001".to_string(),
        sub_technique: None,
    });
    Some(alert)
}

fn append_snapshot(log_dir: &Path, integrity: &RulesIntegrity, verdict: &RulesIntegrityVerdict) {
    let path = log_dir.join("rules_integrity.log");
    let stamp = chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let verdict_str = match verdict {
        RulesIntegrityVerdict::NoBaseline => "no-baseline",
        RulesIntegrityVerdict::Match => "match",
        RulesIntegrityVerdict::Mismatch { .. } => "MISMATCH",
    };
    let mut line = format!(
        "{} verdict={} digest={} files={}\n",
        stamp,
        verdict_str,
        integrity.combined_digest,
        integrity.files.len()
    );
    for (name, hash) in &integrity.files {
        line.push_str(&format!("  {hash}  {name}\n"));
    }
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_rule(dir: &Path, name: &str, content: &str) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[test]
    fn test_digest_stable_and_content_sensitive() {
        let dir = TempDir::new().unwrap();
        write_rule(dir.path(), "a.yml", "- name: a\n  severity: high\n");
        write_rule(dir.path(), "b.yml", "- name: b\n  severity: low\n");
        let d1 = digest_rules_dir(dir.path()).unwrap();
        let d2 = digest_rules_dir(dir.path()).unwrap();
        assert_eq!(d1.combined_digest, d2.combined_digest, "同一目录指纹应稳定");
        assert_eq!(d1.files.len(), 2);
        assert_eq!(d1.files[0].0, "a.yml");

        // 改一个字节 → 指纹变
        write_rule(dir.path(), "a.yml", "- name: a\n  severity: critical\n");
        let d3 = digest_rules_dir(dir.path()).unwrap();
        assert_ne!(d1.combined_digest, d3.combined_digest);

        // 删一个文件 → 指纹变（文件名参与指纹）
        std::fs::remove_file(dir.path().join("b.yml")).unwrap();
        let d4 = digest_rules_dir(dir.path()).unwrap();
        assert_ne!(d1.combined_digest, d4.combined_digest);
    }

    #[test]
    fn test_digest_file_rename_changes_fingerprint() {
        let dir = TempDir::new().unwrap();
        write_rule(dir.path(), "a.yml", "- name: a\n");
        let d1 = digest_rules_dir(dir.path()).unwrap();
        std::fs::rename(dir.path().join("a.yml"), dir.path().join("renamed.yml")).unwrap();
        let d2 = digest_rules_dir(dir.path()).unwrap();
        assert_ne!(d1.combined_digest, d2.combined_digest, "重命名应改变指纹");
    }

    #[test]
    fn test_digest_empty_dir_is_error() {
        let dir = TempDir::new().unwrap();
        assert!(digest_rules_dir(dir.path()).is_err());
    }

    #[test]
    fn test_check_and_record_baseline_flow() {
        let rules = TempDir::new().unwrap();
        let logs = TempDir::new().unwrap();
        write_rule(rules.path(), "r.yml", "- name: r\n");
        let (integrity, _) = check_and_record(rules.path(), logs.path()).unwrap();

        // 无基线
        std::env::remove_var("KS_RULES_DIGEST");
        let (_, v) = check_and_record(rules.path(), logs.path()).unwrap();
        assert!(matches!(v, RulesIntegrityVerdict::NoBaseline));

        // 基线一致
        std::env::set_var("KS_RULES_DIGEST", &integrity.combined_digest);
        let (_, v) = check_and_record(rules.path(), logs.path()).unwrap();
        assert!(matches!(v, RulesIntegrityVerdict::Match));

        // 基线不一致
        std::env::set_var("KS_RULES_DIGEST", "deadbeef");
        let (_, v) = check_and_record(rules.path(), logs.path()).unwrap();
        let RulesIntegrityVerdict::Mismatch { baseline, .. } = &v else {
            panic!("应为 Mismatch");
        };
        assert_eq!(baseline, "deadbeef");
        assert!(mismatch_alert(&v).is_some(), "Mismatch 应产出审计告警");
        std::env::remove_var("KS_RULES_DIGEST");

        // 快照已落盘
        let snapshot = std::fs::read_to_string(logs.path().join("rules_integrity.log")).unwrap();
        assert!(snapshot.contains("verdict=no-baseline"));
        assert!(snapshot.contains("verdict=match"));
        assert!(snapshot.contains("verdict=MISMATCH"));
    }
}

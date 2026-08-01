use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// 配置来源优先级:CLI > KS_*环境变量 > YAML配置文件 > 内置默认值。
/// 绝大多数情况默认值就能跑,生产环境再上配置文件。
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub engine: EngineConfig,
    #[serde(default)]
    pub detection: DetectionConfig,
    #[serde(default)]
    pub forensic: ForensicConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub performance: PerformanceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_engine_buffer_size")]
    pub buffer_size: usize,
    #[serde(default = "default_engine_ring_buffer_size_kb")]
    pub ring_buffer_size_kb: u32,
    #[serde(default = "default_engine_batch_size")]
    pub batch_size: u32,
}

fn default_engine_buffer_size() -> usize {
    10_000
}
fn default_engine_ring_buffer_size_kb() -> u32 {
    256
}
fn default_engine_batch_size() -> u32 {
    64
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            buffer_size: default_engine_buffer_size(),
            ring_buffer_size_kb: default_engine_ring_buffer_size_kb(),
            batch_size: default_engine_batch_size(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    #[serde(default = "default_detection_rules_dir")]
    pub rules_dir: String,
    #[serde(default = "default_detection_anomaly_threshold")]
    pub anomaly_threshold: f64,
    #[serde(default = "default_detection_kernel_inference")]
    pub kernel_inference: bool,
    /// 是否启用内核态阻断(默认false防误杀)
    #[serde(default = "default_detection_block_enabled")]
    pub block_enabled: bool,
    /// 阻断TTL(秒,默认300)
    #[serde(default = "default_detection_block_ttl_secs")]
    pub block_ttl_secs: u64,
    /// 触发阻断的严重度阈值(critical、high、medium)
    #[serde(default = "default_detection_block_severity_threshold")]
    pub block_severity_threshold: String,
}

fn default_detection_block_enabled() -> bool {
    false
}
fn default_detection_block_ttl_secs() -> u64 {
    300
}
fn default_detection_block_severity_threshold() -> String {
    "critical".to_string()
}

fn default_detection_rules_dir() -> String {
    "/etc/ks/rules/".to_string()
}
fn default_detection_anomaly_threshold() -> f64 {
    0.7
}
fn default_detection_kernel_inference() -> bool {
    true
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            rules_dir: default_detection_rules_dir(),
            anomaly_threshold: default_detection_anomaly_threshold(),
            kernel_inference: default_detection_kernel_inference(),
            block_enabled: default_detection_block_enabled(),
            block_ttl_secs: default_detection_block_ttl_secs(),
            block_severity_threshold: default_detection_block_severity_threshold(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicConfig {
    #[serde(default = "default_forensic_log_dir")]
    pub log_dir: String,
    #[serde(default = "default_forensic_max_log_size_mb")]
    pub max_log_size_mb: u32,
    #[serde(default = "default_forensic_retention_days")]
    pub retention_days: u32,
    #[serde(default = "default_forensic_hash_chain")]
    pub hash_chain: bool,
}

fn default_forensic_log_dir() -> String {
    "/var/log/ks/".to_string()
}
fn default_forensic_max_log_size_mb() -> u32 {
    100
}
fn default_forensic_retention_days() -> u32 {
    30
}
fn default_forensic_hash_chain() -> bool {
    true
}

impl Default for ForensicConfig {
    fn default() -> Self {
        Self {
            log_dir: default_forensic_log_dir(),
            max_log_size_mb: default_forensic_max_log_size_mb(),
            retention_days: default_forensic_retention_days(),
            hash_chain: default_forensic_hash_chain(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_network_serve_port")]
    pub serve_port: u16,
    #[serde(default = "default_network_bind_address")]
    pub bind_address: String,
    #[serde(default = "default_network_ws_enabled")]
    pub ws_enabled: bool,
}

fn default_network_serve_port() -> u16 {
    3000
}
fn default_network_bind_address() -> String {
    "127.0.0.1".to_string()
}
fn default_network_ws_enabled() -> bool {
    true
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            serve_port: default_network_serve_port(),
            bind_address: default_network_bind_address(),
            ws_enabled: default_network_ws_enabled(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    #[serde(default = "default_performance_cpu_affinity")]
    pub cpu_affinity: String,
    #[serde(default = "default_performance_max_cpu_percent")]
    pub max_cpu_percent: u32,
    #[serde(default = "default_performance_memory_limit_mb")]
    pub memory_limit_mb: u32,
}

fn default_performance_cpu_affinity() -> String {
    "auto".to_string()
}
fn default_performance_max_cpu_percent() -> u32 {
    5
}
fn default_performance_memory_limit_mb() -> u32 {
    128
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            cpu_affinity: default_performance_cpu_affinity(),
            max_cpu_percent: default_performance_max_cpu_percent(),
            memory_limit_mb: default_performance_memory_limit_mb(),
        }
    }
}

impl Config {
    pub fn load_from_file(path: &Path) -> Result<Self> {
        if !path.exists() {
            log::info!("配置文件不存在，使用默认配置: {}", path.display());
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        Self::load_from_yaml(&content)
    }

    pub fn load_from_yaml(content: &str) -> Result<Self> {
        let config: Self = serde_yaml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// 环境变量覆盖:KS_<SECTION>_<KEY>,比如KS_ENGINE_BUFFER_SIZE=20000
    pub fn apply_env_overrides(&mut self) -> &mut Self {
        if let Ok(v) = std::env::var("KS_ENGINE_BUFFER_SIZE") {
            if let Ok(parsed) = v.parse::<usize>() {
                self.engine.buffer_size = parsed;
            } else {
                log::warn!("KS_ENGINE_BUFFER_SIZE 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_ENGINE_RING_BUFFER_SIZE_KB") {
            if let Ok(parsed) = v.parse::<u32>() {
                self.engine.ring_buffer_size_kb = parsed;
            } else {
                log::warn!("KS_ENGINE_RING_BUFFER_SIZE_KB 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_ENGINE_BATCH_SIZE") {
            if let Ok(parsed) = v.parse::<u32>() {
                self.engine.batch_size = parsed;
            } else {
                log::warn!("KS_ENGINE_BATCH_SIZE 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_DETECTION_ANOMALY_THRESHOLD") {
            if let Ok(parsed) = v.parse::<f64>() {
                self.detection.anomaly_threshold = parsed;
            } else {
                log::warn!("KS_DETECTION_ANOMALY_THRESHOLD 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_DETECTION_RULES_DIR") {
            self.detection.rules_dir = v;
        }
        if let Ok(v) = std::env::var("KS_DETECTION_KERNEL_INFERENCE") {
            if let Ok(parsed) = v.parse::<bool>() {
                self.detection.kernel_inference = parsed;
            } else {
                log::warn!("KS_DETECTION_KERNEL_INFERENCE 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_DETECTION_BLOCK_ENABLED") {
            if let Ok(parsed) = v.parse::<bool>() {
                self.detection.block_enabled = parsed;
            } else {
                log::warn!("KS_DETECTION_BLOCK_ENABLED 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_DETECTION_BLOCK_TTL_SECS") {
            if let Ok(parsed) = v.parse::<u64>() {
                self.detection.block_ttl_secs = parsed;
            } else {
                log::warn!("KS_DETECTION_BLOCK_TTL_SECS 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_DETECTION_BLOCK_SEVERITY_THRESHOLD") {
            self.detection.block_severity_threshold = v;
        }
        if let Ok(v) = std::env::var("KS_FORENSIC_LOG_DIR") {
            self.forensic.log_dir = v;
        }
        if let Ok(v) = std::env::var("KS_FORENSIC_RETENTION_DAYS") {
            if let Ok(parsed) = v.parse::<u32>() {
                self.forensic.retention_days = parsed;
            } else {
                log::warn!("KS_FORENSIC_RETENTION_DAYS 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_FORENSIC_MAX_LOG_SIZE_MB") {
            if let Ok(parsed) = v.parse::<u32>() {
                self.forensic.max_log_size_mb = parsed;
            } else {
                log::warn!("KS_FORENSIC_MAX_LOG_SIZE_MB 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_FORENSIC_HASH_CHAIN") {
            if let Ok(parsed) = v.parse::<bool>() {
                self.forensic.hash_chain = parsed;
            } else {
                log::warn!("KS_FORENSIC_HASH_CHAIN 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_NETWORK_SERVE_PORT") {
            if let Ok(parsed) = v.parse::<u16>() {
                self.network.serve_port = parsed;
            } else {
                log::warn!("KS_NETWORK_SERVE_PORT 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_NETWORK_BIND_ADDRESS") {
            self.network.bind_address = v;
        }
        if let Ok(v) = std::env::var("KS_NETWORK_WS_ENABLED") {
            if let Ok(parsed) = v.parse::<bool>() {
                self.network.ws_enabled = parsed;
            } else {
                log::warn!("KS_NETWORK_WS_ENABLED 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_PERFORMANCE_CPU_AFFINITY") {
            self.performance.cpu_affinity = v;
        }
        if let Ok(v) = std::env::var("KS_PERFORMANCE_MAX_CPU_PERCENT") {
            if let Ok(parsed) = v.parse::<u32>() {
                self.performance.max_cpu_percent = parsed;
            } else {
                log::warn!("KS_PERFORMANCE_MAX_CPU_PERCENT 解析失败: '{}'", v);
            }
        }
        if let Ok(v) = std::env::var("KS_PERFORMANCE_MEMORY_LIMIT_MB") {
            if let Ok(parsed) = v.parse::<u32>() {
                self.performance.memory_limit_mb = parsed;
            } else {
                log::warn!("KS_PERFORMANCE_MEMORY_LIMIT_MB 解析失败: '{}'", v);
            }
        }
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.engine.buffer_size < 1000 || self.engine.buffer_size > 100_000 {
            anyhow::bail!(
                "engine.buffer_size 必须在 1000~100000 之间，当前值: {}",
                self.engine.buffer_size
            );
        }
        if self.engine.ring_buffer_size_kb < 64 || self.engine.ring_buffer_size_kb > 1024 {
            anyhow::bail!(
                "engine.ring_buffer_size_kb 必须在 64~1024 之间，当前值: {}",
                self.engine.ring_buffer_size_kb
            );
        }
        if self.engine.batch_size < 1 || self.engine.batch_size > 256 {
            anyhow::bail!(
                "engine.batch_size 必须在 1~256 之间，当前值: {}",
                self.engine.batch_size
            );
        }
        if self.detection.anomaly_threshold < 0.0 || self.detection.anomaly_threshold > 1.0 {
            anyhow::bail!(
                "detection.anomaly_threshold 必须在 0.0~1.0 之间，当前值: {}",
                self.detection.anomaly_threshold
            );
        }
        if self.forensic.retention_days < 1 || self.forensic.retention_days > 365 {
            anyhow::bail!(
                "forensic.retention_days 必须在 1~365 之间，当前值: {}",
                self.forensic.retention_days
            );
        }
        if self.forensic.max_log_size_mb < 10 || self.forensic.max_log_size_mb > 1000 {
            anyhow::bail!(
                "forensic.max_log_size_mb 必须在 10~1000 之间，当前值: {}",
                self.forensic.max_log_size_mb
            );
        }
        if self.network.serve_port < 1 {
            anyhow::bail!(
                "network.serve_port 必须在 1~65535 之间，当前值: {}",
                self.network.serve_port
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.engine.buffer_size, 10_000);
        assert_eq!(config.detection.anomaly_threshold, 0.7);
        assert_eq!(config.forensic.retention_days, 30);
    }

    #[test]
    fn test_config_validation_valid() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_invalid_buffer_size() {
        let mut config = Config::default();
        config.engine.buffer_size = 50;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_load_from_yaml() {
        let yaml = r#"
engine:
  buffer_size: 20000
  ring_buffer_size_kb: 512
detection:
  anomaly_threshold: 0.8
forensic:
  retention_days: 60
"#;
        let config = Config::load_from_yaml(yaml).unwrap();
        assert_eq!(config.engine.buffer_size, 20000);
    }

    #[test]
    fn test_config_env_overrides() {
        let mut config = Config::default();
        std::env::set_var("KS_ENGINE_BUFFER_SIZE", "20000");
        config.apply_env_overrides();
        assert_eq!(config.engine.buffer_size, 20000);
        std::env::remove_var("KS_ENGINE_BUFFER_SIZE");
    }

    #[test]
    fn test_config_load_from_file() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("config.yml");
        let yaml = "engine:\n  buffer_size: 50000\n";
        std::fs::write(&config_path, yaml).unwrap();
        let config = Config::load_from_file(&config_path).unwrap();
        assert_eq!(config.engine.buffer_size, 50000);
    }

    #[test]
    fn test_config_file_not_found() {
        let config = Config::load_from_file(Path::new("/nonexistent/config.yml")).unwrap();
        assert_eq!(config.engine.buffer_size, 10_000);
    }
}

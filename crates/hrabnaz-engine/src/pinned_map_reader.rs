#![cfg(target_os = "linux")]

//! ⚠ 已退役消费者（2026-10-17）：本实现是为 C loader（NOBTF tier）接入
//! `BpfMapReader` 契约而做的第二实现，随 C loader 退役已无激活调用。
//! **保留为参考**，因为它是"进程外加载器如何满足 map 契约"的可运行样本：
//! bpffs pin + 字节级布局，进程不参与契约。未来的内核下沉 runtime 属于同一
//! 形态（加载方持有 fd、用户态跨进程访问），可直接复用本模式与单元测试。
//!
//! 经 bpffs pin 访问契约 map 的读取器——`BpfMapReader` 的第二个实现。
//!
//! aya 路径持有加载后的 map 句柄直接读写；C loader（hrabnaz_loader，NOBTF tier）
//! 是独立进程，map fd 在它手里，唯一跨进程通道是 bpffs pin：
//! `hrabnaz_loader` 启动时把契约 map pin 到 `/sys/fs/bpf/hrabnaz_<map>`，
//! 本模块按同一路径打开，实现与 aya 路径完全相同的 `BpfMapReader` 契约
//! （含阻断裁决的写/删/读/pin）。map 是契约，进程不是。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use aya::maps::{Map, MapData};
use serde_json::Value;

use crate::linux_map_reader::{
    map_data_ref, map_type_str, pin_block_map_to, read_block_decisions_from, read_entries,
    remove_block_decision_map, write_block_decision_map, SHARED_MAPS,
};
use crate::loader::{BpfMapReader, MapSnapshot, MapStat};

/// C loader 的 pin 前缀（与 hrabnaz_loader.c 的 `pin_contract_maps` 对齐）
pub const PIN_PREFIX: &str = "/sys/fs/bpf/hrabnaz_";

pub struct PinnedBpfMapReader {
    prefix: String,
}

impl Default for PinnedBpfMapReader {
    fn default() -> Self {
        Self::new()
    }
}

impl PinnedBpfMapReader {
    pub fn new() -> Self {
        Self {
            prefix: PIN_PREFIX.to_string(),
        }
    }

    pub fn path_for(&self, map_name: &str) -> PathBuf {
        PathBuf::from(format!("{}{}", self.prefix, map_name))
    }

    /// 打开一个 pinned map。类型由契约表决定（与 hrabnaz_loader.c 的 known_maps 对齐）。
    fn open_map(&self, map_name: &str) -> Result<Map> {
        let path = self.path_for(map_name);
        let md = MapData::from_pin(&path).with_context(|| {
            format!(
                "打开 pin {} 失败（C loader 未运行或 /sys/fs/bpf 未挂载）",
                path.display()
            )
        })?;
        Ok(match map_name {
            "infer_config" => Map::Array(md),
            // block_decisions / risk_scores / ip_whitelist / net_conn_history /
            // freq_counters / protected_comms 都是 HASH（见 hrabnaz_loader.c known_maps）
            _ => Map::HashMap(md),
        })
    }

    fn open_block_map(&self) -> Result<Map> {
        self.open_map("block_decisions")
    }

    /// C loader 是异步子进程：轮询等待 pin 就绪（上限 `timeout`）。
    /// 返回 None = bpffs 不可用或 loader 没 pin 出去 —— 调用方应降级为
    /// "仅检测"，并保留明确日志，不静默假装阻断可用。
    pub fn wait_ready(timeout: Duration) -> Option<Self> {
        let reader = Self::new();
        let deadline = Instant::now() + timeout;
        loop {
            if reader.open_block_map().is_ok() {
                return Some(reader);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl BpfMapReader for PinnedBpfMapReader {
    fn read_map(&self, map_name: &str) -> anyhow::Result<MapSnapshot> {
        let map = self.open_map(map_name)?;
        let md = map_data_ref(&map);
        let map_type = md
            .info()
            .ok()
            .and_then(|i| i.map_type().ok())
            .map(map_type_str)
            .unwrap_or("UNKNOWN");
        let (count, _) = read_entries(map_name, &map);
        Ok(MapSnapshot {
            name: map_name.to_string(),
            map_type: map_type.to_string(),
            entry_count: count,
            entries: vec![],
        })
    }

    fn read_map_structured(&self, map_name: &str) -> Vec<Value> {
        match self.open_map(map_name) {
            Ok(map) => read_entries(map_name, &map).1,
            Err(_) => Vec::new(),
        }
    }

    fn list_maps(&self) -> Vec<String> {
        SHARED_MAPS.iter().map(|s| s.to_string()).collect()
    }

    fn list_map_stats(&self) -> Vec<MapStat> {
        SHARED_MAPS
            .iter()
            .map(|&name| match self.read_map(name) {
                Ok(snap) => MapStat {
                    name: snap.name,
                    map_type: snap.map_type,
                    entry_count: snap.entry_count,
                },
                Err(_) => MapStat {
                    name: name.to_string(),
                    map_type: "UNKNOWN".to_string(),
                    entry_count: 0,
                },
            })
            .collect()
    }

    fn write_block_decision(
        &self,
        pid: u32,
        expire_monotonic_ns: u64,
        reason: u8,
    ) -> anyhow::Result<()> {
        let mut map = self.open_block_map()?;
        write_block_decision_map(&mut map, pid, expire_monotonic_ns, reason)
    }

    fn remove_block_decision(&self, pid: u32) -> anyhow::Result<()> {
        let mut map = self.open_block_map()?;
        remove_block_decision_map(&mut map, pid)
    }

    fn read_block_decisions(&self) -> Vec<(u32, u64, u8)> {
        match self.open_block_map() {
            Ok(map) => read_block_decisions_from(&map),
            Err(_) => Vec::new(),
        }
    }

    /// loader 已 pin 在契约路径。若调用方要求同一路径：校验可达即成功；
    /// 要求别的路径：从 pin 打开的 fd 再 pin 一份（内核允许同一 map 多处 pin）。
    fn pin_block_map(&self, path: &str) -> anyhow::Result<()> {
        let map = self.open_block_map()?;
        let current = self.path_for("block_decisions");
        if current == Path::new(path) {
            return Ok(());
        }
        pin_block_map_to(&map, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_paths_follow_the_loader_contract() {
        let r = PinnedBpfMapReader::new();
        assert_eq!(
            r.path_for("block_decisions"),
            PathBuf::from("/sys/fs/bpf/hrabnaz_block_decisions")
        );
        assert_eq!(
            r.path_for("infer_config"),
            PathBuf::from("/sys/fs/bpf/hrabnaz_infer_config")
        );
    }

    /// pin 前缀必须与 hrabnaz_loader.c 的 `pin_contract_maps()` 逐字节一致——
    /// 两边各写一份字符串，测试把契约钉死
    #[test]
    fn pin_prefix_matches_c_loader_expectation() {
        assert_eq!(PIN_PREFIX, "/sys/fs/bpf/hrabnaz_");
        // 与 engine 阻断通道常量拼接结果一致（ks block 打开同一路径）
        assert_eq!(
            format!("{}{}", PIN_PREFIX, "block_decisions"),
            crate::blocker::BLOCK_DECISIONS_PIN
        );
    }

    #[test]
    fn shared_map_list_is_the_reader_contract() {
        let r = PinnedBpfMapReader::new();
        assert_eq!(r.list_maps().len(), SHARED_MAPS.len());
        assert!(r.list_maps().iter().any(|m| m == "risk_scores"));
    }

    /// 没有 C loader 在跑时应快速返回 None（不 panic、不阻塞）
    #[test]
    fn wait_ready_times_out_without_loader() {
        let t0 = Instant::now();
        let r = PinnedBpfMapReader::wait_ready(Duration::from_millis(100));
        assert!(r.is_none(), "无 pin 时 wait_ready 必须返回 None");
        assert!(t0.elapsed() < Duration::from_secs(2));
    }
}

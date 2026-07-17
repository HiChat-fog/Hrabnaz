//! LinuxBpfMapReader — 通过 aya::Ebpf 真实读取 BPF map 统计信息。
//!
//! Phase E1.2：用真实 LinuxBpfMapReader 替换 MockBpfMapReader，让 /api/v1/stats
//! 端点能暴露 BPF map 真实统计（map_type + entry_count）。
//!
//! ## 设计
//!
//! - 持有 `Arc<Mutex<aya::Ebpf>>` 引用，与 `EbpfLoader` 共享同一个 Ebpf 实例。
//!   `EbpfLoader` 在 `start_all` 末尾把 bpf 包成 `Arc<Mutex>`，并通过 `map_reader()`
//!   暴露一个克隆给调用方。
//! - 5 个事件 map（events/tree_events/freq_events/flow_events/filter_events）已被
//!   `take_map` 移走，不在此读取；只读 5 个共享 map：
//!     risk_scores / ip_whitelist / net_conn_history / freq_counters / infer_config
//!
//! ## 实现现状
//!
//! - `list_map_stats()`：通过 `MapData::info()` 读取真实 `map_type` 和 `max_entries`。
//!   - ARRAY / PERCPU_ARRAY：`max_entries` == 实际 entry 数（所有槽位始终存在）。
//!   - HASH / LRU_HASH：`max_entries` 是容量上限，实际 entry 数需 `iter().count()`
//!     （TODO：需要按 map 名匹配 K/V 类型构造 `aya::maps::HashMap<K,V>`）。
//! - `read_map()`：返回真实 `map_type`，但 `entries` 为空（同上 TODO）。
//!
//! ## aya API 扩展点
//!
//! 真实读取 entries 见 `aya::maps::HashMap::<&MapData, K, V>::try_from(md).iter()`，
//! 需要按 map 名硬编码 K/V 类型（如 risk_scores: (u32, u64)）。当前仅返回统计信息，
//! 不阻塞 E1.3 集成测试和 E1.4 端到端脚本。

#![cfg(target_os = "linux")]

use std::sync::{Arc, Mutex};

use crate::loader::{BpfMapReader, MapSnapshot, MapStat};

/// 5 个共享 map（事件 map 已被 `take_map` 移走，不在此读取）。
/// 顺序与 `MockBpfMapReader::list_map_stats()` 保持一致，便于前端兼容。
const SHARED_MAPS: &[&str] = &[
    "risk_scores",
    "ip_whitelist",
    "net_conn_history",
    "freq_counters",
    "infer_config",
];

/// 真实 BPF map 读取器 — 持有 `Arc<Mutex<aya::Ebpf>>` 共享 Ebpf 实例。
///
/// 线程安全：`Arc<Mutex<Ebpf>>` 是 Send+Sync（因 `aya::Ebpf` 是 Send），
/// 满足 `BpfMapReader: Send + Sync` supertrait 要求。
pub struct LinuxBpfMapReader {
    bpf: Arc<Mutex<aya::Ebpf>>,
}

impl LinuxBpfMapReader {
    pub fn new(bpf: Arc<Mutex<aya::Ebpf>>) -> Self {
        Self { bpf }
    }

    /// 从 `aya::maps::Map` enum 提取内部 `&MapData` 引用。
    ///
    /// `Map` 的每个 variant 都恰好包裹一个 `MapData`，用 `|` 模式合并所有分支。
    /// 若 aya 未来新增 variant，编译器会在 `match` 穷尽性检查时报错，迫使我们更新。
    fn map_data_ref(map: &aya::maps::Map) -> &aya::maps::MapData {
        match map {
            aya::maps::Map::Array(md)
            | aya::maps::Map::ArrayOfMaps(md)
            | aya::maps::Map::BloomFilter(md)
            | aya::maps::Map::CgroupArray(md)
            | aya::maps::Map::CgroupStorage(md)
            | aya::maps::Map::CgrpStorage(md)
            | aya::maps::Map::CpuMap(md)
            | aya::maps::Map::DevMap(md)
            | aya::maps::Map::DevMapHash(md)
            | aya::maps::Map::HashMap(md)
            | aya::maps::Map::HashOfMaps(md)
            | aya::maps::Map::InodeStorage(md)
            | aya::maps::Map::LpmTrie(md)
            | aya::maps::Map::LruHashMap(md)
            | aya::maps::Map::PerCpuArray(md)
            | aya::maps::Map::PerCpuCgroupStorage(md)
            | aya::maps::Map::PerCpuHashMap(md)
            | aya::maps::Map::PerCpuLruHashMap(md)
            | aya::maps::Map::PerfEventArray(md)
            | aya::maps::Map::ProgramArray(md)
            | aya::maps::Map::Queue(md)
            | aya::maps::Map::ReusePortSockArray(md)
            | aya::maps::Map::RingBuf(md)
            | aya::maps::Map::SockHash(md)
            | aya::maps::Map::SockMap(md)
            | aya::maps::Map::SkStorage(md)
            | aya::maps::Map::Stack(md)
            | aya::maps::Map::StackTraceMap(md)
            | aya::maps::Map::Unsupported(md)
            | aya::maps::Map::XskMap(md) => md,
            // 穷尽匹配：aya 新增 variant 时编译器报错，避免静默漏处理。
        }
    }

    /// 将 `aya::maps::MapType` 转为前端可读的字符串标签。
    fn map_type_str(t: aya::maps::MapType) -> &'static str {
        match t {
            aya::maps::MapType::Hash => "HASH",
            aya::maps::MapType::Array => "ARRAY",
            aya::maps::MapType::LruHash => "LRU_HASH",
            aya::maps::MapType::PerCpuArray => "PERCPU_ARRAY",
            aya::maps::MapType::PerCpuHash => "PERCPU_HASH",
            aya::maps::MapType::LruPerCpuHash => "LRU_PERCPU_HASH",
            aya::maps::MapType::LpmTrie => "LPM_TRIE",
            aya::maps::MapType::RingBuf => "RINGBUF",
            aya::maps::MapType::PerfEventArray => "PERF_EVENT_ARRAY",
            aya::maps::MapType::ProgramArray => "PROG_ARRAY",
            aya::maps::MapType::SockMap => "SOCKMAP",
            aya::maps::MapType::SockHash => "SOCKHASH",
            aya::maps::MapType::Queue => "QUEUE",
            aya::maps::MapType::Stack => "STACK",
            aya::maps::MapType::BloomFilter => "BLOOM_FILTER",
            aya::maps::MapType::CpuMap => "CPUMAP",
            aya::maps::MapType::DevMap => "DEVMAP",
            aya::maps::MapType::DevMapHash => "DEVMAP_HASH",
            aya::maps::MapType::XskMap => "XSKMAP",
            aya::maps::MapType::StackTrace => "STACK_TRACE",
            aya::maps::MapType::CgroupArray => "CGROUP_ARRAY",
            aya::maps::MapType::CgroupStorage => "CGROUP_STORAGE",
            aya::maps::MapType::PerCpuCgroupStorage => "PERCPU_CGROUP_STORAGE",
            aya::maps::MapType::ReuseportSockArray => "REUSEPORT_SOCKARRAY",
            aya::maps::MapType::SkStorage => "SK_STORAGE",
            aya::maps::MapType::InodeStorage => "INODE_STORAGE",
            aya::maps::MapType::CgrpStorage => "CGRP_STORAGE",
            aya::maps::MapType::TaskStorage => "TASK_STORAGE",
            aya::maps::MapType::ArrayOfMaps => "ARRAY_OF_MAPS",
            aya::maps::MapType::HashOfMaps => "HASH_OF_MAPS",
            aya::maps::MapType::UserRingBuf => "USER_RINGBUF",
            aya::maps::MapType::StructOps => "STRUCT_OPS",
            aya::maps::MapType::Arena => "ARENA",
            aya::maps::MapType::Unspecified => "UNSPEC",
            // MapType 是 #[non_exhaustive]，aya 新增 variant 时走此分支。
            _ => "OTHER",
        }
    }
}

impl BpfMapReader for LinuxBpfMapReader {
    fn read_map(&self, map_name: &str) -> anyhow::Result<MapSnapshot> {
        // 通过 aya 真实读取 map_type；entries 暂不实现（需要按 map 名匹配 K/V 类型）。
        // TODO: 实现 entries 读取 — aya::maps::HashMap::<&MapData, K, V>::try_from(md).iter()
        let bpf = self.bpf.lock().expect("Ebpf Mutex 中毒");
        let map_type_str = bpf
            .map(map_name)
            .map(Self::map_data_ref)
            .and_then(|md| md.info().ok())
            .and_then(|info| info.map_type().ok())
            .map(Self::map_type_str)
            .unwrap_or("unknown");
        Ok(MapSnapshot {
            name: map_name.to_string(),
            map_type: map_type_str.to_string(),
            entry_count: 0,
            entries: vec![],
        })
    }

    /// G2.4: 真实读取 map entries（按 map 名分发 typed reader）。
    /// 真机阶段补全：risk_scores 等 map 的 typed reading 需用 aya::maps::HashMap
    /// （aya 0.14 借用语义需 take_map owned MapData，当前 EbpfLoader.bpf 是
    ///  Arc<Mutex<Ebpf>> 仅能 bpf.map(name) 借用，需重构 EbpfLoader 暴露 owned
    ///  map clone 或改用 aya Ebpf::map_mut()）。
    /// MockBpfMapReader 提供完整桩数据用于 CI 测试。
    fn read_map_structured(&self, map_name: &str) -> Vec<serde_json::Value> {
        let bpf = self.bpf.lock().expect("Ebpf Mutex 中毒");
        let md = match bpf.map(map_name).map(Self::map_data_ref) {
            Some(md) => md,
            None => return Vec::new(),
        };
        log::debug!(
            "map '{}' (type={:?}) typed reading 待真机阶段补全",
            map_name,
            md.info().and_then(|i| i.map_type()).ok()
        );
        Vec::new()
    }

    fn list_maps(&self) -> Vec<String> {
        SHARED_MAPS.iter().map(|s| s.to_string()).collect()
    }

    fn list_map_stats(&self) -> Vec<MapStat> {
        let bpf = self.bpf.lock().expect("Ebpf Mutex 中毒");
        SHARED_MAPS
            .iter()
            .filter_map(|&name| {
                let map = bpf.map(name)?;
                let md = Self::map_data_ref(map);
                match md.info() {
                    Ok(info) => {
                        let map_type_str =
                            info.map_type().map(Self::map_type_str).unwrap_or("UNKNOWN");
                        // max_entries 是 map 容量上限：
                        // - ARRAY / PERCPU_ARRAY：max_entries == 实际 entry 数
                        //   （所有槽位始终存在，无"空槽"概念）
                        // - HASH / LRU_HASH：max_entries 是容量上限，
                        //   实际 entry 数需 iter().count()。
                        //   TODO: 对 HASH map 实现 iter().count() 真实计数
                        //   （需按 map 名匹配 K/V 类型构造 aya::maps::HashMap<K,V>）
                        let entry_count = info.max_entries() as usize;
                        Some(MapStat {
                            name: name.to_string(),
                            map_type: map_type_str.to_string(),
                            entry_count,
                        })
                    }
                    Err(_) => Some(MapStat {
                        name: name.to_string(),
                        map_type: "UNKNOWN".to_string(),
                        entry_count: 0,
                    }),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_maps_count() {
        assert_eq!(SHARED_MAPS.len(), 5);
        assert!(SHARED_MAPS.contains(&"risk_scores"));
        assert!(SHARED_MAPS.contains(&"infer_config"));
    }
}

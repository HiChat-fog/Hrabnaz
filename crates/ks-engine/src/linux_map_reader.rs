//! LinuxBpfMapReader,通过aya::Ebpf真实读取BPF map统计信息。
//!
//! 用真实LinuxBpfMapReader替换MockBpfMapReader,让/api/v1/stats端点暴露BPF map真实统计(map_type和entry_count)。
//!
//! ## 设计
//!
//! 持有Arc<Mutex<aya::Ebpf>>引用,与EbpfLoader共享同一个Ebpf实例。EbpfLoader在start_all末尾把bpf包成Arc<Mutex>,通过map_reader()暴露一个克隆给调用方。5个事件map(events/tree_events/freq_events/flow_events/filter_events)已被take_map移走,不在此读取,只读5个共享map:risk_scores、ip_whitelist、net_conn_history、freq_counters、infer_config。
//!
//! ## 实现现状
//!
//! list_map_stats()通过MapData::info()读真实map_type和max_entries。ARRAY和PERCPU_ARRAY的max_entries等于实际entry数(所有槽位始终存在);HASH和LRU_HASH的max_entries是容量上限,实际entry数需iter().count()(TODO:要按map名匹配K/V类型构造aya::maps::HashMap<K,V>)。read_map()返回真实map_type,但entries为空(同上TODO)。
//!
//! ## aya API扩展点
//!
//! 真实读取entries见aya::maps::HashMap::<&MapData, K, V>::try_from(md).iter(),要按map名硬编码K/V类型(如risk_scores: (u32, u64))。当前只返回统计信息,不阻塞集成测试和端到端脚本。

#![cfg(target_os = "linux")]

use std::sync::{Arc, Mutex};

use crate::loader::{BpfMapReader, MapSnapshot, MapStat};

/// 5个共享map(事件map已被take_map移走,不在此读取)。
/// 顺序与MockBpfMapReader::list_map_stats()保持一致,便于前端兼容。
const SHARED_MAPS: &[&str] = &[
    "risk_scores",
    "ip_whitelist",
    "net_conn_history",
    "freq_counters",
    "infer_config",
];

/// 真实BPF map读取器,持有Arc<Mutex<aya::Ebpf>>共享Ebpf实例。
///
/// 线程安全:Arc<Mutex<Ebpf>>是Send+Sync(因aya::Ebpf是Send),满足BpfMapReader的Send + Sync supertrait要求。
pub struct LinuxBpfMapReader {
    bpf: Arc<Mutex<aya::Ebpf>>,
}

impl LinuxBpfMapReader {
    pub fn new(bpf: Arc<Mutex<aya::Ebpf>>) -> Self {
        Self { bpf }
    }

    /// 从aya::maps::Map enum提取内部&MapData引用。
    ///
    /// Map的每个variant都恰好包裹一个MapData,用|模式合并所有分支。若aya未来新增variant,编译器会在match穷尽性检查时报错,迫使更新。
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
            // 穷尽匹配:aya新增variant时编译器报错,避免静默漏处理。
        }
    }

    /// 将aya::maps::MapType转为前端可读的字符串标签。
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
            // MapType是#[non_exhaustive],aya新增variant时走此分支。
            _ => "OTHER",
        }
    }
}

impl BpfMapReader for LinuxBpfMapReader {
    fn read_map(&self, map_name: &str) -> anyhow::Result<MapSnapshot> {
        // 通过aya真实读取map_type,entries暂不实现(要按map名匹配K/V类型)。
        // TODO: 实现entries读取 - aya::maps::HashMap::<&MapData, K, V>::try_from(md).iter()
        let bpf = self.bpf.lock().expect("Ebpf Mutex中毒");
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

    /// 真实读取map entries(按map名分发typed reader)。
    /// 真机阶段补全:risk_scores等map的typed reading需用aya::maps::HashMap
    /// (aya 0.14借用语义需take_map owned MapData,当前EbpfLoader.bpf是
    ///  Arc<Mutex<Ebpf>>仅能bpf.map(name)借用,需重构EbpfLoader暴露owned
    ///  map clone或改用aya Ebpf::map_mut())。
    /// MockBpfMapReader提供完整桩数据用于CI测试。
    fn read_map_structured(&self, map_name: &str) -> Vec<serde_json::Value> {
        let bpf = self.bpf.lock().expect("Ebpf Mutex中毒");
        let md = match bpf.map(map_name).map(Self::map_data_ref) {
            Some(md) => md,
            None => return Vec::new(),
        };
        log::debug!(
            "map '{}' (type={:?}) typed reading待真机阶段补全",
            map_name,
            md.info().and_then(|i| i.map_type()).ok()
        );
        Vec::new()
    }

    fn list_maps(&self) -> Vec<String> {
        SHARED_MAPS.iter().map(|s| s.to_string()).collect()
    }

    fn list_map_stats(&self) -> Vec<MapStat> {
        let bpf = self.bpf.lock().expect("Ebpf Mutex中毒");
        SHARED_MAPS
            .iter()
            .filter_map(|&name| {
                let map = bpf.map(name)?;
                let md = Self::map_data_ref(map);
                match md.info() {
                    Ok(info) => {
                        let map_type_str =
                            info.map_type().map(Self::map_type_str).unwrap_or("UNKNOWN");
                        // max_entries是map容量上限:
                        // ARRAY和PERCPU_ARRAY的max_entries等于实际entry数
                        //   (所有槽位始终存在,无"空槽"概念)
                        // HASH和LRU_HASH的max_entries是容量上限,
                        //   实际entry数需iter().count()。
                        //   TODO: 对HASH map实现iter().count()真实计数
                        //   (需按map名匹配K/V类型构造aya::maps::HashMap<K,V>)
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

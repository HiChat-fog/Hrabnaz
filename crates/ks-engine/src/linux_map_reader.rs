#![cfg(target_os = "linux")]

use std::sync::{Arc, Mutex};

use aya::maps::{Array, HashMap};
use aya::Pod;
use serde_json::{Value, json};

use crate::loader::{BpfMapReader, MapSnapshot, MapStat};

const SHARED_MAPS: &[&str] = &[
    "risk_scores",
    "ip_whitelist",
    "net_conn_history",
    "freq_counters",
    "infer_config",
    "protected_comms",
];

#[repr(C)]
#[derive(Clone, Copy)]
struct NetConnKey {
    pid: u32,
    daddr: u32,
    dport: u16,
    proto: u8,
    _pad: u8,
}
unsafe impl Pod for NetConnKey {}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct FreqCounter {
    syscall_count_60s: u32,
    file_op_count_60s: u32,
    net_op_count_60s: u32,
    dns_op_count_60s: u32,
    ptrace_count_60s: u32,
    signal_count_60s: u32,
    last_update_ns: u64,
    window_start_ns: u64,
    anomaly_flags: u32,
    _pad_freq1: u32,
}
unsafe impl Pod for FreqCounter {}

pub struct LinuxBpfMapReader {
    bpf: Arc<Mutex<aya::Ebpf>>,
}

impl LinuxBpfMapReader {
    pub fn new(bpf: Arc<Mutex<aya::Ebpf>>) -> Self {
        Self { bpf }
    }

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
        }
    }

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
            _ => "OTHER",
        }
    }

    fn read_entries(&self, map_name: &str) -> (usize, Vec<Value>) {
        let bpf = self.bpf.lock().expect("Ebpf Mutex中毒");
        let map = match bpf.map(map_name) {
            Some(m) => m,
            None => return (0, Vec::new()),
        };

        match map_name {
            "risk_scores" => {
                if let Ok(hm) = HashMap::<_, u32, u32>::try_from(map) {
                    let mut entries = Vec::new();
                    for kv in hm.iter() {
                        if let Ok((pid, score)) = kv {
                            entries.push(json!({"pid": pid, "risk_score": score}));
                        }
                    }
                    let n = entries.len();
                    return (n, entries);
                }
            }
            "ip_whitelist" => {
                if let Ok(hm) = HashMap::<_, u32, u8>::try_from(map) {
                    let mut entries = Vec::new();
                    for kv in hm.iter() {
                        if let Ok((ip, flag)) = kv {
                            entries.push(json!({"ip": ip, "whitelisted": flag}));
                        }
                    }
                    let n = entries.len();
                    return (n, entries);
                }
            }
            "net_conn_history" => {
                if let Ok(hm) = HashMap::<_, NetConnKey, u64>::try_from(map) {
                    let mut entries = Vec::new();
                    for kv in hm.iter() {
                        if let Ok((k, ts)) = kv {
                            let daddr = k.daddr;
                            let [b0, b1, b2, b3] = daddr.to_le_bytes();
                            entries.push(json!({
                                "pid": k.pid,
                                "daddr": format!("{}.{}.{}.{}", b0, b1, b2, b3),
                                "dport": k.dport,
                                "proto": k.proto,
                                "last_ns": ts,
                            }));
                        }
                    }
                    let n = entries.len();
                    return (n, entries);
                }
            }
            "freq_counters" => {
                if let Ok(hm) = HashMap::<_, u32, FreqCounter>::try_from(map) {
                    let mut entries = Vec::new();
                    for kv in hm.iter() {
                        if let Ok((pid, fc)) = kv {
                            entries.push(json!({
                                "pid": pid,
                                "syscall_60s": fc.syscall_count_60s,
                                "file_60s": fc.file_op_count_60s,
                                "net_60s": fc.net_op_count_60s,
                                "dns_60s": fc.dns_op_count_60s,
                                "ptrace_60s": fc.ptrace_count_60s,
                                "signal_60s": fc.signal_count_60s,
                                "anomaly_flags": fc.anomaly_flags,
                            }));
                        }
                    }
                    let n = entries.len();
                    return (n, entries);
                }
            }
            "infer_config" => {
                let md = Self::map_data_ref(map);
                if let Ok(info) = md.info() {
                    let max = info.max_entries() as usize;
                    if let Ok(arr) = Array::<_, u32>::try_from(map) {
                        let mut entries = Vec::new();
                        for i in 0..max as u32 {
                            if let Ok(v) = arr.get(&i, 0) {
                                entries.push(json!({"idx": i, "value": v}));
                            }
                        }
                        return (max, entries);
                    }
                }
            }
            "protected_comms" => {
                if let Ok(hm) = HashMap::<_, [u8; 16], u8>::try_from(map) {
                    let mut entries = Vec::new();
                    for kv in hm.iter() {
                        if let Ok((key, flag)) = kv {
                            let end = key.iter().position(|&b| b == 0).unwrap_or(16);
                            let comm = String::from_utf8_lossy(&key[..end]).to_string();
                            entries.push(json!({"comm": comm, "protected": flag}));
                        }
                    }
                    let n = entries.len();
                    return (n, entries);
                }
            }
            _ => {}
        }
        (0, Vec::new())
    }
}

impl BpfMapReader for LinuxBpfMapReader {
    fn read_map(&self, map_name: &str) -> anyhow::Result<MapSnapshot> {
        let bpf = self.bpf.lock().expect("Ebpf Mutex中毒");
        let map_type_str = bpf
            .map(map_name)
            .map(Self::map_data_ref)
            .and_then(|md| md.info().ok())
            .and_then(|info| info.map_type().ok())
            .map(Self::map_type_str)
            .unwrap_or("unknown");
        drop(bpf);

        let (count, _entries) = self.read_entries(map_name);
        Ok(MapSnapshot {
            name: map_name.to_string(),
            map_type: map_type_str.to_string(),
            entry_count: count,
            entries: vec![],
        })
    }

    fn read_map_structured(&self, map_name: &str) -> Vec<Value> {
        self.read_entries(map_name).1
    }

    fn list_maps(&self) -> Vec<String> {
        SHARED_MAPS.iter().map(|s| s.to_string()).collect()
    }

    fn list_map_stats(&self) -> Vec<MapStat> {
        SHARED_MAPS
            .iter()
            .map(|&name| {
                match self.read_map(name) {
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
        assert_eq!(SHARED_MAPS.len(), 6);
        assert!(SHARED_MAPS.contains(&"risk_scores"));
        assert!(SHARED_MAPS.contains(&"infer_config"));
        assert!(SHARED_MAPS.contains(&"protected_comms"));
    }
}

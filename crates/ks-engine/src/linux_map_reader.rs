#![cfg(target_os = "linux")]

use std::sync::{Arc, Mutex};

use aya::maps::{Array, HashMap};

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

// net_conn_history / freq_counters 的 key/value 用原始字节数组而非 repr(C)
// 结构体：与 open_block_map 的 block_key/block_value 同一模式——布局契约在解码
// 代码里逐字节可见，且 aya 对 [u8; N] 自带 Pod 实现，无需 unsafe impl。
// 布局对齐 common.h 的 `struct net_conn_key`（12B）与 `struct freq_counter`（48B），
// native endian（同架构读取）。

/// net_conn_key: u32 pid @0, u32 daddr @4, u16 dport @8, u8 proto @10
fn decode_net_conn_key(k: &[u8; 12]) -> (u32, u32, u16, u8) {
    let arr4 = |off: usize| u32::from_ne_bytes([k[off], k[off + 1], k[off + 2], k[off + 3]]);
    (arr4(0), arr4(4), u16::from_ne_bytes([k[8], k[9]]), k[10])
}

/// freq_counter: 六个 u32 计数器 @0..24, 两个 u64 时间戳 @24/@32, u32 anomaly_flags @40
fn decode_freq_counter(v: &[u8; 48]) -> [u32; 7] {
    let u32at = |off: usize| {
        u32::from_ne_bytes([v[off], v[off + 1], v[off + 2], v[off + 3]])
    };
    [
        u32at(0),  // syscall_count_60s
        u32at(4),  // file_op_count_60s
        u32at(8),  // net_op_count_60s
        u32at(12), // dns_op_count_60s
        u32at(16), // ptrace_count_60s
        u32at(20), // signal_count_60s
        u32at(40), // anomaly_flags
    ]
}

pub struct LinuxBpfMapReader {
    bpf: Arc<Mutex<aya::Ebpf>>,
}

impl LinuxBpfMapReader {
    pub fn new(bpf: Arc<Mutex<aya::Ebpf>>) -> Self {
        Self { bpf }
    }

    /// 打开内核 `block_decisions` map（阻断裁决下发通道）。
    ///
    /// key/value 用原始字节数组而非 repr(C) 结构体：布局必须逐字节对齐
    /// common.h 的 `struct block_key {u32 pid; u32 _pad;}` /
    /// `struct block_value {u64 expire_ns; u8 reason; u8 _pad[7];}`（native endian，同架构），
    /// 字节数组写法让对齐契约在拷贝代码里可见，也免去补 Pod 派生。
    fn open_block_map(
        bpf: &mut aya::Ebpf,
    ) -> anyhow::Result<aya::maps::HashMap<&mut aya::maps::MapData, [u8; 8], [u8; 16]>> {
        let map = bpf
            .map_mut("block_decisions")
            .ok_or_else(|| anyhow::anyhow!("block_decisions map 不存在（该 tier 未加载或已被 take）"))?;
        let hm = aya::maps::HashMap::<_, [u8; 8], [u8; 16]>::try_from(map)?;
        Ok(hm)
    }

    pub fn write_block_decision(
        &self,
        pid: u32,
        expire_monotonic_ns: u64,
        reason: u8,
    ) -> anyhow::Result<()> {
        let mut bpf = self
            .bpf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut hm = Self::open_block_map(&mut bpf)?;
        let mut key = [0u8; 8];
        key[..4].copy_from_slice(&pid.to_ne_bytes());
        let mut value = [0u8; 16];
        value[..8].copy_from_slice(&expire_monotonic_ns.to_ne_bytes());
        value[8] = reason;
        hm.insert(key, value, 0)
            .map_err(|e| anyhow::anyhow!("写入 block_decisions[pid={}] 失败: {}", pid, e))?;
        Ok(())
    }

    pub fn remove_block_decision(&self, pid: u32) -> anyhow::Result<()> {
        let mut bpf = self
            .bpf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut hm = Self::open_block_map(&mut bpf)?;
        let mut key = [0u8; 8];
        key[..4].copy_from_slice(&pid.to_ne_bytes());
        hm.remove(&key)
            .map_err(|e| anyhow::anyhow!("删除 block_decisions[pid={}] 失败: {}", pid, e))?;
        Ok(())
    }

    /// 读全表：killer 与列表命令共用。(pid, expire_mono, reason)
    pub fn read_block_decisions(&self) -> Vec<(u32, u64, u8)> {
        let mut bpf = self
            .bpf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Ok(hm) = Self::open_block_map(&mut bpf) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (key, value) in hm.iter().flatten() {
            let pid = u32::from_ne_bytes(key[..4].try_into().unwrap_or([0; 4]));
            let expire = u64::from_ne_bytes(value[..8].try_into().unwrap_or([0; 8]));
            out.push((pid, expire, value[8]));
        }
        out
    }

    /// pin 到 bpffs。先删同路径残留（上次崩溃遗留的 pin 指向已死的 map）。
    pub fn pin_block_map(&self, path: &str) -> anyhow::Result<()> {
        let _ = std::fs::remove_file(path);
        let mut bpf = self
            .bpf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let map = bpf
            .map_mut("block_decisions")
            .ok_or_else(|| anyhow::anyhow!("block_decisions map 不存在"))?;
        map.pin(path)
            .map_err(|e| anyhow::anyhow!("pin {} 失败: {}（/sys/fs/bpf 未挂载?）", path, e))?;
        Ok(())
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
        // 锁中毒不 panic 整个进程：接管锁内容降级继续读
        let bpf = self
            .bpf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let map = match bpf.map(map_name) {
            Some(m) => m,
            None => return (0, Vec::new()),
        };

        match map_name {
            "risk_scores" => {
                if let Ok(hm) = HashMap::<_, u32, u32>::try_from(map) {
                    let mut entries = Vec::new();
                    for (pid, score) in hm.iter().flatten() {
                    entries.push(json!({"pid": pid, "risk_score": score}));
                    }
                    let n = entries.len();
                    return (n, entries);
                }
            }
            "ip_whitelist" => {
                if let Ok(hm) = HashMap::<_, u32, u8>::try_from(map) {
                    let mut entries = Vec::new();
                    for (ip, flag) in hm.iter().flatten() {
                    entries.push(json!({"ip": ip, "whitelisted": flag}));
                    }
                    let n = entries.len();
                    return (n, entries);
                }
            }
            "net_conn_history" => {
                if let Ok(hm) = HashMap::<_, [u8; 12], u64>::try_from(map) {
                    let mut entries = Vec::new();
                    for (k, ts) in hm.iter().flatten() {
                        let (pid, daddr, dport, proto) = decode_net_conn_key(&k);
                        let [b0, b1, b2, b3] = daddr.to_le_bytes();
                        entries.push(json!({
                            "pid": pid,
                            "daddr": format!("{}.{}.{}.{}", b0, b1, b2, b3),
                            "dport": dport,
                            "proto": proto,
                            "last_ns": ts,
                        }));
                    }
                    let n = entries.len();
                    return (n, entries);
                }
            }
            "freq_counters" => {
                if let Ok(hm) = HashMap::<_, u32, [u8; 48]>::try_from(map) {
                    let mut entries = Vec::new();
                    for (pid, v) in hm.iter().flatten() {
                        let fc = decode_freq_counter(&v);
                        entries.push(json!({
                            "pid": pid,
                            "syscall_60s": fc[0],
                            "file_60s": fc[1],
                            "net_60s": fc[2],
                            "dns_60s": fc[3],
                            "ptrace_60s": fc[4],
                            "signal_60s": fc[5],
                            "anomaly_flags": fc[6],
                        }));
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
                    for (key, flag) in hm.iter().flatten() {
                        let end = key.iter().position(|&b| b == 0).unwrap_or(16);
                        let comm = String::from_utf8_lossy(&key[..end]).to_string();
                        entries.push(json!({"comm": comm, "protected": flag}));
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
        // 锁中毒不 panic 整个进程：接管锁内容降级继续读
        let bpf = self
            .bpf
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

    fn write_block_decision(
        &self,
        pid: u32,
        expire_monotonic_ns: u64,
        reason: u8,
    ) -> anyhow::Result<()> {
        LinuxBpfMapReader::write_block_decision(self, pid, expire_monotonic_ns, reason)
    }

    fn remove_block_decision(&self, pid: u32) -> anyhow::Result<()> {
        LinuxBpfMapReader::remove_block_decision(self, pid)
    }

    fn read_block_decisions(&self) -> Vec<(u32, u64, u8)> {
        LinuxBpfMapReader::read_block_decisions(self)
    }

    fn pin_block_map(&self, path: &str) -> anyhow::Result<()> {
        LinuxBpfMapReader::pin_block_map(self, path)
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

    /// 解码等价性：字节数组手解必须与 repr(C) 结构体字段读法逐字段一致
    /// （native endian 同架构）。旧 NetConnKey {pid,daddr,dport,proto,_pad}。
    #[test]
    fn net_conn_key_decode_matches_repr_c_layout() {
        let k = (0u8..12).collect::<Vec<u8>>().try_into().unwrap();
        let (pid, daddr, dport, proto) = decode_net_conn_key(&k);
        assert_eq!(pid, u32::from_ne_bytes([0, 1, 2, 3]));
        assert_eq!(daddr, u32::from_ne_bytes([4, 5, 6, 7]));
        assert_eq!(dport, u16::from_ne_bytes([8, 9]));
        assert_eq!(proto, 10);
    }

    /// 旧 FreqCounter 的逐字段偏移：六个 u32 @0/4/8/12/16/20，
    /// 两个 u64 @24/32（不读），anomaly_flags @40。
    #[test]
    fn freq_counter_decode_matches_repr_c_layout() {
        let mut v = [0u8; 48];
        for (i, b) in v.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3);
        }
        let fc = decode_freq_counter(&v);
        let u32at = |off: usize| {
            u32::from_ne_bytes([v[off], v[off + 1], v[off + 2], v[off + 3]])
        };
        for (i, &expected) in fc.iter().enumerate().take(6) {
            assert_eq!(expected, u32at(i * 4), "counter[{i}] 偏移不符");
        }
        // anomaly_flags 在两个 u64 时间戳之后（@40），不是 @24+4
        assert_eq!(fc[6], u32at(40));
        assert_ne!(fc[6], u32at(24));
    }
}

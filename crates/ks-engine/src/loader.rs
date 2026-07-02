//! eBPF 加载器 — A4 重构后：
//!
//! - 加载合并后的单一 ks_main.bpf.o（包含全部 7 类探针的 18 个程序）
//! - 持久持有 5 个 RingBuf：events / tree_events / freq_events / flow_events / filter_events
//!   （旧实现每次 try_next_event 临时 RingBuf::try_from，会丢数据 + 借用冲突；
//!    aya 0.14 用 `bpf.take_map(name)` 取出 owned Map，再 `RingBuf::try_from(map)`
//!    得到无 lifetime 的 `RingBuf<Map>`，可独立持久持有。）
//! - try_next_events() round-robin 轮询 5 个 ringbuf，返回 (来源, 字节)

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub tracepoints: Vec<TracepointProbe>,
    pub kprobes: Vec<KprobeProbe>,
}

#[derive(Debug, Clone)]
pub struct TracepointProbe {
    pub program_name: String,
    pub category: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct KprobeProbe {
    pub program_name: String,
    pub function_name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProbeState {
    Loaded,
    Attached,
    Detached,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct MapEntry {
    pub map_name: String,
    pub key_hex: String,
    pub value_hex: String,
    pub value_display: String,
}

#[derive(Debug, Clone)]
pub struct MapSnapshot {
    pub name: String,
    pub map_type: String,
    pub entry_count: usize,
    pub entries: Vec<MapEntry>,
}

pub trait BpfMapReader: Send + Sync {
    fn read_map(&self, map_name: &str) -> anyhow::Result<MapSnapshot>;
    fn list_maps(&self) -> Vec<String>;
}

pub struct MockBpfMapReader;

impl BpfMapReader for MockBpfMapReader {
    fn read_map(&self, _map_name: &str) -> anyhow::Result<MapSnapshot> {
        Ok(MapSnapshot {
            name: _map_name.to_string(),
            map_type: "mock".into(),
            entry_count: 0,
            entries: vec![],
        })
    }
    fn list_maps(&self) -> Vec<String> {
        vec!["risk_scores".into(), "conn_history".into(), "ip_whitelist".into()]
    }
}

// ─── EbpfLoader ──────────────────────────────────────────────

/// 事件来源 ringbuf 名称（5 个，对应 ks_main.bpf.c 中的 5 个 KS_EVENT_MAP）。
/// 顺序也代表轮询优先级：events（syscall/vfs/net 主流）> tree > freq > flow > filter。
pub const RING_NAMES: &[&str] = &[
    "events",
    "tree_events",
    "freq_events",
    "flow_events",
    "filter_events",
];

#[cfg(target_os = "linux")]
struct RingBufSource {
    name: &'static str,
    // RingBuf::try_from(Map) 返回 RingBuf<MapData>（owned，无 lifetime），
    // 可脱离 Bpf 独立持久持有。
    ring: aya::maps::RingBuf<aya::maps::MapData>,
}

pub struct EbpfLoader {
    /// 已 attach 的程序名（仅用于状态展示）。
    probes: Vec<String>,
    #[cfg(target_os = "linux")]
    rings: Vec<RingBufSource>,
    /// take_map 之后 Bpf 只剩程序对象（用于 stop_all 时 drop）。
    #[cfg(target_os = "linux")]
    bpf: Option<aya::Ebpf>,
    /// round-robin 轮询游标。
    #[cfg(target_os = "linux")]
    ring_idx: usize,
}

impl EbpfLoader {
    pub fn new() -> Self {
        // 合并后的 ks_main.o 中所有程序的 attach 列表（A4 扩展自原 4 个 tracepoint）。
        // 注意：多程序挂载同一 hook（如 vfs_open 有 kprobe_vfs_open + smart_filter_vfs_open）
        // 在 5.x 内核通过 BPF_LINK_CREATE 多 link 支持，KS_TIER_MODERN 路径可用。
        let probes: Vec<String> = vec![
            // syscall probe (ks_probes_syscall.h)
            "trace_sys_enter", "trace_sys_exit",
            "trace_sched_exec", "trace_sched_exit",
            // process_tree probe (ks_probes_process_tree.h)
            "trace_sched_fork", "trace_sched_exec_tree", "trace_sched_exit_tree",
            // freq probe (ks_probes_freq.h)
            "freq_sys_exit",
            // vfs probe (ks_probes_vfs.h)
            "kprobe_vfs_open", "kprobe_vfs_write", "kprobe_vfs_unlink",
            // net probe (ks_probes_net.h)
            "kprobe_tcp_v4_connect", "kprobe_tcp_v6_connect", "kprobe_udp_sendmsg",
            // net_flow probe (ks_probes_netflow.h)
            "kprobe_tcp_v4_connect_flow", "kprobe_tcp_set_state_flow", "kprobe_tcp_sendmsg_flow",
            // smart_filter probe (ks_probes_smart_filter.h)
            "smart_filter_vfs_open",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            probes,
            #[cfg(target_os = "linux")]
            rings: Vec::new(),
            #[cfg(target_os = "linux")]
            bpf: None,
            #[cfg(target_os = "linux")]
            ring_idx: 0,
        }
    }

    /// 加载 ks_main.bpf.o，attach 全部 18 个程序，take 出 5 个 RingBuf 持久持有。
    pub async fn start_all(&mut self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            // A4: 加载合并后的单一 ks_main.o（原 8 个 .o 已合并）
            let obj = include_bytes!(concat!(env!("OUT_DIR"), "/ks_main.o"));
            let mut bpf = aya::Ebpf::load(obj)?;

            // ── attach tracepoints ──
            macro_rules! attach_tp {
                ($name:expr, $cat:expr, $evt:expr) => {
                    let prog: &mut aya::programs::TracePoint =
                        bpf.program_mut($name)
                            .ok_or_else(|| anyhow::anyhow!("tracepoint 程序 '{}' 未找到", $name))?
                            .try_into()?;
                    prog.load()?;
                    prog.attach($cat, $evt)?;
                };
            }
            // raw_syscalls（syscall probe + freq probe 都挂 sys_exit）
            attach_tp!("trace_sys_enter", "raw_syscalls", "sys_enter");
            attach_tp!("trace_sys_exit",  "raw_syscalls", "sys_exit");
            attach_tp!("freq_sys_exit",    "raw_syscalls", "sys_exit");
            // sched（syscall probe + process_tree probe 都挂 exec/exit）
            attach_tp!("trace_sched_exec",       "sched", "sched_process_exec");
            attach_tp!("trace_sched_exit",       "sched", "sched_process_exit");
            attach_tp!("trace_sched_fork",       "sched", "sched_process_fork");
            attach_tp!("trace_sched_exec_tree", "sched", "sched_process_exec");
            attach_tp!("trace_sched_exit_tree", "sched", "sched_process_exit");

            // ── attach kprobes ──
            macro_rules! attach_kp {
                ($name:expr, $func:expr) => {
                    let prog: &mut aya::programs::KProbe =
                        bpf.program_mut($name)
                            .ok_or_else(|| anyhow::anyhow!("kprobe 程序 '{}' 未找到", $name))?
                            .try_into()?;
                    prog.load()?;
                    prog.attach($func, 0)?;
                };
            }
            // vfs
            attach_kp!("kprobe_vfs_open",  "vfs_open");
            attach_kp!("kprobe_vfs_write", "vfs_write");
            attach_kp!("kprobe_vfs_unlink","vfs_unlink");
            // net
            attach_kp!("kprobe_tcp_v4_connect", "tcp_v4_connect");
            attach_kp!("kprobe_tcp_v6_connect", "tcp_v6_connect");
            attach_kp!("kprobe_udp_sendmsg",    "udp_sendmsg");
            // net_flow（与 net probe 共享 tcp_v4_connect hook）
            attach_kp!("kprobe_tcp_v4_connect_flow", "tcp_v4_connect");
            attach_kp!("kprobe_tcp_set_state_flow",  "tcp_set_state");
            attach_kp!("kprobe_tcp_sendmsg_flow",    "tcp_sendmsg");
            // smart_filter（与 vfs probe 共享 vfs_open hook）
            attach_kp!("smart_filter_vfs_open", "vfs_open");

            // ── A4: take 出 5 个 RingBuf 持久持有 ──
            // take_map 返回 owned Map，RingBuf::try_from(Map) 得到 RingBuf<Map>，
            // 不再借用 Bpf，可独立存入 self.rings。
            for &name in RING_NAMES {
                let map = bpf.take_map(name)
                    .ok_or_else(|| anyhow::anyhow!("RingBuf map '{}' 未找到", name))?;
                // take_map 返回 owned Map，RingBuf::try_from(Map) -> RingBuf<MapData>，
                // 不再借用 Bpf，可独立存入 self.rings 持久持有。
                let ring = aya::maps::RingBuf::try_from(map)?;
                // SAFETY: name 来自 RING_NAMES 的 'static 切片
                let name_static: &'static str =
                    RING_NAMES.iter().copied().find(|n| *n == name).unwrap();
                self.rings.push(RingBufSource { name: name_static, ring });
            }

            self.bpf = Some(bpf);
            log::info!(
                "eBPF ks_main.o 加载完成：{} 个程序已 attach，{} 个 RingBuf 持久持有",
                self.probes.len(),
                self.rings.len()
            );
        }

        Ok(())
    }

    pub fn loaded_probes(&self) -> &[String] {
        &self.probes
    }

    /// A4: round-robin 轮询全部 5 个 RingBuf，返回 (来源名, 字节)。
    /// 顺序优先 events（主 syscall/vfs/net 流）> tree > freq > flow > filter。
    #[cfg(target_os = "linux")]
    pub fn try_next_events(&mut self) -> Option<(&'static str, Vec<u8>)> {
        let n = self.rings.len();
        if n == 0 {
            return None;
        }
        for _ in 0..n {
            let idx = self.ring_idx % n;
            self.ring_idx = self.ring_idx.wrapping_add(1);
            let src = &mut self.rings[idx];
            if let Some(item) = src.ring.next() {
                let bytes: &[u8] = &item;
                return Some((src.name, bytes.to_vec()));
            }
        }
        None
    }

    #[cfg(not(target_os = "linux"))]
    pub fn try_next_events(&mut self) -> Option<(&'static str, Vec<u8>)> {
        None
    }

    /// 兼容旧调用方（start.rs）：仅返回字节，丢弃来源标签。
    /// A7 重构 start.rs 后会迁移到 try_next_events()。
    pub fn try_next_event(&mut self) -> Option<Vec<u8>> {
        self.try_next_events().map(|(_, bytes)| bytes)
    }

    pub async fn stop_all(&mut self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            // 先 drop RingBuf（关闭 consumer fd），再 drop Bpf（关闭程序 fd）。
            self.rings.clear();
            self.bpf.take();
            self.ring_idx = 0;
            log::info!("eBPF 探针已卸载");
        }
        Ok(())
    }

    /// 返回 BPF map 读取器（平台无关，Linux 上跳过真实读取）。
    pub fn map_reader(&self) -> &dyn BpfMapReader {
        &MockBpfMapReader
    }
}

// ─── 测试 ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_list_contains_all_18_programs() {
        let loader = EbpfLoader::new();
        // 4 syscall + 3 process_tree + 1 freq + 3 vfs + 3 net + 3 net_flow + 1 smart_filter = 18
        assert_eq!(loader.probes.len(), 18);
    }

    #[test]
    fn test_ring_names_count() {
        assert_eq!(RING_NAMES.len(), 5);
        assert!(RING_NAMES.contains(&"events"));
        assert!(RING_NAMES.contains(&"tree_events"));
        assert!(RING_NAMES.contains(&"freq_events"));
        assert!(RING_NAMES.contains(&"flow_events"));
        assert!(RING_NAMES.contains(&"filter_events"));
    }
}

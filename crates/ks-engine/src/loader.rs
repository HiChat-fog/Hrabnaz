//! eBPF加载器 — B4 重构：支持multi-tier（Modern ringbuf / Legacy perfbuf / Ancient perfbuf）。
//!
//! - 根据tier选择ks_main_modern/legacy/ancient.o加载
//! - attach 16个程序（跨tier一致）
//! - Modern: take 5 RingBuf持久持有，round-robin轮询
//! - Legacy/Ancient: take 5 PerfEventArray，per-CPU open buffer，round-robin轮询
//! - try_next_events()按backend类型分路径返回(来源,字节)

use crate::event_source::SourceKind;

/// D1: 内嵌eBPF字节码（build.rs编译各tier .o后生成`ebpf_objects.rs`）。
///
/// 单二进制部署：`.o`编译期`include_bytes!`进二进制，运行时不读磁盘；`KS_EBPF_DIR`仅调试覆盖（指向含.o的目录）。
#[cfg(target_os = "linux")]
pub mod ebpf_objects {
    include!(concat!(env!("OUT_DIR"), "/ebpf_objects.rs"));
}

#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};

use serde_json::json;

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

/// Phase E1.2：map统计信息（用于/api/v1/stats端点的map_stats字段）。
///
/// `entry_count`语义因map_type而异：
/// - ARRAY / PERCPU_ARRAY：实际entry数（所有槽位始终存在）
/// - HASH / LRU_HASH：容量上限（max_entries），实际entry数需iter().count()
#[derive(Debug, Clone)]
pub struct MapStat {
    pub name: String,
    pub map_type: String,
    pub entry_count: usize,
}

pub trait BpfMapReader: Send + Sync {
    fn read_map(&self, map_name: &str) -> anyhow::Result<MapSnapshot>;
    fn list_maps(&self) -> Vec<String>;
    /// Phase E1.2：返回所有共享map的统计信息（name / map_type / entry_count）。
    fn list_map_stats(&self) -> Vec<MapStat>;
    /// G2.4: 返回map的结构化条目（每个entry序列化为JSON对象）。
    ///
    /// 支持的map: process_tree / net_flows / freq_counters / filter_stats / risk_scores / block_decisions
    /// - MockBpfMapReader: 返回完整桩数据（CI/测试用）
    /// - LinuxBpfMapReader: risk_scores真实读取（K/V类型简单），其他返回空数组（真机可补全typed reading）
    fn read_map_structured(&self, _map_name: &str) -> Vec<serde_json::Value> {
        Vec::new()
    }
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
        vec![
            "risk_scores".into(),
            "ip_whitelist".into(),
            "net_conn_history".into(),
            "freq_counters".into(),
            "infer_config".into(),
        ]
    }
    /// 返回5个固定mock条目（entry_count=0），与LinuxBpfMapReader顺序一致。
    fn list_map_stats(&self) -> Vec<MapStat> {
        vec![
            MapStat {
                name: "risk_scores".into(),
                map_type: "HASH".into(),
                entry_count: 0,
            },
            MapStat {
                name: "ip_whitelist".into(),
                map_type: "HASH".into(),
                entry_count: 0,
            },
            MapStat {
                name: "net_conn_history".into(),
                map_type: "LRU_HASH".into(),
                entry_count: 0,
            },
            MapStat {
                name: "freq_counters".into(),
                map_type: "PERCPU_ARRAY".into(),
                entry_count: 0,
            },
            MapStat {
                name: "infer_config".into(),
                map_type: "ARRAY".into(),
                entry_count: 0,
            },
        ]
    }

    /// G2.4: 返回map的结构化桩数据（CI/测试用）。
    /// 6个map各返回3条样本，结构与真机读取保持一致。
    fn read_map_structured(&self, map_name: &str) -> Vec<serde_json::Value> {
        match map_name {
            "process_tree" => vec![
                json!({"pid": 1234u64, "ppid": 1u64, "comm": "sshd", "start_ns": 1625340000000000u64, "flags": 0u32}),
                json!({"pid": 2345u64, "ppid": 1234u64, "comm": "bash", "start_ns": 1625340010000000u64, "flags": 1u32}),
                json!({"pid": 3456u64, "ppid": 2345u64, "comm": "nc", "start_ns": 1625340020000000u64, "flags": 2u32}),
            ],
            "net_flows" => vec![
                json!({"pid": 1234, "daddr": "203.0.113.10", "dport": 4444, "proto": "TCP", "state": 4, "anomaly_flags": 1}),
                json!({"pid": 2345, "daddr": "198.51.100.5", "dport": 53, "proto": "UDP", "state": 1, "anomaly_flags": 4}),
                json!({"pid": 3456, "daddr": "192.0.2.1", "dport": 8080, "proto": "TCP", "state": 4, "anomaly_flags": 0}),
            ],
            "freq_counters" => vec![
                json!({"pid": 1234, "syscall_count_60s": 8500, "file_op_count_60s": 320, "net_op_count_60s": 45, "dns_op_count_60s": 0, "ptrace_count_60s": 0, "signal_count_60s": 0, "anomaly_flags": 1}),
                json!({"pid": 2345, "syscall_count_60s": 12000, "file_op_count_60s": 1800, "net_op_count_60s": 12, "dns_op_count_60s": 0, "ptrace_count_60s": 0, "signal_count_60s": 0, "anomaly_flags": 1}),
                json!({"pid": 3456, "syscall_count_60s": 420, "file_op_count_60s": 15, "net_op_count_60s": 220, "dns_op_count_60s": 180, "ptrace_count_60s": 0, "signal_count_60s": 0, "anomaly_flags": 4}),
            ],
            "filter_stats" => vec![
                json!({"cpu": 0, "pass_count": 15420, "block_count": 12, "sample_count": 15432}),
                json!({"cpu": 1, "pass_count": 14200, "block_count": 8, "sample_count": 14208}),
                json!({"cpu": 2, "pass_count": 16890, "block_count": 15, "sample_count": 16905}),
            ],
            "risk_scores" => vec![
                json!({"pid": 1234, "risk_score": 75, "level": "high"}),
                json!({"pid": 2345, "risk_score": 90, "level": "critical"}),
                json!({"pid": 3456, "risk_score": 40, "level": "medium"}),
            ],
            "block_decisions" => vec![
                json!({"pid": 2345u64, "expire_ns": 0u64, "reason": "RuleMatch", "reason_code": 1u32}),
                json!({"pid": 4567u64, "expire_ns": 1625340030000000u64, "reason": "Correlation", "reason_code": 4u32}),
            ],
            _ => Vec::new(),
        }
    }
}

// EbpfLoader

/// 事件来源map名称（5个，对应ks_main.bpf.c中的5个KS_EVENT_MAP）。
/// 顺序代表轮询优先级：events（syscall/vfs/net主流）> tree > freq > flow > filter。
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
    ring: aya::maps::RingBuf<aya::maps::MapData>,
}

/// B4: PerfEventArray per-CPU buffer
#[cfg(target_os = "linux")]
struct PerfEventBuffer {
    map_name: &'static str,
    cpu_id: u32,
    buf: aya::maps::perf::PerfEventArrayBuffer<aya::maps::MapData>,
}

/// B4: 事件后端 — RingBuf (Modern) 或PerfEvent (Legacy/Ancient)
#[cfg(target_os = "linux")]
enum EventBackend {
    Empty,
    RingBuf {
        rings: Vec<RingBufSource>,
        idx: usize,
    },
    PerfEvent {
        buffers: Vec<PerfEventBuffer>,
        idx: usize,
    },
}

pub struct EbpfLoader {
    /// 已attach的程序名（仅用于状态展示）。
    probes: Vec<String>,
    #[cfg(target_os = "linux")]
    backend: EventBackend,
    /// take_map之后Bpf只剩程序对象+共享map（risk_scores等）。
    ///
    /// Phase E1.2：用`Arc<Mutex<aya::Ebpf>>`让`LinuxBpfMapReader`共享同一Ebpf读map统计。
    /// 事件map已take到`backend`，不在此字段，故`try_next_events`无需锁。
    #[cfg(target_os = "linux")]
    bpf: Option<Arc<Mutex<aya::Ebpf>>>,
}

/// 读取online CPU列表（格式如"0-3"或"0,2,4-6"）
#[cfg(target_os = "linux")]
fn online_cpus() -> Vec<u32> {
    let content = std::fs::read_to_string("/sys/devices/system/cpu/online")
        .unwrap_or_else(|_| "0".to_string());
    let content = content.trim();
    let mut cpus = Vec::new();
    for part in content.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                for c in s..=e {
                    cpus.push(c);
                }
            }
        } else if let Ok(c) = part.parse::<u32>() {
            cpus.push(c);
        }
    }
    if cpus.is_empty() {
        cpus.push(0);
    }
    cpus
}

impl Default for EbpfLoader {
    fn default() -> Self {
        Self::new()
    }
}

/// 把自身tgid及父进程链(sshd等)写入protected_pids豁免map，
/// 防止eBPF阻断逻辑冷启动误杀自身及连接会话的系统进程。
#[cfg(target_os = "linux")]
fn inject_protected_pid(bpf: &mut aya::Ebpf, self_pid: u32) {
    use aya::maps::HashMap;
    // 收集需要豁免的pid：自身+父进程链(到init)+pid 1(systemd)。
    // enforce模式下分类器冷启动会对高频系统进程(sshd/cron)误判verdict==2，
    // 不豁免会导致ssh会话进程被SIGKILL，连接断裂。自身链含父sshd故一并豁免。
    let mut pids: Vec<u32> = vec![self_pid, 1];
    let mut cur = self_pid;
    for _ in 0..8 {
        match std::fs::read_to_string(format!("/proc/{}/status", cur)) {
            Ok(s) => {
                let ppid = s
                    .lines()
                    .find_map(|l| l.strip_prefix("PPid:").map(|v| v.trim().parse::<u32>().ok()))
                    .flatten();
                match ppid {
                    Some(p) if p > 1 && !pids.contains(&p) => {
                        pids.push(p);
                        cur = p;
                    }
                    _ => break,
                }
            }
            Err(_) => break,
        }
    }
    let val: u8 = 1;
    match bpf.map_mut("protected_pids") {
        Some(m) => match HashMap::<_, u32, u8>::try_from(m) {
            Ok(mut hm) => {
                for &pid in &pids {
                    if let Err(e) = hm.insert(&pid, &val, 0) {
                        log::warn!("写入 protected_pids 失败(pid={}): {:?}", pid, e);
                    }
                }
                log::info!("已注入 protected_pids 豁免 map: {:?}", pids);
            }
            Err(e) => log::warn!("打开 protected_pids map 失败: {:?}（豁免未生效）", e),
        },
        None => log::warn!("protected_pids map 不存在（豁免未生效）"),
    }
}

#[cfg(not(target_os = "linux"))]
fn inject_protected_pid(_bpf: &mut (), _self_pid: u32) {}

/// infer_config map的CFG_ENFORCE_MODE索引(与common.h enum infer_config_key对齐)。
const CFG_ENFORCE_MODE_IDX: u32 = 5;

/// 写infer_config Array<u32>，用于设置enforce_mode等运行时配置。
#[cfg(target_os = "linux")]
fn set_infer_config(bpf: &mut aya::Ebpf, idx: u32, val: u32) {
    use aya::maps::Array;
    match bpf.map_mut("infer_config") {
        Some(m) => match Array::<_, u32>::try_from(m) {
            Ok(mut arr) => match arr.set(idx, val, 0) {
                Ok(_) => log::info!("infer_config[{}]={}", idx, val),
                Err(e) => log::warn!("写 infer_config[{}] 失败: {:?}", idx, e),
            },
            Err(e) => log::warn!("打开 infer_config map 失败: {:?}", e),
        },
        None => log::warn!("infer_config map 不存在"),
    }
}

#[cfg(not(target_os = "linux"))]
fn set_infer_config(_bpf: &mut (), _idx: u32, _val: u32) {}

impl EbpfLoader {
    pub fn new() -> Self {
        let probes: Vec<String> = vec![
            "trace_sys_enter",
            "trace_sys_exit",
            "trace_sched_fork",
            "trace_sched_exec_tree",
            "trace_sched_exit_tree",
            "kprobe_vfs_open",
            "kprobe_vfs_write",
            "kprobe_vfs_unlink",
            "kprobe_tcp_connect",
            "kprobe_tcp_v6_connect",
            "kprobe_udp_sendmsg",
            "kprobe_tcp_set_state_flow",
            "kprobe_tcp_sendmsg_flow",
            // E4.1/E4.2/E4.3: 安全探针（容器逃逸/LKM加载/eBPF自身防护）
            "kprobe_commit_creds",
            "kprobe_do_init_module",
            "kprobe_security_bpf_prog_free",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            probes,
            #[cfg(target_os = "linux")]
            backend: EventBackend::Empty,
            #[cfg(target_os = "linux")]
            bpf: None,
        }
    }

    /// B4: 加载tier-specific .o，attach 16个程序，take事件maps持久持有。
    /// Modern → RingBuf backend；Legacy/Ancient → PerfEvent backend。
    pub async fn start_all(&mut self, tier: SourceKind) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let (obj_name, tier_suffix) = match tier {
                SourceKind::EbpfModern => ("ks_main_modern.o", "modern"),
                SourceKind::EbpfLegacy => ("ks_main_legacy.o", "legacy"),
                SourceKind::EbpfAncient => {
                    if crate::tier_detect::btf_available() {
                        ("ks_main_ancient.o", "ancient")
                    } else {
                        // NOBTF: aya加载ks_main_ancient_nobtf.o在3.10 stock上可能失败
                        // （aya依赖libbpf 1.0+，CentOS 7.9自带libbpf太旧）；上层default_event_source应优先走CLoaderSource
                        ("ks_main_ancient_nobtf.o", "ancient_nobtf")
                    }
                }
                _ => anyhow::bail!("不支持的 eBPF tier: {:?}", tier),
            };

            // D1: 从二进制内嵌字节码加载（单二进制部署）。
            // 消除env!("OUT_DIR")烤死构建机路径的地雷；KS_EBPF_DIR仅调试覆盖。
            let obj: Vec<u8> = if let Ok(dir) = std::env::var("KS_EBPF_DIR") {
                let obj_path = std::path::Path::new(&dir).join(obj_name);
                std::fs::read(&obj_path).map_err(|e| {
                    anyhow::anyhow!(
                        "KS_EBPF_DIR 覆盖读取 {} 失败: {}",
                        obj_path.display(),
                        e
                    )
                })?
            } else {
                ebpf_objects::ebpf_object_for(tier_suffix)
                    .map(|b| b.to_vec())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "二进制内无内嵌 {}（编译期该 tier 未成功编译）；\
                             如需指定外部 .o，设 KS_EBPF_DIR 环境变量",
                            obj_name
                        )
                    })?
            };

            log::info!(
                "[loader] 加载 {} (tier={:?}, {} 字节)",
                obj_name,
                tier,
                obj.len()
            );
            let bpf_load_result = aya::Ebpf::load(&obj);
            let mut bpf = match bpf_load_result {
                Ok(b) => b,
                Err(e) => {
                    // Ancient+NOBTF路径加载失败 — 给上层default_event_source明确提示
                    // 走CLoaderSource（ks_loader --stream）替代aya加载。
                    if matches!(tier, SourceKind::EbpfAncient)
                        && !crate::tier_detect::btf_available()
                    {
                        return Err(anyhow::anyhow!(
                            "aya 加载 {} 失败: {} — 建议用 CLoaderSource（ks_loader --stream）替代 aya 加载",
                            obj_name, e,
                        ));
                    }
                    return Err(anyhow::anyhow!("aya 加载 {} 失败: {}", obj_name, e));
                }
            };

            // attach tracepoints
            macro_rules! attach_tp {
                ($name:expr, $cat:expr, $evt:expr) => {
                    let prog: &mut aya::programs::TracePoint = bpf
                        .program_mut($name)
                        .ok_or_else(|| anyhow::anyhow!("tracepoint 程序 '{}' 未找到", $name))?
                        .try_into()?;
                    prog.load()?;
                    prog.attach($cat, $evt)?;
                };
            }
            attach_tp!("trace_sys_enter", "raw_syscalls", "sys_enter");
            attach_tp!("trace_sys_exit", "raw_syscalls", "sys_exit");
            attach_tp!("trace_sched_fork", "sched", "sched_process_fork");
            attach_tp!("trace_sched_exec_tree", "sched", "sched_process_exec");
            attach_tp!("trace_sched_exit_tree", "sched", "sched_process_exit");

            // attach kprobes
            macro_rules! attach_kp {
                ($name:expr, $func:expr) => {
                    let prog: &mut aya::programs::KProbe = bpf
                        .program_mut($name)
                        .ok_or_else(|| anyhow::anyhow!("kprobe 程序 '{}' 未找到", $name))?
                        .try_into()?;
                    prog.load()?;
                    prog.attach($func, 0)?;
                };
            }
            attach_kp!("kprobe_vfs_open", "vfs_open");
            attach_kp!("kprobe_vfs_write", "vfs_write");
            attach_kp!("kprobe_vfs_unlink", "vfs_unlink");
            attach_kp!("kprobe_tcp_connect", "tcp_v4_connect");
            attach_kp!("kprobe_tcp_v6_connect", "tcp_v6_connect");
            attach_kp!("kprobe_udp_sendmsg", "udp_sendmsg");
            attach_kp!("kprobe_tcp_set_state_flow", "tcp_set_state");
            attach_kp!("kprobe_tcp_sendmsg_flow", "tcp_sendmsg");
            // E4.1/E4.2/E4.3: 安全探针
            attach_kp!("kprobe_commit_creds", "commit_creds");
            attach_kp!("kprobe_do_init_module", "do_init_module");
            // security_bpf_prog_free在部分内核版本可能不存在，attach失败不阻断其他探针
            match (|| -> anyhow::Result<()> {
                attach_kp!("kprobe_security_bpf_prog_free", "security_bpf_prog_free");
                Ok(())
            })() {
                Ok(()) => {}
                Err(e) => log::warn!("[loader] security_bpf_prog_free attach 失败（忽略）: {}", e),
            }

            // B4: take事件maps — 按tier选择后端
            let use_ringbuf = matches!(tier, SourceKind::EbpfModern);

            if use_ringbuf {
                let mut rings = Vec::new();
                for &name in RING_NAMES {
                    let map = bpf
                        .take_map(name)
                        .ok_or_else(|| anyhow::anyhow!("RingBuf map '{}' 未找到", name))?;
                    let ring = aya::maps::RingBuf::try_from(map)?;
                    let name_static: &'static str =
                        RING_NAMES.iter().copied().find(|n| *n == name).unwrap();
                    rings.push(RingBufSource {
                        name: name_static,
                        ring,
                    });
                }
                self.backend = EventBackend::RingBuf { rings, idx: 0 };
                log::info!("[loader] Modern tier: 5 RingBuf 持久持有");
            } else {
                let mut buffers = Vec::new();
                let cpus = online_cpus();
                for &name in RING_NAMES {
                    let map = bpf
                        .take_map(name)
                        .ok_or_else(|| anyhow::anyhow!("PerfEventArray map '{}' 未找到", name))?;
                    let mut perf_array = aya::maps::PerfEventArray::try_from(map)?;
                    for &cpu_id in &cpus {
                        match perf_array.open(cpu_id, Some(64)) {
                            Ok(buf) => {
                                let name_static: &'static str =
                                    RING_NAMES.iter().copied().find(|n| *n == name).unwrap();
                                buffers.push(PerfEventBuffer {
                                    map_name: name_static,
                                    cpu_id,
                                    buf,
                                });
                            }
                            Err(e) => {
                                log::warn!(
                                    "[loader] PerfEventArray open failed for {} cpu {}: {}",
                                    name,
                                    cpu_id,
                                    e
                                );
                            }
                        }
                    }
                }
                self.backend = EventBackend::PerfEvent { buffers, idx: 0 };
                log::info!(
                    "[loader] {:?} tier: {} PerfEventArray buffers ({} CPUs × {} maps)",
                    tier,
                    online_cpus().len() * RING_NAMES.len(),
                    cpus.len(),
                    RING_NAMES.len()
                );
            }

            // 注入自身pid到protected_pids豁免map，避免分类器冷启动误报时
            // bpf_send_signal杀掉自身。enforce_mode默认0(monitor)只告警不杀。
            inject_protected_pid(&mut bpf, std::process::id());
            // enforce开关：KS_ENFORCE=1时verdict==2内核态直接SIGKILL(申报书
            // 第四阶段零延迟阻断)；默认monitor只告警不杀，冷启动误报不误伤。
            if std::env::var("KS_ENFORCE").map(|v| v == "1").unwrap_or(false) {
                set_infer_config(&mut bpf, CFG_ENFORCE_MODE_IDX, 1);
                log::info!("阻断模式: enforce(verdict==2 内核态 SIGKILL)");
            } else {
                log::info!("阻断模式: monitor(默认，KS_ENFORCE=1 切换为 enforce)");
            }

            self.bpf = Some(Arc::new(Mutex::new(bpf)));
            log::info!(
                "eBPF {} 加载完成：{} 个程序已 attach",
                obj_name,
                self.probes.len()
            );
        }

        Ok(())
    }

    pub fn loaded_probes(&self) -> &[String] {
        &self.probes
    }

    /// round-robin轮询全部事件源，返回(来源名,字节)。
    /// Modern: 5 RingBuf；Legacy/Ancient: N×CPU PerfEventArray buffers。
    #[cfg(target_os = "linux")]
    pub fn try_next_events(&mut self) -> Option<(&'static str, Vec<u8>)> {
        use aya::maps::perf::PerfEvent;
        use std::ops::ControlFlow;

        match &mut self.backend {
            EventBackend::Empty => None,

            EventBackend::RingBuf { rings, idx } => {
                let n = rings.len();
                if n == 0 {
                    return None;
                }
                for _ in 0..n {
                    let i = *idx % n;
                    *idx = idx.wrapping_add(1);
                    let src = &mut rings[i];
                    if let Some(item) = src.ring.next() {
                        let bytes: &[u8] = &item;
                        return Some((src.name, bytes.to_vec()));
                    }
                }
                None
            }

            EventBackend::PerfEvent { buffers, idx } => {
                let n = buffers.len();
                if n == 0 {
                    return None;
                }
                for _ in 0..n {
                    let i = *idx % n;
                    *idx = idx.wrapping_add(1);
                    let pb = &mut buffers[i];
                    if !pb.buf.readable() {
                        continue;
                    }
                    let mut found: Option<(&'static str, Vec<u8>)> = None;
                    let map_name = pb.map_name;
                    let cpu_id = pb.cpu_id;
                    let fold_result = pb.buf.try_fold((), |_, evt| match evt {
                        PerfEvent::Sample { head, tail } => {
                            let mut data = head.to_vec();
                            data.extend_from_slice(tail);
                            found = Some((map_name, data));
                            ControlFlow::Break(())
                        }
                        PerfEvent::Lost { count } => {
                            log::warn!(
                                "[perfbuf] lost {} events on {} cpu {}",
                                count,
                                map_name,
                                cpu_id
                            );
                            ControlFlow::Continue(())
                        }
                    });
                    let _ = fold_result;
                    if found.is_some() {
                        return found;
                    }
                }
                None
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn try_next_events(&mut self) -> Option<(&'static str, Vec<u8>)> {
        None
    }

    /// 兼容旧调用方（start.rs）：仅返回字节，丢弃来源标签。
    pub fn try_next_event(&mut self) -> Option<Vec<u8>> {
        self.try_next_events().map(|(_, bytes)| bytes)
    }

    pub async fn stop_all(&mut self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.backend = EventBackend::Empty;
            self.bpf.take();
            log::info!("eBPF 探针已卸载");
        }
        Ok(())
    }

    /// Phase E1.2：返回BPF map读取器。
    ///
    /// - Linux且bpf已加载：返回`LinuxBpfMapReader`（克隆`Arc<Mutex<Ebpf>>`共享同一Ebpf，读5个共享map的真实map_type/max_entries）。
    /// - 否则返回`None`，调用方用`MockBpfMapReader`兜底。返回`Option<Arc<dyn BpfMapReader>>`以避免trait object生命周期问题。
    pub fn map_reader(&self) -> Option<Arc<dyn BpfMapReader>> {
        #[cfg(target_os = "linux")]
        {
            self.bpf.as_ref().map(|bpf| {
                Arc::new(crate::linux_map_reader::LinuxBpfMapReader::new(bpf.clone()))
                    as Arc<dyn BpfMapReader>
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

// 测试

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_list_contains_all_16_programs() {
        let loader = EbpfLoader::new();
        assert_eq!(loader.probes.len(), 16);
        // 确保关键探针都在
        assert!(loader.probes.contains(&"trace_sys_enter".to_string()));
        assert!(loader.probes.contains(&"trace_sys_exit".to_string()));
        assert!(loader.probes.contains(&"kprobe_tcp_connect".to_string()));
        assert!(loader.probes.contains(&"kprobe_commit_creds".to_string()));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn test_online_cpus_nonempty() {
        let cpus = online_cpus();
        assert!(!cpus.is_empty());
        assert!(cpus.iter().all(|&c| c < 1024));
    }

    #[test]
    fn test_mock_map_reader_list_map_stats() {
        let mr = MockBpfMapReader;
        let stats = mr.list_map_stats();
        assert_eq!(stats.len(), 5, "MockBpfMapReader 应返回 5 个共享 map 统计");
        assert_eq!(stats[0].name, "risk_scores");
        assert_eq!(stats[4].name, "infer_config");
        assert!(stats.iter().all(|s| s.entry_count == 0));
    }

    #[test]
    fn test_mock_map_reader_list_maps_matches_stats() {
        let mr = MockBpfMapReader;
        let maps = mr.list_maps();
        let stats = mr.list_map_stats();
        assert_eq!(maps.len(), stats.len());
        for (m, s) in maps.iter().zip(stats.iter()) {
            assert_eq!(m, &s.name);
        }
    }

    /// Phase E1.2：map_reader()在bpf未加载（EbpfLoader::new()）时应返回None。
    #[test]
    fn test_map_reader_none_when_not_loaded() {
        let loader = EbpfLoader::new();
        assert!(loader.map_reader().is_none());
    }

    /// G2.4: MockBpfMapReader.read_map_structured返回6个map的结构化桩数据。
    #[test]
    fn test_mock_read_map_structured_all_maps() {
        let mr = MockBpfMapReader;
        for name in &[
            "process_tree",
            "net_flows",
            "freq_counters",
            "filter_stats",
            "risk_scores",
            "block_decisions",
        ] {
            let entries = mr.read_map_structured(name);
            assert!(!entries.is_empty(), "map {} 应返回非空桩数据", name);
            // 每个entry应是JSON对象
            for entry in &entries {
                assert!(entry.is_object(), "entry 应为 JSON 对象: {}", entry);
            }
        }
    }

    /// G2.4: 未知map名返回空数组（trait默认行为）。
    #[test]
    fn test_mock_read_map_structured_unknown_returns_empty() {
        let mr = MockBpfMapReader;
        assert!(mr.read_map_structured("nonexistent_map").is_empty());
    }

    /// G2.4: risk_scores桩数据包含pid + risk_score + level字段。
    #[test]
    fn test_mock_read_map_structured_risk_scores_schema() {
        let mr = MockBpfMapReader;
        let entries = mr.read_map_structured("risk_scores");
        assert_eq!(entries.len(), 3);
        for entry in &entries {
            let obj = entry.as_object().unwrap();
            assert!(obj.contains_key("pid"));
            assert!(obj.contains_key("risk_score"));
            assert!(obj.contains_key("level"));
            let level = obj["level"].as_str().unwrap();
            assert!(["low", "medium", "high", "critical"].contains(&level));
        }
    }

    /// G2.4: process_tree桩数据包含父子关系（ppid链）。
    #[test]
    fn test_mock_read_map_structured_process_tree_chain() {
        let mr = MockBpfMapReader;
        let entries = mr.read_map_structured("process_tree");
        assert_eq!(entries.len(), 3);
        // sshd(1234) → bash(2345) → nc(3456)父子链
        let sshd = entries[0].as_object().unwrap();
        let bash = entries[1].as_object().unwrap();
        let nc = entries[2].as_object().unwrap();
        assert_eq!(sshd["pid"].as_u64(), Some(1234));
        assert_eq!(sshd["ppid"].as_u64(), Some(1));
        assert_eq!(bash["ppid"].as_u64(), Some(1234)); // bash 父是 sshd
        assert_eq!(nc["ppid"].as_u64(), Some(2345)); // nc 父是 bash
    }

    /// G2.4: block_decisions桩数据包含expire_ns + reason字段。
    #[test]
    fn test_mock_read_map_structured_block_decisions() {
        let mr = MockBpfMapReader;
        let entries = mr.read_map_structured("block_decisions");
        assert_eq!(entries.len(), 2);
        for entry in &entries {
            let obj = entry.as_object().unwrap();
            assert!(obj.contains_key("pid"));
            assert!(obj.contains_key("expire_ns"));
            assert!(obj.contains_key("reason"));
            assert!(obj.contains_key("reason_code"));
        }
    }

    /// D1: 内嵌eBPF字节码可按tier取出，且为合法ELF（\x7fELF魔数）。
    #[cfg(target_os = "linux")]
    #[test]
    fn test_ebpf_objects_embedded_and_elf() {
        // modern tier build.rs保证必编译成功 → 内嵌常量必存在。
        let modern = super::ebpf_objects::ebpf_object_for("modern")
            .expect("modern tier .o 应内嵌进二进制");
        assert!(modern.len() > 1024, "modern .o 字节数异常小: {}", modern.len());
        assert_eq!(&modern[..4], b"\x7fELF", "modern .o 不是 ELF（首4字节不匹配）");
        // 其他tier：编译成功则内嵌且为ELF；未编译返回None（不panic）。
        for suffix in ["legacy", "ancient", "ancient_nobtf"] {
            if let Some(bytes) = super::ebpf_objects::ebpf_object_for(suffix) {
                assert_eq!(&bytes[..4], b"\x7fELF", "{} .o 不是 ELF", suffix);
            }
        }
        // 未知tier返回None（fail loud契约，不静默回退磁盘）。
        assert!(super::ebpf_objects::ebpf_object_for("nonexistent").is_none());
    }
}

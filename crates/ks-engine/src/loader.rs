use crate::event_source::SourceKind;

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

#[derive(Debug, Clone)]
pub struct MapStat {
    pub name: String,
    pub map_type: String,
    pub entry_count: usize,
}

pub trait BpfMapReader: Send + Sync {
    fn read_map(&self, map_name: &str) -> anyhow::Result<MapSnapshot>;
    fn list_maps(&self) -> Vec<String>;
    fn list_map_stats(&self) -> Vec<MapStat>;
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
            "protected_comms".into(),
        ]
    }
    fn list_map_stats(&self) -> Vec<MapStat> {
        vec![
            MapStat { name: "risk_scores".into(), map_type: "HASH".into(), entry_count: 0 },
            MapStat { name: "ip_whitelist".into(), map_type: "HASH".into(), entry_count: 0 },
            MapStat { name: "net_conn_history".into(), map_type: "LRU_HASH".into(), entry_count: 0 },
            MapStat { name: "freq_counters".into(), map_type: "PERCPU_ARRAY".into(), entry_count: 0 },
            MapStat { name: "infer_config".into(), map_type: "ARRAY".into(), entry_count: 0 },
            MapStat { name: "protected_comms".into(), map_type: "LRU_HASH".into(), entry_count: 0 },
        ]
    }

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

#[cfg(target_os = "linux")]
struct PerfEventBuffer {
    map_name: &'static str,
    cpu_id: u32,
    buf: aya::maps::perf::PerfEventArrayBuffer<aya::maps::MapData>,
}

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
    probes: Vec<String>,
    #[cfg(target_os = "linux")]
    backend: EventBackend,
    #[cfg(target_os = "linux")]
    bpf: Option<Arc<Mutex<aya::Ebpf>>>,
    protected_pids: Vec<u32>,
}

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

#[cfg(target_os = "linux")]
impl Drop for EbpfLoader {
    fn drop(&mut self) {
        if let Some((enter, exit, drop)) = self.read_syscount() {
            eprintln!(
                "[syscount] kernel enter={} exit={} ringbuf_drop={}",
                enter, exit, drop
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn inject_protected_pid(bpf: &mut aya::Ebpf, self_pid: u32) -> Vec<u32> {
    use aya::maps::HashMap;
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
            Err(e) => log::warn!("打开 protected_pids map 失败: {:?}(豁免未生效,阻断可能误杀自身)", e),
        },
        None => log::warn!("protected_pids map 不存在(豁免未生效)"),
    }
    pids
}

#[cfg(not(target_os = "linux"))]
fn inject_protected_pid(_bpf: &mut (), _self_pid: u32) {}

const DEFAULT_PROTECTED_COMMS: &[&str] = &[
    "sshd", "systemd", "cron", "crond", "journald", "dbus-daemon",
    "sudo", "login", "agetty", "rsyslogd", "systemd-journal",
];

#[cfg(target_os = "linux")]
fn inject_protected_comms(bpf: &mut aya::Ebpf) -> Vec<String> {
    use aya::maps::HashMap;
    let mut comms: Vec<String> = DEFAULT_PROTECTED_COMMS.iter().map(|s| s.to_string()).collect();
    if let Ok(extra) = std::env::var("KS_PROTECTED_COMMS") {
        for c in extra.split(',') {
            let c = c.trim();
            if !c.is_empty() && !comms.iter().any(|x| x == c) {
                comms.push(c.to_string());
            }
        }
    }
    let val: u8 = 1;
    match bpf.map_mut("protected_comms") {
        Some(m) => match HashMap::<_, [u8; 16], u8>::try_from(m) {
            Ok(mut hm) => {
                let mut injected = Vec::new();
                for c in &comms {
                    let mut key = [0u8; 16];
                    let b = c.as_bytes();
                    let n = b.len().min(15);
                    key[..n].copy_from_slice(&b[..n]);
                    if let Err(e) = hm.insert(&key, &val, 0) {
                        log::warn!("写入 protected_comms 失败({}): {:?}", c, e);
                    } else {
                        injected.push(c.clone());
                    }
                }
                log::info!("已注入 protected_comms 白名单({}项): {:?}", injected.len(), injected);
            }
            Err(e) => log::warn!("打开 protected_comms map 失败: {:?}(enforce误杀风险)", e),
        },
        None => log::warn!("protected_comms map 不存在(enforce误杀风险)"),
    }
    comms
}

#[cfg(not(target_os = "linux"))]
fn inject_protected_comms(_bpf: &mut ()) {}

const CFG_ENFORCE_MODE_IDX: u32 = 5;
const CFG_ENFORCE_WARMUP_UNTIL_SEC_IDX: u32 = 6;
const CFG_ENFORCE_KILL_THRESHOLD_IDX: u32 = 7;

#[cfg(target_os = "linux")]
fn boot_monotonic_sec() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok().and_then(|s| s.split_whitespace().next().and_then(|v| v.parse::<f64>().ok()))
        .map(|f| f as u64).unwrap_or(0)
}

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
            protected_pids: Vec::new(),
        }
    }

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
                        ("ks_main_ancient_nobtf.o", "ancient_nobtf")
                    }
                }
                SourceKind::EbpfLegacyNoBtf | SourceKind::EbpfAncientNoBtf => {
                    anyhow::bail!(
                        "{:?} 应由CLoaderSource加载,不应走aya start_all(检查default_event_source分支)",
                        tier
                    )
                }
                _ => anyhow::bail!("不支持的eBPF tier: {:?}", tier),
            };

            let obj: Vec<u8> = if let Ok(dir) = std::env::var("KS_EBPF_DIR") {
                let obj_path = std::path::Path::new(&dir).join(obj_name);
                std::fs::read(&obj_path).map_err(|e| {
                    anyhow::anyhow!(
                        "KS_EBPF_DIR覆盖读取{}失败: {}",
                        obj_path.display(),
                        e
                    )
                })?
            } else {
                ebpf_objects::ebpf_object_for(tier_suffix)
                    .map(|b| b.to_vec())
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "二进制内无内嵌{}(编译期该tier未成功编译);\
                             如需指定外部.o,设KS_EBPF_DIR环境变量",
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
                    if matches!(tier, SourceKind::EbpfAncient)
                        && !crate::tier_detect::btf_available()
                    {
                        return Err(anyhow::anyhow!(
                            "aya加载{}失败: {} - 建议用CLoaderSource(ks_loader --stream)替代aya加载",
                            obj_name, e,
                        ));
                    }
                    return Err(anyhow::anyhow!("aya加载{}失败: {}", obj_name, e));
                }
            };

            macro_rules! attach_tp {
                ($name:expr, $cat:expr, $evt:expr) => {
                    let prog: &mut aya::programs::TracePoint = bpf
                        .program_mut($name)
                        .ok_or_else(|| anyhow::anyhow!("tracepoint程序'{}'未找到", $name))?
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

            macro_rules! attach_kp {
                ($name:expr, $func:expr) => {
                    let prog: &mut aya::programs::KProbe = bpf
                        .program_mut($name)
                        .ok_or_else(|| anyhow::anyhow!("kprobe程序'{}'未找到", $name))?
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
            attach_kp!("kprobe_commit_creds", "commit_creds");
            attach_kp!("kprobe_do_init_module", "do_init_module");
            match (|| -> anyhow::Result<()> {
                attach_kp!("kprobe_security_bpf_prog_free", "security_bpf_prog_free");
                Ok(())
            })() {
                Ok(()) => {}
                Err(e) => log::warn!("[loader] security_bpf_prog_free attach失败(忽略): {}", e),
            }

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

            let prot_pids = inject_protected_pid(&mut bpf, std::process::id());
            self.protected_pids = prot_pids;
            inject_protected_comms(&mut bpf);
            if std::env::var("KS_ENFORCE").map(|v| v == "1").unwrap_or(false) {
                set_infer_config(&mut bpf, CFG_ENFORCE_MODE_IDX, 1);
                let warmup_sec: u64 = std::env::var("KS_ENFORCE_WARMUP_SEC")
                    .ok().and_then(|s| s.parse().ok()).unwrap_or(120);
                let kill_thr: u32 = std::env::var("KS_ENFORCE_KILL_THRESHOLD")
                    .ok().and_then(|s| s.parse().ok()).unwrap_or(70);
                let warmup_until = boot_monotonic_sec().saturating_add(warmup_sec);
                set_infer_config(&mut bpf, CFG_ENFORCE_WARMUP_UNTIL_SEC_IDX, warmup_until as u32);
                set_infer_config(&mut bpf, CFG_ENFORCE_KILL_THRESHOLD_IDX, kill_thr);
                log::info!(
                    "阻断模式: enforce(verdict==2内核态SIGKILL) 干跑期={}s kill阈值={}",
                    warmup_sec, kill_thr
                );
            } else {
                log::info!("阻断模式: monitor(默认,KS_ENFORCE=1切换为enforce)");
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

    pub fn protected_pids(&self) -> &[u32] {
        &self.protected_pids
    }

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

    #[cfg(target_os = "linux")]
    pub fn read_syscount(&self) -> Option<(u64, u64, u64)> {
        use aya::maps::PerCpuArray;
        let bpf = self.bpf.as_ref()?.lock().ok()?;
        let arr = PerCpuArray::<_, [u64; 3]>::try_from(bpf.map("syscount_map")?).ok()?;
        let vals = arr.get(&0, 0).ok()?;
        let (mut enter, mut exit, mut drop) = (0u64, 0u64, 0u64);
        for v in vals.iter() {
            enter += v[0];
            exit += v[1];
            drop += v[2];
        }
        Some((enter, exit, drop))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn read_syscount(&self) -> Option<(u64, u64, u64)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_probe_list_contains_all_16_programs() {
        let loader = EbpfLoader::new();
        assert_eq!(loader.probes.len(), 16);
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
        assert_eq!(stats.len(), 6, "MockBpfMapReader 应返回 6 个共享 map 统计");
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

    #[test]
    fn test_map_reader_none_when_not_loaded() {
        let loader = EbpfLoader::new();
        assert!(loader.map_reader().is_none());
    }

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
            assert!(!entries.is_empty(), "map {}应返回非空桩数据", name);
            for entry in &entries {
                assert!(entry.is_object(), "entry应为JSON对象: {}", entry);
            }
        }
    }

    #[test]
    fn test_mock_read_map_structured_unknown_returns_empty() {
        let mr = MockBpfMapReader;
        assert!(mr.read_map_structured("nonexistent_map").is_empty());
    }

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

    #[test]
    fn test_mock_read_map_structured_process_tree_chain() {
        let mr = MockBpfMapReader;
        let entries = mr.read_map_structured("process_tree");
        assert_eq!(entries.len(), 3);
        let sshd = entries[0].as_object().unwrap();
        let bash = entries[1].as_object().unwrap();
        let nc = entries[2].as_object().unwrap();
        assert_eq!(sshd["pid"].as_u64(), Some(1234));
        assert_eq!(sshd["ppid"].as_u64(), Some(1));
        assert_eq!(bash["ppid"].as_u64(), Some(1234));
        assert_eq!(nc["ppid"].as_u64(), Some(2345));
    }

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

    #[cfg(target_os = "linux")]
    #[test]
    fn test_ebpf_objects_embedded_and_elf() {
        let modern = super::ebpf_objects::ebpf_object_for("modern")
            .expect("modern tier .o应内嵌进二进制");
        assert!(modern.len() > 1024, "modern .o字节数异常小: {}", modern.len());
        assert_eq!(&modern[..4], b"\x7fELF", "modern .o不是ELF(首4字节不匹配)");
        for suffix in ["legacy", "ancient", "ancient_nobtf"] {
            if let Some(bytes) = super::ebpf_objects::ebpf_object_for(suffix) {
                assert_eq!(&bytes[..4], b"\x7fELF", "{} .o不是ELF", suffix);
            }
        }
        assert!(super::ebpf_objects::ebpf_object_for("nonexistent").is_none());
    }
}

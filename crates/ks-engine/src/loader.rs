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

    /// 向内核 `block_decisions` map 写入一条阻断裁决（ADR-011 闭环的用户态写入点）。
    ///
    /// `expire_monotonic_ns` 与内核 `bpf_ktime_get_ns()` 同源（CLOCK_MONOTONIC），
    /// `0` = 永久阻断；`reason` 编码 1..5 与 `BlockReason` 对齐。
    /// 默认实现返回错误：mock / C loader（NOBTF）路径没有用户态 map 句柄，
    /// 调用方（BlockManager）收到错误后降级为仅记录用户态表。
    fn write_block_decision(&self, _pid: u32, _expire_monotonic_ns: u64, _reason: u8) -> anyhow::Result<()> {
        anyhow::bail!("当前 map reader 不支持写 block_decisions（非 aya 加载路径或 mock）")
    }

    /// 解除内核侧阻断裁决（删除 block_decisions 条目）。默认实现同上。
    fn remove_block_decision(&self, _pid: u32) -> anyhow::Result<()> {
        anyhow::bail!("当前 map reader 不支持写 block_decisions（非 aya 加载路径或 mock）")
    }

    /// 读全表 (pid, expire_monotonic_ns, reason)，供非 Modern tier 的用户态 killer 使用。
    /// 默认空：mock / C loader 路径无 map 句柄，killer 拿不到裁决自然不动作。
    fn read_block_decisions(&self) -> Vec<(u32, u64, u8)> {
        Vec::new()
    }

    /// 把 block_decisions map pin 到 bpffs，供 `ks block` 等独立进程跨进程访问。
    fn pin_block_map(&self, _path: &str) -> anyhow::Result<()> {
        anyhow::bail!("当前 map reader 不支持 pin block_decisions（非 aya 加载路径或 mock）")
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
    attached_probes: usize,
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
                    if let Err(e) = hm.insert(pid, val, 0) {
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

pub const DEFAULT_PROTECTED_COMMS: &[&str] = &[
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
                    if let Err(e) = hm.insert(key, val, 0) {
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

/// 内核符号是否存在。
///
/// kprobe 的目标函数在版本间会增删（3.10 没有 do_init_module，同名功能是 load_module），
/// 而 attach 失败会沿着 `?` 一路冒泡、把整个 tier 拖进 mock 回退。逐探针检查可以让
/// 缺失的符号只影响它自己。
///
/// kallsyms 读不到时返回 true：不做判断，交给 attach 自己报错，避免把"读不到"
/// 误判成"符号不存在"而静默少挂探针。
#[cfg(target_os = "linux")]
fn symbol_exists(name: &str) -> bool {
    static SYMBOLS: std::sync::OnceLock<Option<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    match SYMBOLS.get_or_init(|| {
        let text = std::fs::read_to_string("/proc/kallsyms").ok()?;
        Some(
            text.lines()
                .filter_map(|l| l.split_whitespace().nth(2).map(String::from))
                .collect(),
        )
    }) {
        None => true,
        Some(syms) => syms.contains(name),
    }
}

#[cfg(not(target_os = "linux"))]
fn symbol_exists(_name: &str) -> bool {
    true
}

/// kprobe_events 路径（老内核的 debugfs 实现）。
#[cfg(target_os = "linux")]
const KPROBE_EVENTS: &str = "/sys/kernel/debug/tracing/kprobe_events";

/// 从 kprobe_events 内容里挑出"所有者进程已不存在"的探针条目。
///
/// 两类条目都带 pid，pid 即创建它的进程：
///   aya 侧 `aya_<pid>_<type>_<func>_<off>_<idx>`；ks_loader 侧 `ks<pid>_<func>`。
/// 进程被 SIGKILL（崩溃，或父进程 kill_on_drop）时无人清理条目，反复重启会累积。
/// 只清理 pid 已消失的条目，不碰仍在运行的实例的探针；旧格式 `ks_<func>` 没有
/// pid 无法归属，不在此列（需人工确认后清理）。
fn stale_probe_tags(kprobe_events: &str, pid_alive: impl Fn(u32) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    for line in kprobe_events.lines() {
        let rest = match line.strip_prefix("p:kprobes/").or_else(|| line.strip_prefix("r:kprobes/")) {
            Some(r) => r,
            None => continue,
        };
        let Some(tag) = rest.split_whitespace().next() else {
            continue;
        };
        let pid = if let Some(mid) = tag.strip_prefix("aya_") {
            mid.split('_').next().and_then(|p| p.parse::<u32>().ok())
        } else if let Some(mid) = tag.strip_prefix("ks") {
            mid.split('_').next().and_then(|p| p.parse::<u32>().ok())
        } else {
            None
        };
        if let Some(pid) = pid {
            if !pid_alive(pid) {
                out.push(tag.to_string());
            }
        }
    }
    out
}

/// 清理上一条命被强杀时残留的 aya kprobe 条目，返回清理条数。
#[cfg(target_os = "linux")]
fn sweep_stale_probes() -> usize {
    let Ok(content) = std::fs::read_to_string(KPROBE_EVENTS) else {
        return 0;
    };
    let stale = stale_probe_tags(&content, |pid| {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    });
    if stale.is_empty() {
        return 0;
    }
    let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(KPROBE_EVENTS) else {
        log::warn!(
            "[loader] {} 不可写，{} 条残留探针未清理",
            KPROBE_EVENTS,
            stale.len()
        );
        return 0;
    };
    use std::io::Write as _;
    let mut n = 0;
    for tag in &stale {
        // 必须一次 write 写完一整条命令：tracefs 按"每次 write 一条命令"处理，
        // writeln! 会拆成多次 write("-:kprobes/", tag, "\n")，内核按半条命令解析
        // 会返回错误（条目虽可能被缓冲后生效，但返回值不可信）
        let cmd = format!("-:kprobes/{tag}\n");
        if f.write_all(cmd.as_bytes()).is_ok() {
            n += 1;
        }
    }
    n
}

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
            "kprobe_do_splice_direct",
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
            attached_probes: 0,
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

            // NOBTF 对象在构建期已剥离 .BTF.ext，CO-RE 重定位对它本就是 no-op：
            // 它依赖 common.h 里针对 3.10.0-1160 实测的硬编码偏移，所以这里必须补
            // release 守卫——旧实现会把它加载到任意 3.10 内核上，偏移不匹配时探针
            // 照常 attach、读的却是错误字段。
            // 其余 tier 必须拿到目标内核 BTF：aya 在没有 BTF 时会静默跳过重定位，
            // 带着编译期（vmlinux.h 来源内核的）偏移继续加载，同样是静默错数据，
            // 因此这里直接失败而不是降级。
            let btf = if tier_suffix.ends_with("_nobtf") {
                crate::tier_detect::nobtf_release_compatible().map_err(|reason| {
                    anyhow::anyhow!("{} 依赖硬编码偏移，拒绝加载: {}", obj_name, reason)
                })?;
                log::warn!(
                    "[loader] {} 走 NOBTF 硬编码偏移路径（无 CO-RE 重定位）",
                    obj_name
                );
                None
            } else {
                let (btf, origin) = crate::btf_source::load_target_btf()
                    .map_err(|e| anyhow::anyhow!("aya加载{}失败: {}", obj_name, e))?;
                log::info!("[loader] CO-RE 重定位 BTF 来源: {}", origin);
                Some(btf)
            };

            // 注: EbpfLoader::new() 内部会先按 /sys/kernel/btf/vmlinux 解析一次，
            // 随即被 btf() 覆盖；多出的这一次解析只在启动期发生，可接受。
            let mut bpf = aya::EbpfLoader::new()
                .btf(btf.as_ref())
                .load(&obj)
                .map_err(|e| anyhow::anyhow!("aya加载{}失败: {}", obj_name, e))?;

            let mut n_attached = 0usize;
            let mut n_skipped = 0usize;

            macro_rules! attach_tp {
                ($name:expr, $cat:expr, $evt:expr) => {
                    let prog: &mut aya::programs::TracePoint = bpf
                        .program_mut($name)
                        .ok_or_else(|| anyhow::anyhow!("tracepoint程序'{}'未找到", $name))?
                        .try_into()?;
                    prog.load()?;
                    prog.attach($cat, $evt)?;
                    n_attached += 1;
                };
            }
            attach_tp!("trace_sys_enter", "raw_syscalls", "sys_enter");
            attach_tp!("trace_sys_exit", "raw_syscalls", "sys_exit");
            attach_tp!("trace_sched_fork", "sched", "sched_process_fork");
            attach_tp!("trace_sched_exec_tree", "sched", "sched_process_exec");
            attach_tp!("trace_sched_exit_tree", "sched", "sched_process_exit");

            // 清掉上次被强杀时残留的 aya kprobe 条目（entry 生命周期随 PerfLink，
            // 但 SIGKILL 下没人 drop）
            match sweep_stale_probes() {
                0 => {}
                n => log::warn!("[loader] 清理了 {} 条上次残留的 kprobe 条目", n),
            }

            macro_rules! attach_kp {
                ($name:expr, $func:expr) => {
                    if !symbol_exists($func) {
                        log::warn!(
                            "[loader] 内核无符号 {}，跳过探针 {}（不影响其它探针）",
                            $func,
                            $name
                        );
                        n_skipped += 1;
                    } else {
                        let prog: &mut aya::programs::KProbe = bpf
                            .program_mut($name)
                            .ok_or_else(|| anyhow::anyhow!("kprobe程序'{}'未找到", $name))?
                            .try_into()?;
                        prog.load()?;
                        prog.attach($func, 0)?;
                        n_attached += 1;
                    }
                };
            }
            attach_kp!("kprobe_vfs_open", "vfs_open");
            attach_kp!("kprobe_vfs_write", "vfs_write");
            attach_kp!("kprobe_do_splice_direct", "do_splice_direct");
            attach_kp!("kprobe_vfs_unlink", "vfs_unlink");
            attach_kp!("kprobe_tcp_connect", "tcp_v4_connect");
            attach_kp!("kprobe_tcp_v6_connect", "tcp_v6_connect");
            attach_kp!("kprobe_udp_sendmsg", "udp_sendmsg");
            attach_kp!("kprobe_tcp_set_state_flow", "tcp_set_state");
            attach_kp!("kprobe_tcp_sendmsg_flow", "tcp_sendmsg");
            attach_kp!("kprobe_commit_creds", "commit_creds");
            // 模块加载：3.10 没有 do_init_module，回退到 load_module 的 kretprobe
            // （返回值即 struct module *），取的是同一份信息
            if symbol_exists("do_init_module") {
                attach_kp!("kprobe_do_init_module", "do_init_module");
            } else if symbol_exists("load_module") {
                attach_kp!("kretprobe_load_module", "load_module");
            } else {
                log::warn!("[loader] 内核既无 do_init_module 也无 load_module，无法检测模块加载");
                n_skipped += 1;
            }
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
                    cpus.len() * RING_NAMES.len(),
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

            self.attached_probes = n_attached;
            self.bpf = Some(Arc::new(Mutex::new(bpf)));
            if n_skipped > 0 {
                log::warn!(
                    "eBPF {} 加载完成：{} 个程序已 attach，{} 个因内核缺符号跳过（配置共 {} 个）",
                    obj_name,
                    n_attached,
                    n_skipped,
                    self.probes.len()
                );
            } else {
                log::info!(
                    "eBPF {} 加载完成：{} 个程序已 attach",
                    obj_name,
                    n_attached
                );
            }
        }

        Ok(())
    }

    pub fn loaded_probes(&self) -> &[String] {
        &self.probes
    }

    /// 实际 attach 成功的探针数（`loaded_probes` 是配置清单，含因内核缺符号被跳过的）
    pub fn attached_probe_count(&self) -> usize {
        self.attached_probes
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
    fn test_stale_probe_tags_only_dead_pids() {
        let content = "\
p:kprobes/aya_100_p_vfs_open_0x0_0 vfs_open
p:kprobes/aya_200_p_vfs_write_0x0_1 vfs_write
p:kprobes/ks300_vfs_unlink vfs_unlink
p:kprobes/ks100_commit_creds commit_creds
p:kprobes/ks_vfs_open vfs_open
r:kprobes/aya_100_r_tcp_sendmsg_0x0_2 tcp_sendmsg
r:kprobes/aya_999_r_load_module_0x0_9 load_module
p:kprobes/aya_notapid_p_vfs_open_0x0_0 vfs_open
garbage line
";
        let alive = |pid: u32| pid == 100;
        let stale = stale_probe_tags(content, alive);
        assert_eq!(
            stale,
            vec![
                "aya_200_p_vfs_write_0x0_1".to_string(),
                "ks300_vfs_unlink".to_string(),
                "aya_999_r_load_module_0x0_9".to_string(),
            ],
            "只清 pid 已消失的（含 r: 条目）；旧格式 ks_<func> 与存活 pid 都要保留"
        );
    }

    #[test]
    fn test_stale_probe_tags_empty_input() {
        assert!(stale_probe_tags("", |_| false).is_empty());
    }

    #[test]
    fn test_probe_list_contains_all_17_programs() {
        let loader = EbpfLoader::new();
        assert_eq!(loader.probes.len(), 17);
        assert!(loader.probes.contains(&"trace_sys_enter".to_string()));
        assert!(loader.probes.contains(&"trace_sys_exit".to_string()));
        assert!(loader.probes.contains(&"kprobe_do_splice_direct".to_string()));
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

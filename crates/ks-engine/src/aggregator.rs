use anyhow::Result;
use ks_core::event::{af, EventHeader, RawEvent};
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

pub struct EventAggregator {
    // 存 Arc 避免热路径上每事件深拷贝一次进缓冲（DecodedEvent 含 6+ 个 String）
    buffer: VecDeque<Arc<DecodedEvent>>,
    max_buffer: usize,
    seq: u64,
    pid_windows: HashMap<u32, VecDeque<u64>>,
    max_pids: usize,
    // FIFO 淘汰队列：pid 首次出现时入队。空窗口（pid 已退出）直接淘汰，
    // 仍有 60s 内活动的窗口重排队——O(1) 摊销，替代旧实现每次全 map min_by_key 扫描
    evict_queue: VecDeque<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedEvent {
    pub seq: u64,
    pub header: EventHeader,
    pub comm: String,
    pub filename: Option<String>,
    pub args: Option<String>,
    pub saddr: Option<String>,
    pub daddr: Option<String>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
    pub proto: Option<String>,
    pub target_pid: Option<u32>,
    pub signal: Option<i32>,
    pub file_bytes: Option<u64>,
    pub module_name: Option<String>,
    pub prog_name: Option<String>,
    pub source_ns_inum: Option<u32>,
    pub target_ns_inum: Option<u32>,
    pub cap_eff: Option<u32>,
    pub action: Option<String>,
}

impl EventAggregator {
    pub fn new(max_buffer: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(max_buffer),
            max_buffer,
            seq: 0,
            pid_windows: HashMap::new(),
            max_pids: 10000,
            evict_queue: VecDeque::new(),
        }
    }

    /// 返回 Arc：调用方拿到的事件与内部缓冲共享同一份，免一次深拷贝
    pub fn decode(&mut self, data: &[u8]) -> Result<Arc<DecodedEvent>> {
        let raw = RawEvent::from_bytes(data)
            .ok_or_else(|| anyhow::anyhow!("事件数据不足: {} 字节", data.len()))?;

        let event_type = raw.event_type();
        let header = raw.header;
        let payload = raw.payload;
        let comm = cstr_to_string(&header.comm);

        let decoded = match event_type {
            1 => {
                let fname = cstr_to_string(&payload.filename);
                let args = exec_args_to_cmdline(&payload.args);
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: if fname.is_empty() { None } else { Some(fname) },
                    args,
                    saddr: None,
                    daddr: None,
                    sport: None,
                    dport: None,
                    proto: None,
                    target_pid: None,
                    signal: None,
                    file_bytes: None,
                    module_name: None,
                    prog_name: None,
                    source_ns_inum: None,
                    target_ns_inum: None,
                    cap_eff: None,
                    action: None,
                }
            }
            10..=15 => {
                let fname = cstr_to_string(&payload.filename);
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: if fname.is_empty() { None } else { Some(fname) },
                    args: None,
                    saddr: None,
                    daddr: None,
                    sport: None,
                    dport: None,
                    proto: None,
                    target_pid: None,
                    signal: None,
                    file_bytes: if payload.bytes > 0 {
                        Some(payload.bytes)
                    } else {
                        None
                    },
                    module_name: None,
                    prog_name: None,
                    source_ns_inum: None,
                    target_ns_inum: None,
                    cap_eff: None,
                    action: None,
                }
            }
            20..=24 => {
                let (saddr, daddr) = if payload.family == af::AF_INET6 {
                    (
                        Some(ipv6_to_string(&payload.saddr6)),
                        Some(ipv6_to_string(&payload.daddr6)),
                    )
                } else {
                    (Some(ip_to_string(payload.saddr)), Some(ip_to_string(payload.daddr)))
                };
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: None,
                    args: None,
                    saddr,
                    daddr,
                    sport: Some(payload.sport),
                    dport: Some(payload.dport),
                    proto: Some(
                        if payload.proto == 6 {
                            "TCP"
                        } else if payload.proto == 17 {
                            "UDP"
                        } else {
                            "OTHER"
                        }
                        .to_string(),
                    ),
                    target_pid: None,
                    signal: None,
                    file_bytes: None,
                    module_name: None,
                    prog_name: None,
                    source_ns_inum: None,
                    target_ns_inum: None,
                    cap_eff: None,
                    action: None,
                }
            }
            30 | 31 => {
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: None,
                    args: None,
                    saddr: None,
                    daddr: None,
                    sport: None,
                    dport: None,
                    proto: None,
                    target_pid: Some(payload.target_pid),
                    signal: Some(payload.signal),
                    file_bytes: None,
                    module_name: None,
                    prog_name: None,
                    source_ns_inum: None,
                    target_ns_inum: None,
                    cap_eff: None,
                    action: None,
                }
            }
            2 | 3 => DecodedEvent {
                seq: 0,
                header,
                comm,
                filename: None,
                args: None,
                saddr: None,
                daddr: None,
                sport: None,
                dport: None,
                proto: None,
                target_pid: None,
                signal: None,
                file_bytes: None,
                module_name: None,
                prog_name: None,
                source_ns_inum: None,
                target_ns_inum: None,
                cap_eff: None,
                action: None,
            },
            80 => {
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: None,
                    args: None,
                    saddr: None,
                    daddr: None,
                    sport: None,
                    dport: None,
                    proto: None,
                    target_pid: None,
                    signal: None,
                    file_bytes: None,
                    module_name: None,
                    prog_name: None,
                    source_ns_inum: Some(payload.source_ns_inum),
                    target_ns_inum: Some(payload.target_ns_inum),
                    cap_eff: Some(payload.cap_eff),
                    action: None,
                }
            }
            81 => {
                let mname = cstr_to_string(&payload.module_name);
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: None,
                    args: None,
                    saddr: None,
                    daddr: None,
                    sport: None,
                    dport: None,
                    proto: None,
                    target_pid: None,
                    signal: None,
                    file_bytes: None,
                    module_name: if mname.is_empty() { None } else { Some(mname) },
                    prog_name: None,
                    source_ns_inum: None,
                    target_ns_inum: None,
                    cap_eff: None,
                    action: None,
                }
            }
            82 => {
                let pname = cstr_to_string(&payload.prog_name);
                let act = cstr_to_string(&payload.action);
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: None,
                    args: None,
                    saddr: None,
                    daddr: None,
                    sport: None,
                    dport: None,
                    proto: None,
                    target_pid: None,
                    signal: None,
                    file_bytes: None,
                    module_name: None,
                    prog_name: if pname.is_empty() { None } else { Some(pname) },
                    source_ns_inum: None,
                    target_ns_inum: None,
                    cap_eff: None,
                    action: if act.is_empty() { None } else { Some(act) },
                }
            }
            _ => {
                debug!("未知事件类型: {}", event_type);
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: None,
                    args: None,
                    saddr: None,
                    daddr: None,
                    sport: None,
                    dport: None,
                    proto: None,
                    target_pid: None,
                    signal: None,
                    file_bytes: None,
                    module_name: None,
                    prog_name: None,
                    source_ns_inum: None,
                    target_ns_inum: None,
                    cap_eff: None,
                    action: None,
                }
            }
        };

        self.seq += 1;
        let mut event = decoded;
        event.seq = self.seq;
        let event = Arc::new(event);

        if self.buffer.len() >= self.max_buffer {
            self.buffer.pop_front();
        }
        self.buffer.push_back(event.clone());

        {
            const WINDOW_NS: u64 = 60_000_000_000;
            let now_ns = event.header.timestamp_ns;
            let is_new_pid = !self.pid_windows.contains_key(&event.header.pid);
            let win = self.pid_windows.entry(event.header.pid).or_default();
            win.push_back(now_ns);
            while let Some(&front) = win.front() {
                if now_ns.saturating_sub(front) >= WINDOW_NS {
                    win.pop_front();
                } else {
                    break;
                }
            }
            if is_new_pid {
                self.evict_queue.push_back(event.header.pid);
            }
            if self.pid_windows.len() > self.max_pids {
                self.evict_stale_pids();
            }
        }

        debug!(
            "事件 #{}: type={} pid={} comm={}",
            self.seq, event_type, header.pid, event.comm
        );
        Ok(event)
    }

    /// O(1) 摊销的 pid 淘汰：FIFO 队列，空窗口（进程已退出/窗口已滑空）直接删，
    /// 仍有活动的窗口重排队。旧实现每淘汰一个就全 map min_by_key 扫一遍，
    /// 触发阈值时单事件热路径上千万级比较，造成延迟尖峰
    fn evict_stale_pids(&mut self) {
        let target = self.max_pids.saturating_sub(self.max_pids / 10);
        let mut attempts = 0usize;
        let max_attempts = self.evict_queue.len();
        while self.pid_windows.len() > target && attempts < max_attempts {
            attempts += 1;
            let Some(pid) = self.evict_queue.pop_front() else {
                break;
            };
            let is_active = self
                .pid_windows
                .get(&pid)
                .is_some_and(|w| !w.is_empty());
            if is_active {
                // 60s 窗口内仍活跃的 pid 重排队，不丢统计
                self.evict_queue.push_back(pid);
            } else {
                self.pid_windows.remove(&pid);
            }
        }
    }

    pub fn buffer(&self) -> &VecDeque<Arc<DecodedEvent>> {
        &self.buffer
    }

    pub fn by_pid(&self, pid: u32) -> Vec<&DecodedEvent> {
        self.buffer
            .iter()
            .filter(|e| e.header.pid == pid)
            .map(|e| e.as_ref())
            .collect()
    }

    /// 零拷贝变体（H-3）：返回缓冲内 Arc 的克隆（引用计数 +1），供攻击链还原
    /// 等只读消费方使用。旧路径 `by_pid().into_iter().cloned().collect()` 会把每
    /// 事件的 6+ 个 String 深拷贝一遍，是处理层 45% 开销的来源
    pub fn by_pid_arcs(&self, pid: u32) -> Vec<Arc<DecodedEvent>> {
        self.buffer
            .iter()
            .filter(|e| e.header.pid == pid)
            .cloned()
            .collect()
    }

    pub fn recent(&self, n: usize) -> Vec<&DecodedEvent> {
        let skip = if self.buffer.len() > n {
            self.buffer.len() - n
        } else {
            0
        };
        self.buffer
            .iter()
            .skip(skip)
            .map(|e| e.as_ref())
            .collect()
    }

    pub fn recent_syscall_count(&mut self, pid: u32, now_ns: u64) -> usize {
        const WINDOW_NS: u64 = 60_000_000_000;
        if let Some(win) = self.pid_windows.get_mut(&pid) {
            while let Some(&front) = win.front() {
                if now_ns.saturating_sub(front) >= WINDOW_NS {
                    win.pop_front();
                } else {
                    break;
                }
            }
            win.len()
        } else {
            0
        }
    }

    pub fn by_time_range(&self, start_ns: u64, end_ns: u64) -> Vec<&DecodedEvent> {
        self.buffer
            .iter()
            .filter(|e| e.header.timestamp_ns >= start_ns && e.header.timestamp_ns <= end_ns)
            .map(|e| e.as_ref())
            .collect()
    }

    /// 重启后续号：用取证链恢复出的链尾 seq 播种，避免同一日志文件内 seq
    /// 因进程重启而回退/重复（alert.event_ids 的定位依赖文件内唯一序号）
    pub fn set_seq(&mut self, seq: u64) {
        self.seq = seq;
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn len(&self) -> usize {
        self.buffer.len()
    }
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

fn cstr_to_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn exec_args_to_cmdline(args: &[u8; 512]) -> Option<String> {
    let mut mingling_duan = Vec::new();
    for duan in args.chunks(64).take(5) {
        let zi_fu = cstr_to_string(duan);
        if zi_fu.is_empty() {
            break;
        }
        mingling_duan.push(zi_fu);
    }
    if mingling_duan.is_empty() {
        None
    } else {
        Some(mingling_duan.join(" "))
    }
}

fn ip_to_string(addr: u32) -> String {
    let ip = u32::from_be(addr);
    format!(
        "{}.{}.{}.{}",
        (ip >> 24) & 0xFF,
        (ip >> 16) & 0xFF,
        (ip >> 8) & 0xFF,
        ip & 0xFF
    )
}

fn ipv6_to_string(addr: &[u8; 16]) -> String {
    let groups: Vec<u16> = (0..8)
        .map(|i| u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]))
        .collect();

    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut current_start = 0usize;
    let mut current_len = 0usize;

    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if current_len == 0 {
                current_start = i;
            }
            current_len += 1;
            if current_len > best_len {
                best_start = current_start;
                best_len = current_len;
            }
        } else {
            current_len = 0;
        }
    }

    if best_len >= 2 {
        let mut result = String::new();
        for g in groups.iter().take(best_start) {
            if !result.is_empty() {
                result.push(':');
            }
            result.push_str(&format!("{:x}", g));
        }
        result.push_str("::");
        for g in groups.iter().skip(best_start + best_len) {
            if !result.ends_with(':') {
                result.push(':');
            }
            result.push_str(&format!("{:x}", g));
        }
        if result == "::" {
            "::".to_string()
        } else {
            result
        }
    } else {
        groups
            .iter()
            .map(|g| format!("{:x}", g))
            .collect::<Vec<_>>()
            .join(":")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::IntoBytes;
    use ks_core::event::EventHeader;

    fn make_header(event_type: u32, pid: u32, timestamp_ns: u64) -> EventHeader {
        EventHeader {
            event_type,
            _pad1: 0,
            timestamp_ns,
            pid,
            tid: 0,
            uid: 0,
            ppid: 0,
            comm: [0; 16],
            syscall_nr: 0,
            _pad2: 0,
            retval: 0,
        }
    }

    fn encode_header(header: &EventHeader) -> Vec<u8> {
        header.as_bytes().to_vec()
    }

    #[test]
    fn test_aggregator_basic() {
        let mut agg = EventAggregator::new(100);
        let mut header = make_header(2, 1234, 1000);
        header.comm[..4].copy_from_slice(b"test");
        let event = agg.decode(&encode_header(&header)).unwrap();
        assert_eq!(event.comm, "test");
        assert_eq!(agg.seq(), 1);
    }

    #[test]
    fn test_aggregator_ring_buffer_eviction() {
        let mut agg = EventAggregator::new(3);
        for i in 0..5 {
            agg.decode(&encode_header(&make_header(2, i, i as u64 * 1000)))
                .unwrap();
        }
        assert_eq!(agg.len(), 3);
        let events: Vec<_> = agg.buffer().iter().map(|e| e.header.pid).collect();
        assert_eq!(events, vec![2, 3, 4]);
    }

    #[test]
    fn test_by_pid() {
        let mut agg = EventAggregator::new(100);
        for pid in [100, 200, 100, 300] {
            agg.decode(&encode_header(&make_header(2, pid, 0))).unwrap();
        }
        assert_eq!(agg.by_pid(100).len(), 2);
        assert_eq!(agg.by_pid(999).len(), 0);
    }

    #[test]
    fn test_recent_syscall_count_window() {
        let mut agg = EventAggregator::new(100);
        for t in [0u64, 10_000_000_000, 20_000_000_000, 30_000_000_000, 40_000_000_000] {
            agg.decode(&encode_header(&make_header(2, 100, t))).unwrap();
        }
        agg.decode(&encode_header(&make_header(2, 200, 5_000_000_000))).unwrap();

        assert_eq!(agg.recent_syscall_count(100, 40_000_000_000), 5);
        assert_eq!(agg.recent_syscall_count(200, 40_000_000_000), 1);
        assert_eq!(agg.recent_syscall_count(999, 40_000_000_000), 0);

        agg.decode(&encode_header(&make_header(2, 100, 80_000_000_000))).unwrap();
        assert_eq!(agg.recent_syscall_count(100, 80_000_000_000), 3);
    }


    #[test]
    fn test_by_time_range() {
        let mut agg = EventAggregator::new(100);
        for ts in [1000u64, 2000, 3000, 4000, 5000] {
            agg.decode(&encode_header(&make_header(2, 0, ts))).unwrap();
        }
        assert_eq!(agg.by_time_range(2000, 4000).len(), 3);
    }

    #[test]
    fn test_cstr_to_string() {
        assert_eq!(cstr_to_string(b"hello\0world"), "hello");
        assert_eq!(cstr_to_string(b"test"), "test");
    }

    #[test]
    fn test_ip_to_string() {
        assert_eq!(ip_to_string(0x0100007F), "127.0.0.1");
        assert_eq!(ip_to_string(0x0101A8C0), "192.168.1.1");
    }

    #[test]
    fn test_ipv6_to_string() {
        let mut addr = [0u8; 16];
        addr[15] = 1;
        assert_eq!(ipv6_to_string(&addr), "::1");
    }

    /// 构造 FileEvent 原始字节（8-31 新增的 rename/chmod 探针走同一 file_event 结构）
    fn encode_file_event(event_type: u32, pid: u32, ts: u64, filename: &str, bytes: u64) -> Vec<u8> {
        let mut fname = [0u8; 256];
        let b = filename.as_bytes();
        fname[..b.len().min(255)].copy_from_slice(&b[..b.len().min(255)]);
        let fe = ks_core::event::FileEvent {
            header: make_header(event_type, pid, ts),
            filename: fname,
            bytes,
            fd: -1,
            flags: 0,
        };
        fe.as_bytes().to_vec()
    }

    #[test]
    fn test_decode_file_rename_event() {
        let mut agg = EventAggregator::new(10);
        let data = encode_file_event(14, 4242, 7_000_000_000, "/etc/cron.d/backdoor", 0);
        let e = agg.decode(&data).unwrap();
        assert_eq!(e.header.event_type, 14);
        assert_eq!(e.filename.as_deref(), Some("/etc/cron.d/backdoor"));
        assert_eq!(e.file_bytes, None, "rename 事件 bytes=0 应解码为 None");
    }

    #[test]
    fn test_decode_file_chmod_event() {
        let mut agg = EventAggregator::new(10);
        let data = encode_file_event(15, 4243, 8_000_000_000, "/usr/bin/backdoor", 0);
        let e = agg.decode(&data).unwrap();
        assert_eq!(e.header.event_type, 15);
        assert_eq!(e.filename.as_deref(), Some("/usr/bin/backdoor"));
    }
}

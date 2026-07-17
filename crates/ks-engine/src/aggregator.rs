use anyhow::Result;
use ks_core::event::{af, EventHeader, RawEvent};
use log::debug;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// 事件聚合器 —— VecDeque 环形缓冲，O(1) 淘汰。
/// 解码时做数据长度校验，支持按 PID/时间范围查询。
pub struct EventAggregator {
    buffer: VecDeque<DecodedEvent>,
    max_buffer: usize,
    seq: u64,
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
    // E4.4 新增字段 (容器逃逸 / LKM 加载 / eBPF 篡改探针)
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
        }
    }

    /// 从 ring buffer 裸字节解码事件。
    /// RawEvent::from_bytes 内部已做两阶段长度校验。
    pub fn decode(&mut self, data: &[u8]) -> Result<DecodedEvent> {
        let raw = unsafe { RawEvent::from_bytes(data) }
            .ok_or_else(|| anyhow::anyhow!("事件数据不足: {} 字节", data.len()))?;

        let event_type = raw.event_type();
        let header = unsafe { raw.header };
        let comm = cstr_to_string(&header.comm);

        let decoded = match event_type {
            1 => {
                let exec = unsafe { &raw.exec };
                let fname = cstr_to_string(&exec.filename);
                let args = cstr_to_string(&exec.args);
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: if fname.is_empty() { None } else { Some(fname) },
                    args: if args.is_empty() { None } else { Some(args) },
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
                let file = unsafe { &raw.file };
                let fname = cstr_to_string(&file.filename);
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
                    file_bytes: if file.bytes > 0 {
                        Some(file.bytes)
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
                let net = unsafe { &raw.net };
                let (saddr, daddr) = if net.family == af::AF_INET6 {
                    (
                        Some(ipv6_to_string(&net.saddr6)),
                        Some(ipv6_to_string(&net.daddr6)),
                    )
                } else {
                    (Some(ip_to_string(net.saddr)), Some(ip_to_string(net.daddr)))
                };
                DecodedEvent {
                    seq: 0,
                    header,
                    comm,
                    filename: None,
                    args: None,
                    saddr,
                    daddr,
                    sport: Some(net.sport),
                    dport: Some(net.dport),
                    proto: Some(
                        if net.proto == 6 {
                            "TCP"
                        } else if net.proto == 17 {
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
                let sig = unsafe { &raw.signal };
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
                    target_pid: Some(sig.target_pid),
                    signal: Some(sig.signal),
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
            // E4.4.1: 容器逃逸事件 (kprobe/commit_creds)
            80 => {
                let ce = unsafe { &raw.container_escape };
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
                    source_ns_inum: Some(ce.source_ns_inum),
                    target_ns_inum: Some(ce.target_ns_inum),
                    cap_eff: Some(ce.cap_eff),
                    action: None,
                }
            }
            // E4.4.2: LKM 加载事件 (kprobe/do_init_module)
            81 => {
                let lkm = unsafe { &raw.lkm_load };
                let mname = cstr_to_string(&lkm.module_name);
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
            // E4.4.3: eBPF 篡改事件 (kprobe/security_bpf_prog_free)
            82 => {
                let et = unsafe { &raw.ebpf_tamper };
                let pname = cstr_to_string(&et.prog_name);
                let act = cstr_to_string(&et.action);
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

        if self.buffer.len() >= self.max_buffer {
            self.buffer.pop_front();
        }
        self.buffer.push_back(event.clone());

        debug!(
            "事件 #{}: type={} pid={} comm={}",
            self.seq, event_type, header.pid, event.comm
        );
        Ok(event)
    }

    pub fn buffer(&self) -> &VecDeque<DecodedEvent> {
        &self.buffer
    }

    pub fn by_pid(&self, pid: u32) -> Vec<&DecodedEvent> {
        self.buffer.iter().filter(|e| e.header.pid == pid).collect()
    }

    pub fn recent(&self, n: usize) -> Vec<&DecodedEvent> {
        let skip = if self.buffer.len() > n {
            self.buffer.len() - n
        } else {
            0
        };
        self.buffer.iter().skip(skip).collect()
    }

    pub fn by_time_range(&self, start_ns: u64, end_ns: u64) -> Vec<&DecodedEvent> {
        self.buffer
            .iter()
            .filter(|e| e.header.timestamp_ns >= start_ns && e.header.timestamp_ns <= end_ns)
            .collect()
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

/// C 字节数组 → Rust String（遇到 \0 截断）
fn cstr_to_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

fn ip_to_string(addr: u32) -> String {
    // 内核 sockaddr_in.sin_addr.s_addr 是 __be32 (网络字节序, big-endian)
    // Rust 在 x86 (小端) 上读出的 u32 字节序与原始内存一致 (即大端值在内存中为小端布局)
    // 用 from_be 转成本地字节序
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
        let size = core::mem::size_of::<EventHeader>();
        let mut data = vec![0u8; size];
        unsafe {
            core::ptr::write_unaligned(data.as_mut_ptr() as *mut EventHeader, *header);
        }
        data
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
        // 内核 sockaddr_in.s_addr 是 __be32，在内存中以小端存储
        // 0x7F000001 (127.0.0.1 big-endian) 在 x86 内存中为 01 00 00 7F，
        // Rust 读为 u32 值 0x0100007F
        assert_eq!(ip_to_string(0x0100007F), "127.0.0.1");
        assert_eq!(ip_to_string(0x0101A8C0), "192.168.1.1");
    }

    #[test]
    fn test_ipv6_to_string() {
        let mut addr = [0u8; 16];
        addr[15] = 1;
        assert_eq!(ipv6_to_string(&addr), "::1");
    }
}

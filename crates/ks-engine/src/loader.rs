//! eBPF 加载器 — 加载字节码、挂载 tracepoint/kprobe、管理探针生命周期。

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

pub struct EbpfLoader {
    probes: Vec<String>,
    #[cfg(target_os = "linux")]
    bpf: Option<aya::Bpf>,
}

impl EbpfLoader {
    pub fn new() -> Self {
        Self {
            probes: vec![
                "trace_sys_enter".into(), "trace_sys_exit".into(),
                "trace_sched_exec".into(), "trace_sched_exit".into(),
            ],
            #[cfg(target_os = "linux")]
            bpf: None,
        }
    }

    /// 加载 eBPF、挂载探针。
    pub async fn start_all(&mut self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            let obj = include_bytes!(concat!(env!("OUT_DIR"), "/syscall_probe.bpf.o"));
            let mut bpf = aya::Bpf::load(obj)?;

            macro_rules! attach_tp {
                ($name:expr, $cat:expr, $evt:expr) => {
                    let prog: &mut aya::programs::TracePoint =
                        bpf.program_mut($name)
                            .ok_or_else(|| anyhow::anyhow!("程序 '{}' 未找到", $name))?
                            .try_into()?;
                    prog.load()?;
                    prog.attach($cat, $evt)?;
                };
            }
            attach_tp!("trace_sys_enter", "raw_syscalls", "sys_enter");
            attach_tp!("trace_sys_exit", "raw_syscalls", "sys_exit");
            attach_tp!("trace_sched_exec", "sched", "sched_process_exec");
            attach_tp!("trace_sched_exit", "sched", "sched_process_exit");

            self.bpf = Some(bpf);
            log::info!("eBPF 探针加载成功: {} 个已挂载", self.probes.len());
        }

        Ok(())
    }

    pub fn loaded_probes(&self) -> &[String] {
        &self.probes
    }

    /// 从 ring buffer 读取一条事件（非阻塞）。
    /// 每次调用临时创建 RingBuf，读一条，释放。
    #[cfg(target_os = "linux")]
    pub fn try_next_event(&mut self) -> Option<Vec<u8>> {
        let bpf = self.bpf.as_mut()?;
        let map = bpf.map_mut("events")?;
        let mut ring_buf = aya::maps::RingBuf::try_from(map).ok()?;
        let item = ring_buf.next()?;
        Some(item.to_vec())
    }

    pub async fn stop_all(&mut self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.bpf.take();
            log::info!("eBPF 探针已卸载");
        }
        Ok(())
    }

    /// 返回 BPF map 读取器（平台无关，Linux 上跳过真实读取）
    pub fn map_reader(&self) -> &dyn BpfMapReader {
        &MockBpfMapReader
    }
}

// ─── 测试 ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mock_reader() {
        let _loader = EbpfLoader::new();
    }
}
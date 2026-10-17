use ks_core::event::DecodedEvent;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub pid: u32,
    pub ppid: u32,
    pub comm: String,
    pub exe_path: String,
    pub create_time_ns: u64,
    pub exit_time_ns: u64,
    pub flags: ProcessFlags,
    pub risk_score: u32,
    // VecDeque 使到达上限后的淘汰为 O(1)（旧 Vec::remove(0) 每次整体搬移，且在每事件热路径上）
    pub events: VecDeque<DecodedEvent>,
    pub children: Vec<u32>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessFlags {
    pub is_root: bool,
    pub is_container: bool,
    pub is_orphan: bool,
    pub is_anomalous: bool,
}

#[derive(Debug, Clone)]
pub struct ProcessFamily {
    pub root_pid: u32,
    pub member_pids: HashSet<u32>,
    pub all_events: Vec<DecodedEvent>,
    pub max_risk_score: u32,
    pub has_root_process: bool,
    pub has_anomalous_process: bool,
    pub anomaly_relations: Vec<AnomalyRelation>,
}

#[derive(Debug, Clone)]
pub struct AnomalyRelation {
    pub parent_comm: String,
    pub child_comm: String,
    pub parent_pid: u32,
    pub child_pid: u32,
    pub anomaly_type: String,
}

pub struct ProcessTreeManager {
    nodes: HashMap<u32, ProcessNode>,
    anomaly_patterns: Vec<AnomalyPattern>,
    max_nodes: usize,
    max_events_per_node: usize,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct AnomalyPattern {
    parent_comm: String,
    child_comm: String,
    description: String,
    mitre_tactic: String,
    mitre_technique: String,
}

impl Default for ProcessTreeManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTreeManager {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            anomaly_patterns: Self::default_anomaly_patterns(),
            max_nodes: 10000,
            // 旧值 100：最坏 10000 节点 × 100 条完整事件（每条 6+ String）≈ 数百 MB，
            // 远超 memory_limit_mb=128。降到 16：单节点最近 16 条足够链还原使用
            max_events_per_node: 16,
        }
    }

    fn default_anomaly_patterns() -> Vec<AnomalyPattern> {
        vec![
            AnomalyPattern {
                parent_comm: "systemd".into(),
                child_comm: "nc".into(),
                description: "系统服务执行网络工具，疑似反弹Shell".into(),
                mitre_tactic: "TA0001".into(),
                mitre_technique: "T1059.004".into(),
            },
            AnomalyPattern {
                parent_comm: "cron".into(),
                child_comm: "nc".into(),
                description: "定时任务执行nc，疑似C2".into(),
                mitre_tactic: "TA0003".into(),
                mitre_technique: "T1053.003".into(),
            },
            AnomalyPattern {
                parent_comm: "bash".into(),
                child_comm: "wget".into(),
                description: "Shell下载文件，可能是payload".into(),
                mitre_tactic: "TA0002".into(),
                mitre_technique: "T1105".into(),
            },
            AnomalyPattern {
                parent_comm: "sshd".into(),
                child_comm: "bash".into(),
                description: "SSH会话启动Shell".into(),
                mitre_tactic: "TA0001".into(),
                mitre_technique: "T1021.004".into(),
            },
            AnomalyPattern {
                parent_comm: "bash".into(),
                child_comm: "sudo".into(),
                description: "Shell调sudo提权".into(),
                mitre_tactic: "TA0004".into(),
                mitre_technique: "T1548.003".into(),
            },
            AnomalyPattern {
                parent_comm: "bash".into(),
                child_comm: "insmod".into(),
                description: "Shell加载内核模块，疑似Rootkit".into(),
                mitre_tactic: "TA0005".into(),
                mitre_technique: "T1547.006".into(),
            },
        ]
    }

    pub fn update_from_event(&mut self, event: &DecodedEvent) {
        let pid = event.header.pid;
        let ppid = event.header.ppid;
        let uid = event.header.uid;
        let event_type = event.header.event_type;
        let comm = event.comm.clone();
        let filename = event.filename.clone();
        let timestamp_ns = event.header.timestamp_ns;

        let is_anomalous_child = if ppid > 0 {
            let parent_comm = self
                .nodes
                .get(&ppid)
                .map(|n| n.comm.clone())
                .unwrap_or_default();
            self.anomaly_patterns
                .iter()
                .any(|p| parent_comm.contains(&p.parent_comm) && comm.contains(&p.child_comm))
        } else {
            false
        };

        if let Some(node) = self.nodes.get_mut(&pid) {
            if event_type == 1 {
                node.comm = comm.clone();
                if let Some(f) = &filename {
                    node.exe_path = f.clone();
                }
            } else if event_type == 2 {
                node.exit_time_ns = timestamp_ns;
            }
            node.events.push_back(event.clone());
            while node.events.len() > self.max_events_per_node {
                node.events.pop_front();
            }
            if uid == 0 {
                node.flags.is_root = true;
            }
            if is_anomalous_child {
                node.flags.is_anomalous = true;
            }
        } else {
            self.nodes.insert(
                pid,
                ProcessNode {
                    pid,
                    ppid,
                    comm: comm.clone(),
                    exe_path: filename.unwrap_or_default(),
                    create_time_ns: timestamp_ns,
                    exit_time_ns: 0,
                    flags: ProcessFlags {
                        is_root: uid == 0,
                        is_container: false,
                        is_orphan: false,
                        is_anomalous: is_anomalous_child,
                    },
                    risk_score: 0,
                    events: VecDeque::from(vec![event.clone()]),
                    children: Vec::new(),
                },
            );
        }

        if ppid > 0 && self.nodes.contains_key(&ppid) {
            let parent = self.nodes.get_mut(&ppid).unwrap();
            if !parent.children.contains(&pid) {
                parent.children.push(pid);
            }
        }

        if self.nodes.len() > self.max_nodes {
            // 单次收集+排序按创建时间批量淘汰最旧一批，替代逐个 min_by_key 全表扫描
            let target = self.max_nodes.saturating_sub(self.max_nodes / 10);
            if self.nodes.len() > target {
                let mut by_created: Vec<(u32, u64)> = self
                    .nodes
                    .iter()
                    .map(|(p, n)| (*p, n.create_time_ns))
                    .collect();
                by_created.sort_unstable_by_key(|(_, ts)| *ts);
                let excess = self.nodes.len() - target;
                for (pid, _) in by_created.into_iter().take(excess) {
                    self.nodes.remove(&pid);
                }
            }
        }
    }

    pub fn get_node(&self, pid: u32) -> Option<&ProcessNode> {
        self.nodes.get(&pid)
    }

    pub fn get_family(&self, root_pid: u32) -> Option<ProcessFamily> {
        let root = self.nodes.get(&root_pid)?;
        if root.events.is_empty() && root.children.is_empty() {
            return None;
        }

        let mut member_pids = HashSet::new();
        let mut all_events = Vec::new();
        let mut max_risk_score = 0;
        let mut has_root_process = false;
        let mut has_anomalous_process = false;
        let mut anomaly_relations = Vec::new();
        let mut queue = vec![root_pid];

        while let Some(pid) = queue.pop() {
            if member_pids.contains(&pid) {
                continue;
            }
            member_pids.insert(pid);
            let node = match self.nodes.get(&pid) {
                Some(n) => n,
                None => continue,
            };
            all_events.extend(node.events.iter().cloned());
            max_risk_score = max_risk_score.max(node.risk_score);
            if node.flags.is_root {
                has_root_process = true;
            }
            if node.flags.is_anomalous {
                has_anomalous_process = true;
            }

            if node.ppid > 0 {
                let pc = self
                    .nodes
                    .get(&node.ppid)
                    .map(|p| p.comm.clone())
                    .unwrap_or_default();
                for pattern in &self.anomaly_patterns {
                    if pc.contains(&pattern.parent_comm) && node.comm.contains(&pattern.child_comm)
                    {
                        anomaly_relations.push(AnomalyRelation {
                            parent_comm: pc.clone(),
                            child_comm: node.comm.clone(),
                            parent_pid: node.ppid,
                            child_pid: node.pid,
                            anomaly_type: pattern.description.clone(),
                        });
                    }
                }
            }
            for child in &node.children {
                queue.push(*child);
            }
        }

        all_events.sort_by_key(|e| e.header.timestamp_ns);
        Some(ProcessFamily {
            root_pid,
            member_pids,
            all_events,
            max_risk_score,
            has_root_process,
            has_anomalous_process,
            anomaly_relations,
        })
    }

    pub fn all_families(&self) -> Vec<ProcessFamily> {
        let roots: Vec<u32> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.ppid == 0 || !self.nodes.contains_key(&n.ppid))
            .map(|(pid, _)| *pid)
            .collect();
        roots
            .iter()
            .filter_map(|pid| self.get_family(*pid))
            .collect()
    }

    pub fn anomalous_families(&self) -> Vec<ProcessFamily> {
        self.all_families()
            .into_iter()
            .filter(|f| f.has_anomalous_process || !f.anomaly_relations.is_empty())
            .collect()
    }

    pub fn reconstruct_tree_attack_chain(&self, family: &ProcessFamily) -> Option<TreeAttackChain> {
        if family.all_events.is_empty() {
            return None;
        }
        let reconstructor = crate::chain::ChainReconstructor::new();
        // family.all_events 是本调用临时聚合的 owned 数据，包装成 Arc 适配
        // reconstruct 的 Arc 切片签名（离线路径，非热路径）
        let arcs: Vec<std::sync::Arc<DecodedEvent>> =
            family.all_events.iter().map(|e| std::sync::Arc::new(e.clone())).collect();
        let chain = reconstructor.reconstruct(&arcs)?;
        Some(TreeAttackChain {
            root_pid: family.root_pid,
            member_pids: family.member_pids.clone(),
            steps: chain.steps,
            confidence: chain.confidence,
            has_root_process: family.has_root_process,
            has_anomalous_process: family.has_anomalous_process,
            anomaly_relations: family.anomaly_relations.clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct TreeAttackChain {
    pub root_pid: u32,
    pub member_pids: HashSet<u32>,
    pub steps: Vec<crate::chain::AttackStep>,
    pub confidence: f64,
    pub has_root_process: bool,
    pub has_anomalous_process: bool,
    pub anomaly_relations: Vec<AnomalyRelation>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ks_core::event::EventHeader;

    fn make_event(
        seq: u64,
        pid: u32,
        ppid: u32,
        et: u32,
        comm: &str,
        uid: u32,
        filename: Option<&str>,
    ) -> DecodedEvent {
        let mut cb = [0u8; 16];
        let len = comm.len().min(16);
        cb[..len].copy_from_slice(&comm.as_bytes()[..len]);
        DecodedEvent {
            seq,
            comm: comm.to_string(),
            header: EventHeader {
                event_type: et,
                _pad1: 0,
                timestamp_ns: seq * 1_000_000_000,
                pid,
                tid: 0,
                uid,
                ppid,
                comm: cb,
                syscall_nr: 0,
                _pad2: 0,
                retval: 0,
            },
            filename: filename.map(|s| s.to_string()),
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

    #[test]
    fn test_process_tree_basic() {
        let mut tree = ProcessTreeManager::new();
        tree.update_from_event(&make_event(1, 100, 1, 1, "bash", 0, Some("/bin/bash")));
        tree.update_from_event(&make_event(
            2,
            101,
            100,
            1,
            "wget",
            1000,
            Some("/usr/bin/wget"),
        ));
        let parent = tree.get_node(100).unwrap();
        assert!(parent.children.contains(&101));
        assert_eq!(tree.get_node(101).unwrap().ppid, 100);
    }

    #[test]
    fn test_anomaly_relation_detection() {
        let mut tree = ProcessTreeManager::new();
        tree.update_from_event(&make_event(1, 100, 1, 1, "bash", 0, None));
        tree.update_from_event(&make_event(2, 101, 100, 1, "wget", 1000, None));
        let anomalous = tree.anomalous_families();
        assert!(!anomalous.is_empty());
        assert!(!anomalous[0].anomaly_relations.is_empty());
    }

    #[test]
    fn test_process_family() {
        let mut tree = ProcessTreeManager::new();
        tree.update_from_event(&make_event(1, 100, 1, 1, "bash", 0, None));
        tree.update_from_event(&make_event(2, 101, 100, 1, "wget", 0, None));
        tree.update_from_event(&make_event(3, 102, 101, 1, "encryptor", 0, None));
        let family = tree.get_family(100).unwrap();
        assert!(family.member_pids.contains(&102));
        assert_eq!(family.all_events.len(), 3);
    }
}

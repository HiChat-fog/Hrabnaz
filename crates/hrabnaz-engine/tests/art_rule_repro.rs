//! ART 检出率校准（H-4 / I-2）的规则层复现：把 Atomic Red Team 对应技术的
//! 关键行为直接喂给引擎（真实规则集），断言规则层可达性。
//!
//! 这层只回答"事件到达用户态后规则是否能命中"；内核层可达性（探针捕获 +
//! 智能过滤放行）由真机 ART 矩阵回答，两层结论合起来才是完整检出率。
//! 已知的内核层缺口（见 ks-test-evidence 的 ART 报告）：
//!   - FILE_OPEN/FILE_READ 对低风险进程默认丢弃，只有 /etc/shadow、
//!     /etc/gshadow、/etc/sudoers、/root/.ssh 前缀会经 infer_sensitive_file
//!     放行——cron.d、非 root 的 authorized_keys、id_rsa 等路径的事件
//!     到不了这里；
//!   - FILE_WRITE 有 ≥1024B 门槛。

use hrabnaz_core::event::{EbpfTamperEvent, EventHeader, ExecEvent, FileEvent, NetEvent};
use hrabnaz_engine::config::Config;
use hrabnaz_engine::engine::{Engine, EngineEffect, EngineOptions, EventSourceSpec};
use hrabnaz_engine::event_source::{MockEventSource, MockScenario};
use zerocopy::IntoBytes as _;

fn header(event_type: u32, pid: u32, comm: &str) -> EventHeader {
    let mut b = [0u8; 16];
    b[..comm.len().min(16)].copy_from_slice(&comm.as_bytes()[..comm.len().min(16)]);
    EventHeader {
        event_type,
        _pad1: 0,
        timestamp_ns: 1,
        pid,
        tid: pid,
        uid: 0,
        ppid: 1,
        comm: b,
        syscall_nr: 0,
        _pad2: 0,
        retval: 0,
    }
}

fn file_event(event_type: u32, pid: u32, comm: &str, path: &str) -> Vec<u8> {
    let mut f = [0u8; 256];
    f[..path.len()].copy_from_slice(path.as_bytes());
    FileEvent {
        header: header(event_type, pid, comm),
        filename: f,
        bytes: 0,
        fd: 3,
        flags: 0,
    }
    .as_bytes()
    .to_vec()
}

fn file_open(pid: u32, comm: &str, path: &str) -> Vec<u8> {
    file_event(10, pid, comm, path)
}

fn tamper_event(pid: u32, comm: &str) -> Vec<u8> {
    let mut c = [0u8; 16];
    c[..comm.len().min(16)].copy_from_slice(&comm.as_bytes()[..comm.len().min(16)]);
    EbpfTamperEvent {
        header: header(82, pid, comm),
        pid,
        uid: 0,
        _pad_self1: 0,
        prog_name: [0u8; 64],
        comm: c,
        action: [0u8; 16],
        _pad_self2: [0u8; 4],
    }
    .as_bytes()
    .to_vec()
}

fn net_dns(pid: u32, comm: &str, daddr: &str) -> Vec<u8> {
    let p: Vec<u8> = daddr.split('.').filter_map(|x| x.parse().ok()).collect();
    NetEvent {
        header: header(24, pid, comm),
        saddr: u32::from_ne_bytes([192, 168, 1, 50]),
        daddr: u32::from_ne_bytes([p[0], p[1], p[2], p[3]]),
        sport: 53000,
        dport: 53,
        proto: 17,
        family: 2,
        saddr6: [0u8; 16],
        daddr6: [0u8; 16],
        _pad3: [0u8; 2],
    }
    .as_bytes()
    .to_vec()
}

fn exec(pid: u32, comm: &str, args: &str) -> Vec<u8> {
    let mut a = [0u8; 512];
    a[..args.len()].copy_from_slice(args.as_bytes());
    ExecEvent {
        header: header(1, pid, comm),
        filename: [0u8; 256],
        args: a,
    }
    .as_bytes()
    .to_vec()
}

/// 每条用例独立 pid 规避 60s 告警去重窗口
#[tokio::test(flavor = "current_thread")]
async fn art_rule_layer_repro() {
    let dir = tempfile::TempDir::new().unwrap();
    let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let mut engine = Engine::start(EngineOptions {
        config: Config::default(),
        rules_dir: rules.to_string_lossy().to_string(),
        log_dir: dir.path().to_string_lossy().to_string(),
        source: EventSourceSpec::Provided(
            Box::new(MockEventSource::new_with_scenario(MockScenario::All)),
            None,
        ),
        heartbeat_path: None,
        ml_observe_sec: None,
    })
    .await
    .unwrap();

    let cases: Vec<(&str, Vec<u8>, &[&str])> = vec![
        // (ART 技术, 事件, 期望命中的规则名)
        (
            "T1003.008 cat /etc/shadow",
            file_open(9101, "cat", "/etc/shadow"),
            &["敏感文件访问"],
        ),
        (
            "T1098.004 authorized_keys 注入",
            file_open(9102, "bash", "/root/.ssh/authorized_keys"),
            &["SSH后门公钥注入"],
        ),
        (
            "T1548.003 sudoers 访问",
            file_open(9103, "cat", "/etc/sudoers"),
            &["sudo 配置篡改检测"],
        ),
        (
            "T1053.003 cron.d 写入(规则层可达,内核层被丢)",
            file_open(9104, "bash", "/etc/cron.d/art-cron"),
            &["Cron 定时任务持久化"],
        ),
        (
            "T1053.003 cron.daily 打开(FPR 回归: 脚本目录已移出规则面, run-parts 例行打开不告警)",
            file_open(9114, "bash", "/etc/cron.daily/art-cron"),
            &[],
        ),
        (
            "T1486 .enc 加密后缀",
            file_open(9115, "openssl", "/tmp/art-secret.enc"),
            &["勒索软件加密行为"],
        ),
        (
            "T1562 bpftool 释放程序",
            tamper_event(9116, "bpftool"),
            &["eBPF 程序篡改检测"],
        ),
        (
            "T1136.001 useradd",
            exec(
                9105,
                "useradd",
                "-M -N -r -s /bin/bash -c evil_account art-evil",
            ),
            &["新增系统用户"],
        ),
        (
            "T1548.001 chmod u+xs",
            exec(9106, "chmod", "u+xs /tmp/art-suid"),
            &["SUID 提权检测"],
        ),
        (
            "T1574.006 LD_PRELOAD",
            exec(9107, "bash", "LD_PRELOAD=/tmp/art-preload.so ls"),
            &["LD_PRELOAD 劫持检测"],
        ),
        (
            "T1140 base64 -d",
            exec(9108, "bash", "echo aGF4 | base64 -d"),
            &["base64解码执行"],
        ),
        (
            "T1053.003 crontab 替换 (Debian 相对路径)",
            file_event(14, 9109, "crontab", "crontabs/root"),
            &["用户定时任务表修改"],
        ),
        (
            "T1053.003 mv 替换 (CentOS 绝对路径)",
            file_event(14, 9110, "mv", "/var/spool/cron/root"),
            &["定时任务表替换"],
        ),
        (
            "T1053.003 mv 替换 (Debian 绝对路径)",
            file_event(14, 9111, "mv", "/var/spool/cron/crontabs/www-data"),
            &["定时任务表替换"],
        ),
        (
            "T1071.004 公网 DNS 查询",
            net_dns(9113, "bash", "8.8.8.8"),
            &["dns_tunnel_suspicious_domain"],
        ),
        (
            "T1105 第 6 参数落地 /tmp",
            exec(
                9117,
                "curl",
                "-s -m 2 -o /tmp/art_payload http://127.0.0.1:8000/",
            ),
            &["载荷下载落地tmp"],
        ),
        (
            "T1552.004 ssh id_rsa",
            file_open(9118, "cat", "/root/.ssh/id_rsa"),
            &["SSH私钥文件访问"],
        ),
        (
            "T1552.004 ssh .pem 私钥",
            file_open(9119, "cat", "/root/.ssh/aws.pem"),
            &["SSH私钥文件访问"],
        ),
        (
            "T1552.004 ssh host key",
            file_open(9120, "cat", "/etc/ssh/ssh_host_rsa_key"),
            &["SSH私钥文件访问"],
        ),
    ];

    for (name, bytes, expected) in cases {
        let out = engine.process_event(&bytes).await.unwrap();
        let fired: Vec<String> = out
            .effects
            .iter()
            .filter_map(|e| match e {
                EngineEffect::Alert(raised) => Some(raised.alert.rule_name.clone()),
                _ => None,
            })
            .collect();
        let ok = expected.iter().all(|r| fired.iter().any(|f| f.contains(r)));
        assert!(
            ok,
            "{name}: 期望命中 {expected:?}, 实际 {fired:?} — 规则层不可达需修正规则或字段提取"
        );
        println!("[HIT] {name} → {fired:?}");
    }
    // FPR 回归：sshd 认证读 authorized_keys、cron 合法读 shadow 不得告警
    for (name, bytes) in [
        (
            "FPR sshd 读 authorized_keys",
            file_open(9201, "sshd", "/root/.ssh/authorized_keys"),
        ),
        ("FPR cron 读 shadow", file_open(9202, "cron", "/etc/shadow")),
        (
            "FPR crond 读 shadow",
            file_open(9203, "crond", "/etc/shadow"),
        ),
        ("FPR sshd 读 shadow", file_open(9204, "sshd", "/etc/shadow")),
        (
            "FPR (systemd) 读 shadow",
            file_open(9205, "(systemd)", "/etc/shadow"),
        ),
        ("FPR crontab -l", exec(9206, "crontab", "-l")),
        (
            "FPR rename 非任务表",
            file_event(14, 9207, "mv", "/tmp/not-cron"),
        ),
        (
            "FPR cron 重读 /etc/crontab",
            file_open(9208, "cron", "/etc/crontab"),
        ),
        (
            "FPR crond 重读 /etc/cron.d",
            file_open(9209, "crond", "/etc/cron.d/0hourly"),
        ),
        (
            "FPR crontab 读 shadow",
            file_open(9210, "crontab", "/etc/shadow"),
        ),
        (
            "FPR dig 线程查询公网 DNS",
            net_dns(9211, "isc-net-0000", "8.8.8.8"),
        ),
        ("FPR 共享地址段 DNS", net_dns(9212, "bash", "100.100.2.136")),
        ("FPR systemd 释放 BPF 程序", tamper_event(9213, "systemd")),
        (
            "FPR CA bundle cert.pem",
            file_open(9214, "cat", "/etc/pki/tls/cert.pem"),
        ),
        (
            "FPR Debian 证书目录",
            file_open(9215, "cat", "/etc/ssl/certs/server.pem"),
        ),
        (
            "FPR SSH 公钥 .pub",
            file_open(9216, "cat", "/root/.ssh/id_rsa.pub"),
        ),
        (
            "FPR sshd 读主机私钥",
            file_open(9217, "sshd", "/etc/ssh/ssh_host_rsa_key"),
        ),
    ] {
        let out = engine.process_event(&bytes).await.unwrap();
        let fired: Vec<String> = out
            .effects
            .iter()
            .filter_map(|e| match e {
                EngineEffect::Alert(raised) => Some(raised.alert.rule_name.clone()),
                _ => None,
            })
            .collect();
        assert!(fired.is_empty(), "{name}: 不应告警, 实际 {fired:?}");
        println!("[NEG] {name} → 干净");
    }

    // CentOS 上 crontab 的 rename 同时满足进程名与绝对路径，只应出一条
    let out = engine
        .process_event(&file_event(14, 9112, "crontab", "/var/spool/cron/root"))
        .await
        .unwrap();
    let fired: Vec<String> = out
        .effects
        .iter()
        .filter_map(|e| match e {
            EngineEffect::Alert(raised) => Some(raised.alert.rule_name.clone()),
            _ => None,
        })
        .collect();
    assert!(
        fired.iter().any(|f| f.contains("用户定时任务表修改")),
        "crontab rename 未命中: {fired:?}"
    );
    assert!(
        !fired.iter().any(|f| f.contains("定时任务表替换")),
        "同一动作重复告警: {fired:?}"
    );
    println!("[NEG] crontab 绝对路径 rename 不重复告警 → {fired:?}");

    engine.shutdown().await.unwrap();
}

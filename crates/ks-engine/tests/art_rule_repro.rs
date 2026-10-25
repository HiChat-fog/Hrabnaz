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

use ks_core::event::{EventHeader, ExecEvent, FileEvent};
use ks_engine::config::Config;
use ks_engine::engine::{Engine, EngineEffect, EngineOptions, EventSourceSpec};
use ks_engine::event_source::{MockEventSource, MockScenario};
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

fn file_open(pid: u32, comm: &str, path: &str) -> Vec<u8> {
    let mut f = [0u8; 256];
    f[..path.len()].copy_from_slice(path.as_bytes());
    FileEvent {
        header: header(10, pid, comm),
        filename: f,
        bytes: 0,
        fd: 3,
        flags: 0,
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
    engine.shutdown().await.unwrap();
}

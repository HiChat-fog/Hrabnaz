use std::io::{BufRead, BufReader};
use std::process::{Command, Output, Stdio};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kernelsentinel"))
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .expect("spawn kernelsentinel")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn help_is_self_describing() {
    let out = run(&["--help"]);
    assert!(out.status.success());
    let text = stdout(&out);
    for needle in [
        "内核哨兵",
        "start",
        "watch",
        "status",
        "completion",
        "常用示例",
    ] {
        assert!(text.contains(needle), "--help 缺少 {needle}:\n{text}");
    }

    let out = run(&["watch", "--help"]);
    assert!(out.status.success());
    let text = stdout(&out);
    for needle in [
        "--rule",
        "--comm",
        "--severity",
        "--pid",
        "--file",
        "同一 flag 多次为 OR",
    ] {
        assert!(text.contains(needle), "watch --help 缺少 {needle}:\n{text}");
    }
}

#[test]
fn completion_scripts_cover_all_supported_shells() {
    for (shell, needle) in [
        ("bash", "complete -F _kernelsentinel kernelsentinel"),
        ("zsh", "#compdef kernelsentinel"),
        ("fish", "complete -c kernelsentinel"),
        ("powershell", "Register-ArgumentCompleter"),
        ("elvish", "arg-completer"),
    ] {
        let out = run(&["completion", shell]);
        assert!(
            out.status.success(),
            "completion {shell} failed: {}",
            stderr(&out)
        );
        assert!(
            stdout(&out).contains(needle),
            "completion {shell} 缺少 {needle}"
        );
    }

    let out = run(&["completion", "tcsh"]);
    assert_eq!(
        out.status.code(),
        Some(2),
        "未知 shell 必须是 clap 用法错误"
    );
}

#[test]
fn invalid_log_level_is_a_usage_error() {
    let out = run(&["--log-level", "verbose", "status"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("verbose"));
}

#[test]
fn status_json_is_one_stable_snapshot() {
    let out = run(&["status", "--json"]);
    assert!(
        out.status.success(),
        "status --json failed: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "status --json 必须只输出一行快照:\n{text}");

    let v: serde_json::Value =
        serde_json::from_str(lines[0]).expect("status --json 输出必须是 JSON");
    assert_eq!(v["schema_version"], 1);
    assert!(v["generated_at"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(v["heartbeat"]["path"].is_string());
    assert!(v["status_file"].is_object() || v["status_file"].is_null());

    let probes = &v["probes"];
    let total = probes["total"].as_u64().unwrap();
    assert!(total > 0, "探针注册表不应为空");
    assert_eq!(
        total,
        probes["tracepoint"].as_u64().unwrap()
            + probes["kprobe"].as_u64().unwrap()
            + probes["kretprobe"].as_u64().unwrap(),
        "探针分类之和必须等于 total"
    );
    assert!(v["rules"]["files"].is_array());
    assert!(v["config_defaults"]["forensic"]["log_dir"].is_string());
    assert!(v["config_defaults"]["performance"]["max_cpu_percent"].is_number());
}

#[test]
fn watch_no_follow_on_empty_dir_exits_without_waiting() {
    let dir = tempfile::tempdir().unwrap();
    let dir_s = dir.path().to_str().unwrap();

    let out = run(&["watch", "--no-follow", "--json", "--log-dir", dir_s]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(
        stdout(&out).trim().is_empty(),
        "--json 模式不应有非 JSON 噪声"
    );

    let out = run(&["watch", "--no-follow", "--log-dir", dir_s]);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("暂无"), "{}", stdout(&out));
}

#[test]
fn runtime_error_uses_exit_one_and_error_prefix() {
    let out = run(&["replay", "--file", "/nonexistent/events.jsonl"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).lines().any(|l| l.starts_with("error:")),
        "{}",
        stderr(&out)
    );
    assert!(stderr(&out).contains("文件不存在"), "{}", stderr(&out));
}

fn alert_line(
    id: &str,
    rule: &str,
    comm: &str,
    severity: &str,
    pid: u32,
    file: Option<&str>,
) -> String {
    serde_json::json!({
        "id": id,
        "timestamp_ns": 0,
        "severity": severity,
        "title": rule,
        "description": "",
        "rule_name": rule,
        "process": {
            "pid": pid,
            "ppid": 1,
            "comm": comm,
            "uid": 0,
            "exe_path": null,
            "cmdline": null,
        },
        "network": null,
        "file": file.map(|path| serde_json::json!({
            "path": path,
            "operation": "write",
            "bytes": null,
        })),
        "event_ids": [],
        "mitre": null,
        "status": "new",
        "type": "alert",
        "prev_hash": "prev",
        "hash": "hash",
    })
    .to_string()
}

#[test]
fn watch_filters_are_applied_to_real_log_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events_20261023.jsonl");
    let lines = [
        alert_line(
            "00000000-0000-0000-0000-000000000001",
            "SSH Brute Force",
            "sshd",
            "high",
            100,
            Some("/etc/shadow"),
        ),
        alert_line(
            "00000000-0000-0000-0000-000000000002",
            "SSH Brute Force",
            "sshd",
            "medium",
            100,
            None,
        ),
        alert_line(
            "00000000-0000-0000-0000-000000000003",
            "PHP Webshell",
            "nginx",
            "critical",
            200,
            Some("/var/www/x.php"),
        ),
        alert_line(
            "00000000-0000-0000-0000-000000000004",
            "SSH Brute Force",
            "curl",
            "high",
            300,
            Some("/etc/shadow"),
        ),
    ];
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    let dir_s = dir.path().to_str().unwrap();

    let out = run(&[
        "watch",
        "--no-follow",
        "--json",
        "--log-dir",
        dir_s,
        "--severity",
        "high",
        "--comm",
        "sshd",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let records: Vec<serde_json::Value> = stdout(&out)
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is JSON"))
        .collect();
    assert_eq!(records.len(), 1, "severity floor 与 comm 必须同时生效");
    assert_eq!(records[0]["rule_name"], "SSH Brute Force");

    let out = run(&[
        "watch",
        "--no-follow",
        "--json",
        "--log-dir",
        dir_s,
        "--rule",
        "SSH*",
        "--pid",
        "100",
        "--file",
        "/etc/shadow",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let records: Vec<serde_json::Value> = stdout(&out)
        .lines()
        .map(|l| serde_json::from_str(l).expect("each line is JSON"))
        .collect();
    assert_eq!(records.len(), 1, "rule/pid/file 必须同时生效");
    assert_eq!(records[0]["id"], "00000000-0000-0000-0000-000000000001");

    let out = run(&[
        "watch",
        "--no-follow",
        "--json",
        "--log-dir",
        dir_s,
        "--max",
        "1",
    ]);
    assert!(out.status.success(), "{}", stderr(&out));
    let text = stdout(&out);
    assert_eq!(text.lines().count(), 1, "--max 必须截断输出:\n{text}");
}

#[test]
fn broken_pipe_is_a_quiet_exit_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events_20261023.jsonl");
    let line = alert_line(
        "00000000-0000-0000-0000-000000000001",
        "r",
        "c",
        "high",
        1,
        None,
    );
    let mut body = String::with_capacity(line.len() * 20_000 + 1);
    for _ in 0..20_000 {
        body.push_str(&line);
        body.push('\n');
    }
    std::fs::write(&path, body).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_kernelsentinel"))
        .args([
            "watch",
            "--no-follow",
            "--json",
            "--log-dir",
            dir.path().to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn kernelsentinel");
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    assert!(
        first.contains("\"type\"") || first.contains("\"id\""),
        "{first}"
    );
    drop(reader);
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0), "关闭管道后应安静退出，而不是 panic");
}

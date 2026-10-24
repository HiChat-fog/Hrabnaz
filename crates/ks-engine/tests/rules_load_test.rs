//! 规则文件加载回归测试：rules/ 下所有 YAML 必须能被规则引擎加载，
//! 字段名/操作符合法（反序列化失败即失败）、规则名全局唯一。
//!
//! 写新规则前必须先确认传感器面（见 ks_probes_smart_filter.h 的 should_send_event）：
//! - exec(1)/write(12)/delete(13)/connect(20)/ptrace/signal/lkm/容器事件全量放行
//! - open/read(10/11) 仅 /etc/shadow、/etc/gshadow、/etc/sudoers、/root/.ssh 前缀
//!   或风险分>=40 的进程放行
//! - vfs_write 只上报 >=1024 字节的写入，小文件编辑走 exec args 检测
//! - 禁止添加建立在不可能到达规则引擎的事件上的"装饰规则"

use ks_core::rule::DetectionRule;

fn rules_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules")
}

/// 构造一个最小 DecodedEvent（只填规则会用到的字段）
fn make_event(
    event_type: u32,
    comm: &str,
    filename: Option<&str>,
    args: Option<&str>,
    daddr: Option<&str>,
    dport: Option<u16>,
) -> ks_core::event::DecodedEvent {
    use ks_core::event::EventHeader;
    let mut cb = [0u8; 16];
    let len = comm.len().min(16);
    cb[..len].copy_from_slice(&comm.as_bytes()[..len]);
    ks_core::event::DecodedEvent {
        seq: 1,
        comm: comm.to_string(),
        header: EventHeader {
            event_type,
            _pad1: 0,
            timestamp_ns: 1_000,
            pid: 4242,
            tid: 0,
            uid: 0,
            ppid: 1,
            comm: cb,
            syscall_nr: 59,
            _pad2: 0,
            retval: 0,
        },
        filename: filename.map(|s| s.to_string()),
        args: args.map(|s| s.to_string()),
        saddr: None,
        daddr: daddr.map(|s| s.to_string()),
        sport: None,
        dport,
        proto: dport.map(|_| "TCP".to_string()),
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

fn load_engine() -> ks_engine::detector::DetectionEngine {
    let dir = rules_dir();
    let mut engine = ks_engine::detector::DetectionEngine::new();
    let mut total = 0;
    for entry in std::fs::read_dir(&dir).expect("rules 目录存在") {
        let path = entry.expect("read_dir entry").path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "yml" || e == "yaml");
        if is_yaml {
            let content = std::fs::read_to_string(&path).expect("读规则文件");
            total += engine.load_rules_from_yaml(&content).expect("规则加载");
        }
    }
    assert!(total >= 38);
    engine
}

fn rule_names(
    engine: &ks_engine::detector::DetectionEngine,
    event: &ks_core::event::DecodedEvent,
) -> Vec<String> {
    engine
        .match_event(event)
        .into_iter()
        .map(|m| m.rule_name)
        .collect()
}

/// 语义冒烟：新规则必须对构造事件真实命中（防止"能解析但永不命中"的装饰规则）
#[test]
fn test_new_rules_actually_match() {
    let engine = load_engine();

    // uid0 后门用户
    let names = rule_names(
        &engine,
        &make_event(
            1,
            "useradd",
            None,
            Some("-o -u 0 -g 0 backdoor"),
            None,
            None,
        ),
    );
    assert!(
        names.iter().any(|n| n.contains("uid0")),
        "uid0 规则未命中: {:?}",
        names
    );

    // systemd 服务持久化 (bash -c heredoc)
    let names = rule_names(
        &engine,
        &make_event(
            1,
            "bash",
            None,
            Some("-c cat > /etc/systemd/system/evil.service <<EOF"),
            None,
            None,
        ),
    );
    assert!(
        names.iter().any(|n| n.contains("systemd")),
        "systemd 规则未命中: {:?}",
        names
    );

    // 云元数据
    let names = rule_names(
        &engine,
        &make_event(20, "curl", None, None, Some("169.254.169.254"), Some(80)),
    );
    assert!(
        names.iter().any(|n| n.contains("云元数据")),
        "云元数据规则未命中: {:?}",
        names
    );

    // /boot 删除
    let names = rule_names(
        &engine,
        &make_event(
            13,
            "rm",
            Some("/boot/vmlinuz-5.15.0-128-generic"),
            Some("-rf /boot"),
            None,
            None,
        ),
    );
    assert!(
        names.iter().any(|n| n.contains("启动文件")),
        "/boot 删除规则未命中: {:?}",
        names
    );

    // 审计日志清除
    let names = rule_names(
        &engine,
        &make_event(1, "shred", None, Some("-u /var/log/auth.log"), None, None),
    );
    assert!(
        names.iter().any(|n| n.contains("日志清除")),
        "日志清除规则未命中: {:?}",
        names
    );

    // SSH 后门公钥（root 下 open 放行路径）
    let names = rule_names(
        &engine,
        &make_event(
            10,
            "bash",
            Some("/root/.ssh/authorized_keys"),
            None,
            None,
            None,
        ),
    );
    assert!(
        names.iter().any(|n| n.contains("SSH后门")),
        "authorized_keys 规则未命中: {:?}",
        names
    );

    // 反向对照：普通编译行为不应触发任何 critical/high 规则
    let names = rule_names(
        &engine,
        &make_event(1, "gcc", Some("main.c"), Some("-O2 main.c"), None, None),
    );
    assert!(
        names
            .iter()
            .all(|n| !(n.contains("uid0") || n.contains("systemd") || n.contains("元数据"))),
        "普通编译被误报: {:?}",
        names
    );
}

#[test]
fn test_all_rule_files_load() {
    let dir = rules_dir();
    let mut total = 0usize;
    let mut names: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut files = 0usize;

    let entries = std::fs::read_dir(&dir).expect("rules 目录存在");
    for entry in entries {
        let path = entry.expect("read_dir entry").path();
        let is_yaml = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e == "yml" || e == "yaml");
        if !is_yaml {
            continue;
        }
        files += 1;
        let content = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("读取 {} 失败: {}", path.display(), e));
        let rules: Vec<DetectionRule> = serde_yaml::from_str(&content)
            .unwrap_or_else(|e| panic!("解析 {} 失败: {}", path.display(), e));
        assert!(!rules.is_empty(), "{} 至少应包含 1 条规则", path.display());
        for rule in &rules {
            if let Some(prev) = names.insert(rule.name.clone(), path.display().to_string()) {
                panic!(
                    "规则名重复: '{}' 已定义于 {}，重复定义于 {}",
                    rule.name,
                    prev,
                    path.display()
                );
            }
            assert!(
                !rule.alert_message.is_empty(),
                "{} 规则 '{}' 缺少 alert_message",
                path.display(),
                rule.name
            );
        }
        total += rules.len();
    }

    assert!(
        files >= 14,
        "规则文件应 >= 14 个（当前契约），实际 {}",
        files
    );
    assert!(
        total >= 38,
        "规则总数应 >= 38 条（当前契约），实际 {}",
        total
    );
    println!("规则加载回归通过: {} 个文件 / {} 条规则", files, total);
}

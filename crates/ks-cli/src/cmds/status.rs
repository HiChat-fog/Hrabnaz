use anyhow::Result;

use colored::Colorize;
use super::ui::banner;

/// 系统状态报告：配置与静态事实（探针清单、检测机制、取证配置、规则集）。
///
/// 旧实现把"未加载 eBPF 时显示 MockBpfMapReader 的桩数据"当状态展示——
/// 桩数据是常量，读起来像实时 map 快照，实则与运行实例毫无关系，属于误导。
/// 真正的运行时数据有权威来源：状态文件（start 是否在跑）、heartbeat
/// （消费循环是否停摆）、取证日志（事件/告警计数），本命令如实展示这些。
pub async fn run(watch: bool, interval: u64) -> Result<()> {
    banner("内核哨兵 — 系统状态报告");
    println!();

    println!("{}", "── 1. 运行实例 ──".cyan().bold());
    println!();
    match std::fs::read_to_string(super::status_file_path()) {
        Ok(content) => {
            println!("  状态文件: {}", content.trim().replace('\n', "  "));
            let hb_path = super::heartbeat_file_path();
            match std::fs::metadata(&hb_path) {
                Ok(m) => {
                    let age = m
                        .modified()
                        .ok()
                        .and_then(|t| t.elapsed().ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(u64::MAX);
                    if age < 60 {
                        println!("  心跳:      {}s 前（消费循环存活）", age);
                    } else {
                        println!("  心跳:      {}s 前后无更新 — 消费循环可能停摆（kernelsentinel watchdog 可自动处置）", age);
                    }
                }
                Err(_) => println!("  心跳:      无（旧版本引擎或 start 未带心跳）"),
            }
        }
        Err(_) => {
            println!("  (未检测到 start 进程 — 以下为配置概览)");
        }
    }

    println!();
    println!("{}", "── 2. eBPF 探针配置 ──".cyan().bold());
    println!();

    // 探针清单从 loader 取（单一事实来源），不再手抄一份常量表
    let loader = ks_engine::loader::EbpfLoader::new();
    let probes = loader.loaded_probes();
    let tp_count = probes.iter().filter(|p| p.starts_with("trace_")).count();
    let kp_count = probes.iter().filter(|p| p.starts_with("kprobe_") || p.starts_with("kretprobe_")).count();
    println!(
        "  内置探针 {} 个: {} tracepoint + {} kprobe/kretprobe（实际 attach 数随内核符号而定）",
        probes.len(),
        tp_count,
        kp_count
    );
    println!("  覆盖范围: 系统调用 + 进程调度 + VFS + 网络栈 + 凭据/模块/自身完整性");
    println!("  分层:    modern(RingBuf) / legacy(PerfBuf) / ancient(CO-RE 或 NOBTF C loader)");

    println!();
    println!("{}", "── 3. 检测与阻断机制 ──".cyan().bold());
    println!();
    println!("  规则引擎:   YAML 规则 + MITRE ATT&CK 映射");
    println!("  内核推理:   eBPF 内嵌风险累积(PID→0-100), 零浮点");
    println!("  阻断闭环:   block_decisions map — 内核态 bpf_send_signal 实杀(modern), 用户态补杀(老内核)");
    println!("  手动裁决:   kernelsentinel block/unblock 跨进程写 pin map");

    println!();
    println!("{}", "── 4. 取证日志保护 ──".cyan().bold());
    println!();
    println!("  格式:     JSONL + SHA-256 哈希链 防篡改");
    println!("  校验:     replay 从头逐条重算 断裂即发现篡改");
    println!("  滚动:     按天 + 按大小 默认 100MB gzip 归档");
    let config = ks_engine::config::Config::default();
    println!("  目录:     {}", config.forensic.log_dir);
    println!("  清理:     保留 {} 天", config.forensic.retention_days);

    println!();
    println!("{}", "── 5. 检测规则集 ──".cyan().bold());
    println!();
    println!("  规则格式: YAML + Field 枚举 字段名拼写错误会在加载时报错");
    let mut rule_files: Vec<String> = std::fs::read_dir("rules/")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().map(|s| s.to_string()))
                .filter(|s| s.ends_with(".yml") || s.ends_with(".yaml"))
                .collect()
        })
        .unwrap_or_default();
    rule_files.sort();
    println!("  规则集 ({} 个):", rule_files.len());
    for (i, name) in rule_files.iter().enumerate() {
        println!("    {}. {}", i + 1, name);
    }

    println!();
    println!("{}", "── 6. 系统配置 ──".cyan().bold());
    println!();
    println!(
        "  异常阈值:     {:.2} 0.0~1.0 超过则触发异常告警",
        config.detection.anomaly_threshold
    );
    println!("  轮转阈值:     {} MB", config.forensic.max_log_size_mb);
    println!("  CPU 上限:     < {}%", config.performance.max_cpu_percent);
    println!(
        "  内存上限:     < {} MB",
        config.performance.memory_limit_mb
    );

    println!();
    println!("提示:");
    println!("  kernelsentinel start        → 启动实时监控");
    println!("  kernelsentinel replay --file <f> → 取证回放 含哈希链校验 + 攻击链可视化");
    println!("  kernelsentinel watch        → 实时告警流");

    if watch {
        println!();
        println!("{}", format!("── 动态刷新 每 {}s Ctrl+C 退出 ──", interval).cyan().bold());
        let dur = std::time::Duration::from_secs(interval.max(1));
        let mut tick: u64 = 0;
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    println!("\n已退出动态监控");
                    break;
                }
                _ = tokio::time::sleep(dur) => {}
            }
            tick += 1;
            print!("\x1B[2J\x1B[H");
            println!("{} 动态刷新 第 {} 次 {}", "╔".cyan().bold(), tick, "╗".cyan().bold());
            match std::fs::read_to_string(super::status_file_path()) {
                Ok(content) => println!("  运行实例: {}", content.trim().replace('\n', " ")),
                Err(_) => println!("  运行实例: (未检测到 start 进程)"),
            }
            let hb_path = super::heartbeat_file_path();
            match std::fs::metadata(&hb_path).ok().and_then(|m| m.modified().ok()).and_then(|t| t.elapsed().ok()) {
                Some(d) => println!("  心跳:      {}s 前", d.as_secs()),
                None => println!("  心跳:      无"),
            }
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }
    }

    Ok(())
}

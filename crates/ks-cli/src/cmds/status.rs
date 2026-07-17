use anyhow::Result;
use ks_engine::loader::{BpfMapReader, MockBpfMapReader};
use std::io::Write;
use std::sync::Arc;

pub async fn run(watch: bool, interval: u64) -> Result<()> {
    println!("╔══════════════════════════════════════════╗");
    println!("║  内核哨兵 v0.1.0 — 系统状态报告            ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    println!("── 1. eBPF 探针配置 ──");
    println!();
    println!("  内置探针（核心 9 组 另有 E4 容器逃逸/LKM加载/eBPF防护 3 组）");
    println!();
    println!(
        "  {:<4} {:<28} {:<10} {:<24} {:<8}",
        "#", "探针名称", "类型", "挂载点", "内置"
    );
    println!(
        "  {} {} {} {} {}",
        "─".repeat(4),
        "─".repeat(28),
        "─".repeat(10),
        "─".repeat(24),
        "─".repeat(8)
    );

    let probes = [
        (
            "trace_sys_enter",
            "tracepoint",
            "raw_syscalls/sys_enter",
            "是",
        ),
        (
            "trace_sys_exit",
            "tracepoint",
            "raw_syscalls/sys_exit",
            "是",
        ),
        (
            "trace_sched_exec",
            "tracepoint",
            "sched/sched_process_exec",
            "是",
        ),
        (
            "trace_sched_exit",
            "tracepoint",
            "sched/sched_process_exit",
            "是",
        ),
        ("kprobe_vfs_open", "kprobe", "vfs_open", "是"),
        ("kprobe_vfs_write", "kprobe", "vfs_write", "是"),
        ("kprobe_vfs_unlink", "kprobe", "vfs_unlink", "是"),
        ("kprobe_tcp_connect", "kprobe", "tcp_v4_connect", "是"),
        ("kprobe_udp_sendmsg", "kprobe", "udp_sendmsg", "是"),
    ];

    for (i, (name, type_, mount, state)) in probes.iter().enumerate() {
        println!(
            "  {:<4} {:<28} {:<10} {:<24} {:<8}",
            i + 1,
            name,
            type_,
            mount,
            state
        );
    }
    println!();
    println!("  覆盖范围: 系统调用×2 + 进程调度×2 + VFS×3 + 网络栈×2 (核心 9 组)");
    println!("  采集深度: VFS 层 比 syscall 更底层 能捕获内核态操作");

    println!();
    println!("── 2. eBPF Map 配置 ──");
    println!();

    let loader = ks_engine::loader::EbpfLoader::new();
    // status 不加载 eBPF（不调 start） map_reader() 返回 None 时用 MockBpfMapReader
    // 兜底显示 map 配置 is_mock 标记让输出如实标注是 mock 统计而非真实计数
    let (map_reader, is_mock): (Arc<dyn BpfMapReader>, bool) = match loader.map_reader() {
        Some(mr) => (mr, false),
        None => (Arc::new(MockBpfMapReader), true),
    };

    let maps = map_reader.list_maps();
    println!("  已配置 Map ({} 个):", maps.len());
    if is_mock {
        println!("  (未加载 eBPF 显示 mock 统计)");
    }
    for map_name in &maps {
        let snapshot = map_reader
            .read_map(map_name)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        println!(
            "    {} ({}, {} 条)",
            snapshot.name, snapshot.map_type, snapshot.entry_count
        );
        for entry in &snapshot.entries {
            println!(
                "      key={}  value={}  {}",
                entry.key_hex, entry.value_hex, entry.value_display
            );
        }
    }

    println!();
    println!("── 3. 内核推理引擎 ──");
    println!();
    println!("  推理机制: eBPF 程序内嵌推理函数 零浮点运算");
    println!("  风险累积: LRU Hash Map (PID → 0-100 累计风险分)");
    println!();
    println!("  推理维度 (4 维):");
    println!("    1. 敏感文件访问 — /etc/shadow /root/.ssh 等 → +15~40 分");
    println!("    2. 可疑网络连接 — 恶意端口/非标准端口/C2心跳 → +5~50 分");
    println!("    3. 批量文件操作 — 勒索软件特征 写+删+重命名 → +2/次");
    println!("    4. 进程注入检测 — ptrace/异常信号 → +20~35 分");
    println!();
    println!("  阈值机制:");
    println!("    ≥40 分 → 标记高风险 用户态规则引擎二次判定");
    println!("    ≥70 分 → bpf_send_signal 内核态主动阻断");

    println!();
    println!("── 4. 取证日志保护 ──");
    println!();
    println!("  格式:     JSONL + SHA-256 哈希链 防篡改");
    println!("  机制:     每条记录包含 hash=SHA256(内容) + prev_hash=上一条hash");
    println!("  校验:     verify_chain 从头逐条重算 断裂即发现篡改");
    println!("  轮转:     按大小 默认 100MB + gzip 自动压缩归档");
    println!("  清理:     保留 30 天 过期自动删除");
    println!("  链尾哈希: 运行 start 后生成 replay 命令可验证");

    println!();
    println!("── 5. 检测规则集 ──");
    println!();
    println!("  规则格式: YAML + Field 枚举 字段名拼写错误会在加载时报错");
    // 动态读 rules/ 目录 数量始终与实际一致
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
    println!("  MITRE ATT&CK 覆盖:");
    println!("    TA0001 初始入侵 / TA0003 持久化 / TA0004 提权");
    println!("    TA0005 防御规避 / TA0006 凭据访问 / TA0010 数据窃取 / TA0011 命令控制");

    println!();
    println!("── 6. 系统配置 ──");
    println!();

    let config = ks_engine::config::Config::default();
    println!(
        "  引擎缓冲区:   {} 条 环形 O(1) 淘汰",
        config.engine.buffer_size
    );
    println!(
        "  Ring Buffer:  {} KB × 4 探针",
        config.engine.ring_buffer_size_kb
    );
    println!("  批量消费:     {} 条/次", config.engine.batch_size);
    println!(
        "  异常阈值:     {:.2} 0.0~1.0 超过则触发异常告警",
        config.detection.anomaly_threshold
    );
    println!("  取证日志目录: {}", config.forensic.log_dir);
    println!("  轮转阈值:     {} MB", config.forensic.max_log_size_mb);
    println!("  CPU 上限:     < {}%", config.performance.max_cpu_percent);
    println!(
        "  内存上限:     < {} MB",
        config.performance.memory_limit_mb
    );

    println!();
    #[cfg(not(target_os = "linux"))]
    {
        println!("  [MOCK] 当前为非 Linux 环境 探针状态为模拟数据");
        println!("  [MOCK] 真实 eBPF 探针需要 Linux 5.15+ 内核 + root 权限");
    }
    #[cfg(target_os = "linux")]
    {
        println!("  [LINUX] 当前为配置概览 不反映运行时状态");
    }

    println!();
    println!("提示:");
    println!("  kernelsentinel start       → 启动实时监控");
    println!("  kernelsentinel replay <file> → 取证回放 含哈希链校验 + 攻击链可视化");

    // 申报书第七步：status 动态监控模式 定期清屏重绘 map 配置与运行实例
    if watch {
        println!();
        println!("── 动态刷新 每 {}s Ctrl+C 退出 ──", interval);
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
            print!("\x1B[2J\x1B[H"); // 清屏 + 光标归位
            println!("╔ 动态刷新 第 {} 次 ╗", tick);
            for map_name in &maps {
                if let Ok(s) = map_reader.read_map(map_name) {
                    println!("  {:<20} {:<14} {} 条", s.name, s.map_type, s.entry_count);
                }
            }
            match std::fs::read_to_string("/tmp/ks-status.json") {
                Ok(content) => println!("  运行实例: {}", content.trim().replace('\n', " ")),
                Err(_) => println!("  运行实例: (未检测到 start 进程)"),
            }
            let _ = std::io::stdout().flush(); // 非 TTY 管道下强制每 tick 刷新 避免块缓冲丢失
        }
    }

    Ok(())
}

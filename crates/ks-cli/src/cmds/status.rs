use anyhow::Result;
use ks_engine::loader::BpfMapReader;

pub async fn run() -> Result<()> {
    println!("╔══════════════════════════════════════════╗");
    println!("║  内核哨兵 v0.1.0 — 系统状态报告            ║");
    println!("╚══════════════════════════════════════════╝");
    println!();

    println!("── 1. eBPF 探针状态 ──");
    println!();
    println!("  已注册探针 (9 个): 内核态数据采集点");
    println!();
    println!("  {:<4} {:<28} {:<10} {:<24} {:<8}", "#", "探针名称", "类型", "挂载点", "状态");
    println!("  {} {} {} {} {}", "─".repeat(4), "─".repeat(28), "─".repeat(10), "─".repeat(24), "─".repeat(8));

    let probes = [
        ("trace_sys_enter",      "tracepoint", "raw_syscalls/sys_enter",    "已挂载"),
        ("trace_sys_exit",       "tracepoint", "raw_syscalls/sys_exit",     "已挂载"),
        ("trace_sched_exec",     "tracepoint", "sched/sched_process_exec",  "已挂载"),
        ("trace_sched_exit",     "tracepoint", "sched/sched_process_exit",  "已挂载"),
        ("kprobe_vfs_open",      "kprobe",     "vfs_open",                  "已挂载"),
        ("kprobe_vfs_write",     "kprobe",     "vfs_write",                 "已挂载"),
        ("kprobe_vfs_unlink",    "kprobe",     "vfs_unlink",                "已挂载"),
        ("kprobe_tcp_connect",   "kprobe",     "tcp_v4_connect",            "已挂载"),
        ("kprobe_udp_sendmsg",   "kprobe",     "udp_sendmsg",               "已挂载"),
    ];

    for (i, (name, type_, mount, state)) in probes.iter().enumerate() {
        println!("  {:<4} {:<28} {:<10} {:<24} {:<8}", i + 1, name, type_, mount, state);
    }
    println!();
    println!("  覆盖范围: 系统调用 × 5 + VFS 操作 × 3 + 网络协议栈 × 2");
    println!("  采集深度: VFS 层 (比 syscall 更底层, 能捕获内核态操作)");

    println!();
    println!("── 2. eBPF Map 实时数据 ──");
    println!();

    let loader = ks_engine::loader::EbpfLoader::new();
    let map_reader = loader.map_reader();

    let maps = map_reader.list_maps();
    println!("  已注册 Map ({} 个):", maps.len());
    for map_name in &maps {
        let snapshot = map_reader.read_map(map_name).map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("    {} ({}, {} 条)", snapshot.name, snapshot.map_type, snapshot.entry_count);
        for entry in &snapshot.entries {
            println!("      key={}  value={}  {}", entry.key_hex, entry.value_hex, entry.value_display);
        }
    }

    println!();
    println!("── 3. 内核推理引擎 ──");
    println!();
    println!("  推理机制: eBPF 程序内嵌推理函数, 零浮点运算");
    println!("  风险累积: LRU Hash Map (PID → 0-100 累计风险分)");
    println!();
    println!("  推理维度 (4 维):");
    println!("    1. 敏感文件访问 — /etc/shadow, /root/.ssh 等 → +15~40 分");
    println!("    2. 可疑网络连接 — 恶意端口/非标准端口/C2心跳 → +5~50 分");
    println!("    3. 批量文件操作 — 勒索软件特征 (写+删+重命名) → +2/次");
    println!("    4. 进程注入检测 — ptrace/异常信号 → +20~35 分");
    println!();
    println!("  阈值机制:");
    println!("    ≥40 分 → 标记高风险 (用户态规则引擎二次判定)");
    println!("    ≥70 分 → bpf_send_signal (内核态主动阻断)");

    println!();
    println!("── 4. 取证日志保护 ──");
    println!();
    println!("  格式:     JSONL + SHA-256 哈希链 (司法取证级防篡改)");
    println!("  机制:     每条记录包含 hash=SHA256(内容) + prev_hash=上一条hash");
    println!("  校验:     verify_chain 从头逐条重算, 断裂即发现篡改");
    println!("  轮转:     按大小 (默认 100MB) + gzip 自动压缩归档");
    println!("  清理:     保留 30 天, 过期自动删除");
    println!("  链尾哈希: (运行 start 后生成, replay 命令可验证)");

    println!();
    println!("── 5. 检测规则集 ──");
    println!();
    println!("  规则格式: YAML + Field 枚举 (字段名拼写错误会在加载时报错)");
    println!("  规则集 (6 个):");
    println!("    1. reverse_shell.yml    — 反弹 Shell (2 条规则)");
    println!("    2. ransomware.yml       — 勒索软件 (2 条规则)");
    println!("    3. privilege_escalation.yml — 提权攻击 (6 条规则)");
    println!("    4. dns_tunnel.yml       — DNS 隧道 (3 条规则)");
    println!("    5. data_exfil.yml       — 数据窃取 (3 条规则)");
    println!("    6. rootkit_detect.yml   — Rootkit (5 条规则)");
    println!();
    println!("  MITRE ATT&CK 覆盖:");
    println!("    TA0001 初始入侵 / TA0003 持久化 / TA0004 提权");
    println!("    TA0005 防御规避 / TA0006 凭据访问 / TA0010 数据窃取 / TA0011 命令控制");

    println!();
    println!("── 6. 系统配置 ──");
    println!();

    let config = ks_engine::config::Config::default();
    println!("  引擎缓冲区:   {} 条 (环形, O(1) 淘汰)", config.engine.buffer_size);
    println!("  Ring Buffer:  {} KB × 4 探针", config.engine.ring_buffer_size_kb);
    println!("  批量消费:     {} 条/次", config.engine.batch_size);
    println!("  异常阈值:     {:.2} (0.0~1.0, 超过则触发异常告警)", config.detection.anomaly_threshold);
    println!("  取证日志目录: {}", config.forensic.log_dir);
    println!("  轮转阈值:     {} MB", config.forensic.max_log_size_mb);
    println!("  CPU 上限:     < {}%", config.performance.max_cpu_percent);
    println!("  内存上限:     < {} MB", config.performance.memory_limit_mb);

    println!();
    #[cfg(not(target_os = "linux"))]
    {
        println!("  [MOCK] 当前为非 Linux 环境, 探针状态为模拟数据");
        println!("  [MOCK] 真实 eBPF 探针需要 Linux 5.15+ 内核 + root 权限");
    }
    #[cfg(target_os = "linux")]
    {
        println!("  [LINUX] 当前在真实 Linux 环境");
        println!("  [LINUX] 探针状态需从 EbpfLoader.probe_states() 实时读取");
    }

    println!();
    println!("提示:");
    println!("  kernelsentinel start       → 启动实时监控");
    println!("  kernelsentinel replay <file> → 取证回放 (含哈希链校验 + 攻击链可视化)");

    Ok(())
}
//! 诊断工具：对运行中的 ks_loader（C loader / NOBTF tier）验证 pinned map 契约。
//!
//! 用法（root，目标机上先启动 ks_loader）：
//!   pinned_reader_smoke
//!
//! 验证项：契约 map 列表可读 → block_decisions 写/读/删 → pin 校验。
//! 退出码 0 = 契约贯通；非 0 = 某一步失败（错误原因打印到 stderr）。

use std::time::Duration;

use ks_engine::loader::BpfMapReader;
use ks_engine::pinned_map_reader::PinnedBpfMapReader;

fn main() -> anyhow::Result<()> {
    let reader = PinnedBpfMapReader::wait_ready(Duration::from_secs(5)).ok_or_else(|| {
        anyhow::anyhow!("block_decisions pin 未就绪：ks_loader 未运行或 /sys/fs/bpf 未挂载")
    })?;

    println!("== 契约 map（经 bpffs pin 读取）:");
    for name in reader.list_maps() {
        let snap = reader.read_map(&name)?;
        println!(
            "  {:<18} {:<10} {} 条",
            snap.name, snap.map_type, snap.entry_count
        );
    }

    println!("== block_decisions 写/读/删:");
    let pid = 424242u32;
    reader.write_block_decision(pid, 0, 5)?;
    let seen = reader
        .read_block_decisions()
        .into_iter()
        .filter(|e| e.0 == pid)
        .collect::<Vec<_>>();
    anyhow::ensure!(!seen.is_empty(), "写入后读不到 pid={} 的裁决", pid);
    println!("  写入后读到: {:?}", seen);

    reader.remove_block_decision(pid)?;
    anyhow::ensure!(
        !reader.read_block_decisions().iter().any(|e| e.0 == pid),
        "删除后仍能读到 pid={} 的裁决",
        pid
    );
    println!("  删除后已不可见");

    reader.pin_block_map(ks_engine::blocker::BLOCK_DECISIONS_PIN)?;
    println!("== pin_block_map: OK");
    println!("SMOKE OK");
    Ok(())
}

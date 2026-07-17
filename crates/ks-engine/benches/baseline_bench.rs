//! G5.1: baseline 性能压测 — BaselineManager::update_from_event + detect_deviation。
//!
//! 目标：<10μs/次（update + detect 合计）
//! 运行：cargo bench --workspace -p ks-engine --bench baseline_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ks_core::event::EventHeader;
use ks_engine::aggregator::DecodedEvent;
use ks_engine::baseline::BaselineManager;

fn make_event(pid: u32, comm: &str, event_type: u32) -> DecodedEvent {
    DecodedEvent {
        seq: 0,
        header: EventHeader {
            event_type,
            _pad1: 0,
            timestamp_ns: 1_625_340_000_000_000,
            pid,
            tid: pid,
            uid: 0,
            ppid: 1,
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

fn bench_baseline(c: &mut Criterion) {
    let mut mgr = BaselineManager::new();
    // 预热：填充 50 条事件建立基线
    for _ in 0..50u32 {
        let evt = make_event(1234, "bash", 1);
        mgr.update_from_event(&evt);
    }

    let probe = make_event(1234, "bash", 1);

    c.bench_function("update_from_event", |b| {
        b.iter(|| {
            black_box(&mut mgr).update_from_event(black_box(&probe));
        });
    });

    c.bench_function("detect_deviation", |b| {
        b.iter(|| {
            let _ = black_box(&mgr).detect_deviation(black_box(1234));
        });
    });

    // 组合：update + detect（真实事件循环单次开销）
    c.bench_function("update_then_detect", |b| {
        b.iter(|| {
            black_box(&mut mgr).update_from_event(black_box(&probe));
            let _ = black_box(&mgr).detect_deviation(black_box(1234));
        });
    });
}

criterion_group!(benches, bench_baseline);
criterion_main!(benches);

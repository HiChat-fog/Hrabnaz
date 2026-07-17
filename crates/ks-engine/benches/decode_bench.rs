//! G5.1: decode 性能压测 — EventAggregator::decode 单条事件。
//!
//! 目标：>100k eps（<10μs/条）
//! 运行：cargo bench --workspace -p ks-engine --bench decode_bench

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ks_core::event::EventHeader;
use ks_engine::aggregator::EventAggregator;

fn make_exec_event_bytes() -> Vec<u8> {
    // ExecEvent = EventHeader (56B) + filename [u8;256] + args [u8;512] = 824B
    let size = std::mem::size_of::<ks_core::event::ExecEvent>();
    let mut buf = vec![0u8; size];
    // event_type = 1 (ProcessExec)
    let et: u32 = 1;
    buf[..4].copy_from_slice(&et.to_ne_bytes());
    // timestamp_ns (offset 8)
    let ts: u64 = 1_625_340_000_000_000;
    buf[8..16].copy_from_slice(&ts.to_ne_bytes());
    // pid (offset 16)
    let pid: u32 = 1234;
    buf[16..20].copy_from_slice(&pid.to_ne_bytes());
    // comm (offset 32, 16 bytes) — "bash\0..."
    let comm = b"bash\0\0\0\0\0\0\0\0\0\0\0\0";
    buf[32..48].copy_from_slice(comm);
    // filename (offset 56, 256 bytes) — "/bin/bash\0..."
    let fname = b"/bin/bash\0";
    buf[56..56 + fname.len()].copy_from_slice(fname);
    buf
}

fn bench_decode(c: &mut Criterion) {
    let bytes = make_exec_event_bytes();
    let mut agg = EventAggregator::new(10_000);

    c.bench_function("decode_exec_event", |b| {
        b.iter(|| {
            let _ = black_box(&mut agg).decode(black_box(&bytes));
        });
    });

    // 同时测 EventHeader 单独解码（最小事件 ProcessExit 仅需 header）
    let header_size = std::mem::size_of::<EventHeader>();
    let mut exit_bytes = vec![0u8; header_size];
    let et: u32 = 2; // ProcessExit
    exit_bytes[..4].copy_from_slice(&et.to_ne_bytes());
    c.bench_function("decode_exit_event", |b| {
        b.iter(|| {
            let _ = black_box(&mut agg).decode(black_box(&exit_bytes));
        });
    });
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);

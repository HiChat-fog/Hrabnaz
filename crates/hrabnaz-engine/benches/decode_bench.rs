use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hrabnaz_core::event::EventHeader;
use hrabnaz_engine::aggregator::EventAggregator;

fn make_exec_event_bytes() -> Vec<u8> {
    let size = std::mem::size_of::<hrabnaz_core::event::ExecEvent>();
    let mut buf = vec![0u8; size];
    let et: u32 = 1;
    buf[..4].copy_from_slice(&et.to_ne_bytes());
    let ts: u64 = 1_625_340_000_000_000;
    buf[8..16].copy_from_slice(&ts.to_ne_bytes());
    let pid: u32 = 1234;
    buf[16..20].copy_from_slice(&pid.to_ne_bytes());
    let comm = b"bash\0\0\0\0\0\0\0\0\0\0\0\0";
    buf[32..48].copy_from_slice(comm);
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

    let header_size = std::mem::size_of::<EventHeader>();
    let mut exit_bytes = vec![0u8; header_size];
    let et: u32 = 2;
    exit_bytes[..4].copy_from_slice(&et.to_ne_bytes());
    c.bench_function("decode_exit_event", |b| {
        b.iter(|| {
            let _ = black_box(&mut agg).decode(black_box(&exit_bytes));
        });
    });
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);

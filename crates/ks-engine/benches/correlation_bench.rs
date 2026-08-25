use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ks_core::event::EventHeader;
use ks_engine::aggregator::DecodedEvent;
use ks_engine::correlation::CorrelationEngine;
use ks_engine::process_tree::ProcessTreeManager;

fn make_event(pid: u32, ppid: u32, comm: &str, event_type: u32) -> DecodedEvent {
    DecodedEvent {
        seq: 0,
        header: EventHeader {
            event_type,
            _pad1: 0,
            timestamp_ns: 1_625_340_000_000_000,
            pid,
            tid: pid,
            uid: 0,
            ppid,
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

fn bench_correlation(c: &mut Criterion) {
    let mut engine = CorrelationEngine::new(300);
    let mut tree = ProcessTreeManager::new();
    for i in 0..100u32 {
        let evt = make_event(i + 100, 1, "bash", 1);
        engine.detect_correlations_with_tree(&evt, Some(&tree));
        tree.update_from_event(&evt);
    }

    let probe = make_event(9999, 100, "nc", 1);
    c.bench_function("detect_correlations_with_tree", |b| {
        b.iter(|| {
            black_box(&mut engine)
                .detect_correlations_with_tree(black_box(&probe), black_box(Some(&tree)));
        });
    });

    c.bench_function("detect_correlations_no_tree", |b| {
        b.iter(|| {
            black_box(&mut engine).detect_correlations_with_tree(black_box(&probe), None);
        });
    });
}

criterion_group!(benches, bench_correlation);
criterion_main!(benches);

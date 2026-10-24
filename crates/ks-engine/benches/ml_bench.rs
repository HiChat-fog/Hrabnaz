use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ks_core::event::DecodedEvent;
use ks_core::event::EventHeader;
use ks_engine::ml_detector::AdaptiveDetector;

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

fn bench_ml(c: &mut Criterion) {
    let mut detector = AdaptiveDetector::new();
    for _ in 0..100u32 {
        let evt = make_event(1234, "bash", 1);
        detector.update_from_event(&evt);
    }

    let probe = make_event(1234, "bash", 1);

    c.bench_function("update_from_event", |b| {
        b.iter(|| {
            black_box(&mut detector).update_from_event(black_box(&probe));
        });
    });

    c.bench_function("detect", |b| {
        b.iter(|| {
            let _ = black_box(&detector).detect(black_box(1234));
        });
    });

    c.bench_function("update_then_detect", |b| {
        b.iter(|| {
            black_box(&mut detector).update_from_event(black_box(&probe));
            let _ = black_box(&detector).detect(black_box(1234));
        });
    });
}

criterion_group!(benches, bench_ml);
criterion_main!(benches);

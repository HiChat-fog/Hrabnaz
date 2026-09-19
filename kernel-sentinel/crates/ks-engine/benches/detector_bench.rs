use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ks_core::event::EventHeader;
use ks_engine::aggregator::DecodedEvent;
use ks_engine::detector::DetectionEngine;

fn make_event() -> DecodedEvent {
    let header = EventHeader {
        event_type: 1,
        _pad1: 0,
        timestamp_ns: 1_625_340_000_000_000,
        pid: 1234,
        tid: 0,
        uid: 0,
        ppid: 100,
        comm: *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
        syscall_nr: 59,
        _pad2: 0,
        retval: 0,
    };
    DecodedEvent {
        seq: 1,
        header,
        comm: "bash".to_string(),
        filename: Some("/etc/shadow".to_string()),
        args: Some("-c id".to_string()),
        saddr: Some("1.2.3.4".to_string()),
        daddr: Some("8.8.8.8".to_string()),
        sport: Some(44330),
        dport: Some(4444),
        proto: Some("TCP".to_string()),
        target_pid: None,
        signal: None,
        file_bytes: Some(1024),
        module_name: None,
        prog_name: None,
        source_ns_inum: None,
        target_ns_inum: None,
        cap_eff: None,
        action: None,
    }
}

fn load_real_rules() -> DetectionEngine {
    let rules_dir = std::env::var("CARGO_MANIFEST_DIR")
        .map(|d| format!("{}/../../rules", d))
        .unwrap_or_else(|_| "rules".to_string());
    let mut engine = DetectionEngine::new();
    for entry in std::fs::read_dir(&rules_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "yml").unwrap_or(false) {
            let yaml = std::fs::read_to_string(&path).unwrap();
            let _ = engine.load_rules_from_yaml(&yaml);
        }
    }
    engine
}

fn bench_detector_match(c: &mut Criterion) {
    let engine = load_real_rules();
    let event = make_event();
    c.bench_function("match_event_full_rules", |b| {
        b.iter(|| {
            let _ = black_box(&engine).match_event(black_box(&event));
        });
    });
}

criterion_group!(benches, bench_detector_match);
criterion_main!(benches);

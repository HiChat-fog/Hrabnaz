use ks_server::metrics;

#[test]
fn test_metrics_render() {

    metrics::record_event(0);
    metrics::record_alert("low");
    metrics::set_map_entries("__test__", 0);
    metrics::set_tier_status("__test__", false);
    metrics::record_ringbuf_lost();

    metrics::KS_EVENT_PROCESSING_SECONDS
        .with_label_values(&["__test__"])
        .observe(0.001);

    let out = metrics::render_metrics();
    assert!(!out.is_empty(), "render_metrics() 应返回非空字符串");

    assert!(
        out.contains("ks_events_total"),
        "输出应包含 ks_events_total，实际:\n{}",
        out
    );
    assert!(
        out.contains("ks_alerts_total"),
        "输出应包含 ks_alerts_total，实际:\n{}",
        out
    );
    assert!(
        out.contains("ks_map_entries"),
        "输出应包含 ks_map_entries，实际:\n{}",
        out
    );
    assert!(
        out.contains("ks_event_processing_seconds"),
        "输出应包含 ks_event_processing_seconds，实际:\n{}",
        out
    );
    assert!(
        out.contains("ks_tier_status"),
        "输出应包含 ks_tier_status，实际:\n{}",
        out
    );
    assert!(
        out.contains("ks_ringbuf_lost_total"),
        "输出应包含 ks_ringbuf_lost_total，实际:\n{}",
        out
    );
}

#[test]
fn test_record_event() {
    metrics::record_event(1);
    let out = metrics::render_metrics();
    assert!(
        out.contains("ks_events_total"),
        "record_event 后应包含 ks_events_total，实际:\n{}",
        out
    );

    assert!(
        out.contains(r#"event_type="1""#),
        "应包含 event_type=\"1\" 标签，实际:\n{}",
        out
    );
}

#[test]
fn test_record_alert() {
    metrics::record_alert("high");
    let out = metrics::render_metrics();
    assert!(
        out.contains("ks_alerts_total"),
        "record_alert 后应包含 ks_alerts_total，实际:\n{}",
        out
    );
    assert!(
        out.contains(r#"severity="high""#),
        "应包含 severity=\"high\" 标签，实际:\n{}",
        out
    );
}

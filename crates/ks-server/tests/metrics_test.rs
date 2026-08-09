//! metrics模块单元测试。
//!
//! 验证Prometheus指标导出(render_metrics)与记录函数(record_event/record_alert)的基本正确性。所有测试共用同一全局Registry(once_cell::Lazy单例),因此测试间会共享已记录的指标值,断言只检查包含指标名,不检查具体计数。

use ks_server::metrics;

/// 验证render_metrics()返回非空字符串,且包含全部已注册指标名。
/// 这能确保REGISTRY初始化正常、TextEncoder编码成功。
///
/// 注意:IntGaugeVec/HistogramVec类型指标在首次设置label value前
/// 不会出现在Prometheus输出中(无样本可输出),因此本测试先对每个
/// Vec指标touch一次(设置/观测),再断言其指标名出现。
#[test]
fn test_metrics_render() {
    // 先touch所有Vec类型指标,确保它们有label value可输出。
    metrics::record_event(0);
    metrics::record_alert("low");
    metrics::set_map_entries("__test__", 0);
    metrics::set_tier_status("__test__", false);
    metrics::record_ringbuf_lost();
    // HistogramVec也需要观测一次才会在输出中暴露bucket。
    metrics::KS_EVENT_PROCESSING_SECONDS
        .with_label_values(&["__test__"])
        .observe(0.001);

    let out = metrics::render_metrics();
    assert!(!out.is_empty(), "render_metrics() 应返回非空字符串");

    // 6个指标的HELP/TYPE行都应出现在文本输出中。
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

/// 验证record_event(event_type)后,render_metrics()输出中包含ks_events_total
/// 指标样本(带event_type="1" label)。
#[test]
fn test_record_event() {
    metrics::record_event(1);
    let out = metrics::render_metrics();
    assert!(
        out.contains("ks_events_total"),
        "record_event 后应包含 ks_events_total，实际:\n{}",
        out
    );
    // 验证label值出现(CounterVec输出形如ks_events_total{event_type="1"} <n>)。
    assert!(
        out.contains(r#"event_type="1""#),
        "应包含 event_type=\"1\" 标签，实际:\n{}",
        out
    );
}

/// 验证record_alert(severity)后,render_metrics()输出中包含ks_alerts_total
/// 指标样本(带severity="high" label)。
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

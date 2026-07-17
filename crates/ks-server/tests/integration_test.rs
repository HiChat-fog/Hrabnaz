//! ks-server 集成测试 — Phase E1.3
//!
//! 测试 /api/v1/stats 端点通过 ServerState::with_map_reader 持有 MockBpfMapReader 时，
//! 正确返回 5 个共享 BPF map 的统计信息 (map_stats 字段)。
//!
//! 测试方式：用 tower::ServiceExt::oneshot 直接调用 axum::Router，无需启动真实 TCP 监听。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use ks_engine::loader::{BpfMapReader, MockBpfMapReader};
use ks_server::routes::router;
use ks_server::ServerState;

/// Phase E1.3: 验证 /api/v1/stats 端点在持有 MockBpfMapReader 时返回真实 map_stats 数据。
///
/// MockBpfMapReader 固定返回 5 个共享 map:
///   risk_scores (HASH) / ip_whitelist (HASH) / net_conn_history (LRU_HASH)
///   freq_counters (PERCPU_ARRAY) / infer_config (ARRAY)
///
/// 每个 MapStatResponse 应含 name / map_type / entry_count 三个字段。
#[tokio::test]
async fn test_stats_endpoint_returns_real_map_data() {
    // 1. 创建 ServerState::with_map_reader("test", Arc::new(MockBpfMapReader))
    let map_reader: Arc<dyn ks_engine::loader::BpfMapReader + Send + Sync> =
        Arc::new(MockBpfMapReader);
    let state = Arc::new(ServerState::with_map_reader("test", map_reader));

    // 2. 构建 axum Router 并通过 tower::ServiceExt::oneshot 发起单次请求
    let app = router(state);
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot 请求不应失败");

    // 3. 验证 HTTP 状态码 200
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/api/v1/stats 应返回 200 OK"
    );

    // 4. 解析响应体为 JSON
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("读取响应体不应失败");
    let stats: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("响应体应为合法 JSON");

    // 5. 断言 map_stats 字段存在且长度为 5 (MockBpfMapReader 返回 5 个固定 map)
    let map_stats = stats["map_stats"]
        .as_array()
        .expect("map_stats 字段应存在且为数组");
    assert_eq!(
        map_stats.len(),
        5,
        "map_stats 应有 5 个条目 (MockBpfMapReader 返回 5 个固定 map)"
    );

    // 6. 每个 MapStat 含 name / map_type / entry_count 字段
    for (i, ms) in map_stats.iter().enumerate() {
        assert!(ms["name"].is_string(), "map_stats[{}].name 应为字符串", i);
        assert!(
            ms["map_type"].is_string(),
            "map_stats[{}].map_type 应为字符串",
            i
        );
        assert!(
            ms["entry_count"].is_number(),
            "map_stats[{}].entry_count 应为数字",
            i
        );
    }

    // 7. 验证具体的 map 名称和类型 (MockBpfMapReader 返回固定顺序)
    let expected = [
        ("risk_scores", "HASH"),
        ("ip_whitelist", "HASH"),
        ("net_conn_history", "LRU_HASH"),
        ("freq_counters", "PERCPU_ARRAY"),
        ("infer_config", "ARRAY"),
    ];
    for (i, (name, map_type)) in expected.iter().enumerate() {
        assert_eq!(
            map_stats[i]["name"], *name,
            "map_stats[{}].name 应为 {}",
            i, name
        );
        assert_eq!(
            map_stats[i]["map_type"], *map_type,
            "map_stats[{}].map_type 应为 {}",
            i, map_type
        );
        // MockBpfMapReader 的 entry_count 固定为 0
        assert_eq!(
            map_stats[i]["entry_count"], 0,
            "map_stats[{}].entry_count 应为 0 (MockBpfMapReader 固定返回 0)",
            i
        );
    }

    // 8. 验证 StatsResponse 的其他字段也存在 (total / by_severity / by_status)
    assert!(stats["total"].is_number(), "stats.total 字段应存在");
    assert!(
        stats["by_severity"].is_object(),
        "stats.by_severity 字段应存在"
    );
    assert!(stats["by_status"].is_object(), "stats.by_status 字段应存在");
}

/// Phase E1.3: 对照测试 — 当 ServerState 不持有 map_reader (None) 时，
/// /api/v1/stats 应返回空 map_stats 数组。
#[tokio::test]
async fn test_stats_endpoint_empty_map_stats_without_reader() {
    let state = Arc::new(ServerState::with_tier("test-no-reader"));
    let app = router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot 请求不应失败");

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("读取响应体不应失败");
    let stats: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("响应体应为合法 JSON");

    let map_stats = stats["map_stats"]
        .as_array()
        .expect("map_stats 字段应存在且为数组");
    assert_eq!(map_stats.len(), 0, "无 map_reader 时 map_stats 应为空数组");
}

/// Phase E1.3: 直接测试 MockBpfMapReader::list_map_stats() 返回 5 个条目，
/// 验证 MapStat → MapStatResponse 转换的数据源端正确性。
#[test]
fn test_mock_bpf_map_reader_list_map_stats_direct() {
    let reader = MockBpfMapReader;
    let stats = reader.list_map_stats();

    assert_eq!(stats.len(), 5, "MockBpfMapReader 应返回 5 个 map 统计");

    // 验证每个条目都有非空 name 和 map_type
    for s in &stats {
        assert!(!s.name.is_empty(), "name 不应为空");
        assert!(!s.map_type.is_empty(), "map_type 不应为空");
    }

    // 验证顺序和具体值
    assert_eq!(stats[0].name, "risk_scores");
    assert_eq!(stats[0].map_type, "HASH");
    assert_eq!(stats[1].name, "ip_whitelist");
    assert_eq!(stats[1].map_type, "HASH");
    assert_eq!(stats[2].name, "net_conn_history");
    assert_eq!(stats[2].map_type, "LRU_HASH");
    assert_eq!(stats[3].name, "freq_counters");
    assert_eq!(stats[3].map_type, "PERCPU_ARRAY");
    assert_eq!(stats[4].name, "infer_config");
    assert_eq!(stats[4].map_type, "ARRAY");

    // entry_count 都应为 0 (mock 不读取真实 map)
    assert!(
        stats.iter().all(|s| s.entry_count == 0),
        "所有 entry_count 应为 0"
    );
}

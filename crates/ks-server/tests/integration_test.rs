use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use ks_engine::loader::{BpfMapReader, MockBpfMapReader};
use ks_server::routes::router;
use ks_server::ServerState;

#[tokio::test]
async fn test_stats_endpoint_returns_real_map_data() {

    let map_reader: Arc<dyn ks_engine::loader::BpfMapReader + Send + Sync> =
        Arc::new(MockBpfMapReader);
    let state = Arc::new(ServerState::with_map_reader("test", map_reader));

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

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/api/v1/stats 应返回 200 OK"
    );

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("读取响应体不应失败");
    let stats: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("响应体应为合法 JSON");

    let map_stats = stats["map_stats"]
        .as_array()
        .expect("map_stats 字段应存在且为数组");
    assert_eq!(
        map_stats.len(),
        6,
        "map_stats 应有 6 个条目 (MockBpfMapReader 返回 6 个固定 map)"
    );

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

        assert_eq!(
            map_stats[i]["entry_count"], 0,
            "map_stats[{}].entry_count 应为 0 (MockBpfMapReader 固定返回 0)",
            i
        );
    }

    assert!(stats["total"].is_number(), "stats.total 字段应存在");
    assert!(
        stats["by_severity"].is_object(),
        "stats.by_severity 字段应存在"
    );
    assert!(stats["by_status"].is_object(), "stats.by_status 字段应存在");
}

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

#[test]
fn test_mock_bpf_map_reader_list_map_stats_direct() {
    let reader = MockBpfMapReader;
    let stats = reader.list_map_stats();

    assert_eq!(stats.len(), 6, "MockBpfMapReader 应返回 6 个 map 统计");

    for s in &stats {
        assert!(!s.name.is_empty(), "name 不应为空");
        assert!(!s.map_type.is_empty(), "map_type 不应为空");
    }

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

    assert!(
        stats.iter().all(|s| s.entry_count == 0),
        "所有 entry_count 应为 0"
    );
}

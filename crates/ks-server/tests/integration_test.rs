//! ks-server集成测试。
//!
//! 测试/api/v1/stats端点通过ServerState::with_map_reader持有MockBpfMapReader时,正确返回5个共享BPF map的统计信息(map_stats字段)。
//!
//! 测试方式:用tower::ServiceExt::oneshot直接调用axum::Router,无需启动真实TCP监听。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::sync::Arc;
use tower::ServiceExt;

use ks_engine::loader::{BpfMapReader, MockBpfMapReader};
use ks_server::routes::router;
use ks_server::ServerState;

/// 验证/api/v1/stats端点在持有MockBpfMapReader时返回真实map_stats数据。
///
/// MockBpfMapReader固定返回5个共享map:
///   risk_scores (HASH) / ip_whitelist (HASH) / net_conn_history (LRU_HASH)
///   freq_counters (PERCPU_ARRAY) / infer_config (ARRAY)
///
/// 每个MapStatResponse应含name/map_type/entry_count三个字段。
#[tokio::test]
async fn test_stats_endpoint_returns_real_map_data() {
    // 创建ServerState::with_map_reader("test", Arc::new(MockBpfMapReader))
    let map_reader: Arc<dyn ks_engine::loader::BpfMapReader + Send + Sync> =
        Arc::new(MockBpfMapReader);
    let state = Arc::new(ServerState::with_map_reader("test", map_reader));

    // 构建axum Router并通过tower::ServiceExt::oneshot发起单次请求
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

    // 验证HTTP状态码200
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "/api/v1/stats 应返回 200 OK"
    );

    // 解析响应体为JSON
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("读取响应体不应失败");
    let stats: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("响应体应为合法 JSON");

    // 断言map_stats字段存在且长度为6(MockBpfMapReader返回6个固定map,含protected_comms)
    let map_stats = stats["map_stats"]
        .as_array()
        .expect("map_stats 字段应存在且为数组");
    assert_eq!(
        map_stats.len(),
        6,
        "map_stats 应有 6 个条目 (MockBpfMapReader 返回 6 个固定 map)"
    );

    // 每个MapStat含name/map_type/entry_count字段
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

    // 验证具体的map名称和类型(MockBpfMapReader返回固定顺序)
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
        // MockBpfMapReader的entry_count固定为0
        assert_eq!(
            map_stats[i]["entry_count"], 0,
            "map_stats[{}].entry_count 应为 0 (MockBpfMapReader 固定返回 0)",
            i
        );
    }

    // 验证StatsResponse的其他字段也存在(total/by_severity/by_status)
    assert!(stats["total"].is_number(), "stats.total 字段应存在");
    assert!(
        stats["by_severity"].is_object(),
        "stats.by_severity 字段应存在"
    );
    assert!(stats["by_status"].is_object(), "stats.by_status 字段应存在");
}

/// 对照测试:当ServerState不持有map_reader(None)时,
/// /api/v1/stats应返回空map_stats数组。
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

/// 直接测试MockBpfMapReader::list_map_stats()返回6个条目,
/// 验证MapStat到MapStatResponse转换的数据源端正确性。
#[test]
fn test_mock_bpf_map_reader_list_map_stats_direct() {
    let reader = MockBpfMapReader;
    let stats = reader.list_map_stats();

    assert_eq!(stats.len(), 6, "MockBpfMapReader 应返回 6 个 map 统计");

    // 验证每个条目都有非空name和map_type
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

    // entry_count都应为0(mock不读取真实map)
    assert!(
        stats.iter().all(|s| s.entry_count == 0),
        "所有 entry_count 应为 0"
    );
}

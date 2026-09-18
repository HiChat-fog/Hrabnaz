use crate::state::SharedState;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    http::{header::AUTHORIZATION, Request, StatusCode},
    response::{IntoResponse, Response},
};
use std::sync::atomic::{AtomicUsize, Ordering};

/// WS 并发连接数上限：无上限时慢客户端可耗尽 fd/内存
const MAX_WS_CONNECTIONS: usize = 64;

static WS_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(st): State<SharedState>,
    req: Request<axum::body::Body>,
) -> Response {
    // /ws 已从 auth 白名单移除，升级前在此校验 token（query ?token= 或 Authorization: Bearer）
    let auth = st.auth_snapshot();
    if auth.enabled {
        let provided = req
            .headers()
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer ").map(|s| s.to_string()))
            .or_else(|| {
                req.uri().query().and_then(|q| {
                    q.split('&').find_map(|kv| {
                        let (k, v) = kv.split_once('=')?;
                        (k == "token").then(|| v.to_string())
                    })
                })
            });
        if !crate::auth::validate_token(&auth, provided.as_deref()) {
            return (
                StatusCode::UNAUTHORIZED,
                "missing or invalid token (pass ?token= or Authorization: Bearer)",
            )
                .into_response();
        }
    }

    if WS_CONNECTIONS.load(Ordering::Relaxed) >= MAX_WS_CONNECTIONS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many websocket connections",
        )
            .into_response();
    }

    ws.on_upgrade(move |socket| async move {
        WS_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        forward_alerts(socket, st).await;
        WS_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
    })
}

async fn forward_alerts(mut socket: WebSocket, st: SharedState) {
    let mut rx = st.tx.subscribe();
    log::info!("[ws] 新客户端连接，开始推送告警");
    loop {
        match rx.recv().await {
            Ok(alert) => match serde_json::to_string(&alert) {
                Ok(json) => {
                    if socket.send(Message::Text(json)).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    log::warn!("[ws] 告警序列化失败: {}", e);
                    continue;
                }
            },
            // 慢客户端落后超过通道容量时收到 Lagged：跳过丢失段继续推送，
            // 旧实现 `while let Ok(..)` 直接退出把客户端踢掉
            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                log::warn!("[ws] 客户端落后 {} 条告警，跳过丢失段", n);
                continue;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        }
    }
    log::info!("[ws] 客户端断开");
}

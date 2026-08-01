//! WebSocket实时告警推送。
//!
//! 客户端连接/ws/alerts后,订阅ServerState的broadcast channel,每当push_alert被调用,客户端收到JSON序列化的Alert。

use crate::state::SharedState;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    response::IntoResponse,
};

pub async fn ws_handler(ws: WebSocketUpgrade, State(st): State<SharedState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| forward_alerts(socket, st))
}

async fn forward_alerts(mut socket: WebSocket, st: SharedState) {
    let mut rx = st.tx.subscribe();
    log::info!("[ws] 新客户端连接，开始推送告警");
    while let Ok(alert) = rx.recv().await {
        match serde_json::to_string(&alert) {
            Ok(json) => {
                if socket.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                log::warn!("[ws] 告警序列化失败: {}", e);
                continue;
            }
        }
    }
    log::info!("[ws] 客户端断开");
}

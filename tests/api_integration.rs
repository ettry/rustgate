//! api.rs 网络 IO 层集成测试：真实启动 axum router + HTTP 客户端请求。
//!
//! 覆盖：Web UI 页面、鉴权中间件、stats/alerts 端点、WebSocket 告警推送。

use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use rustgate::api;
use rustgate::bus::AlertBus;

/// 启动一个监听随机端口的 API 服务，返回 (addr, bus)。
async fn spawn_api(token: &str) -> (std::net::SocketAddr, Arc<AlertBus>) {
    let bus = Arc::new(AlertBus::new());
    let app = api::router(Arc::clone(&bus), token.to_string());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    // 等服务就绪
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (addr, bus)
}

/// 建立 http1 连接，返回 sender（conn 后台跑）。
async fn connect(
    addr: std::net::SocketAddr,
) -> hyper::client::conn::http1::SendRequest<Empty<Bytes>> {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let io = TokioIo::new(stream);
    let (sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
    tokio::spawn(async move {
        conn.await.unwrap();
    });
    sender
}

/// 发送请求并返回 (status, body 文本)。
async fn request(
    sender: &mut hyper::client::conn::http1::SendRequest<Empty<Bytes>>,
    path: &str,
    auth: Option<&str>,
) -> (hyper::StatusCode, String) {
    let mut builder = hyper::Request::builder().uri(path);
    if let Some(t) = auth {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }
    let req = builder.body(Empty::<Bytes>::new()).unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn web_ui_is_public_and_serves_html() {
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    let (status, body) = request(&mut sender, "/", None).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("<title>RustGate WAF 监控</title>"));
    assert!(body.contains("连接设置"));
}

#[tokio::test]
async fn rest_api_requires_bearer_token() {
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    // 无 token → 401
    let (status, _) = request(&mut sender, "/api/stats", None).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);

    // 错误 token → 401
    let (status, _) = request(&mut sender, "/api/stats", Some("wrong")).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);

    // 前缀相同、仅后续字节不同的错误 token → 401
    // （专门暴露恒定时间比较中 |= 退化为 &= 的变异）
    let (status, _) = request(&mut sender, "/api/stats", Some("tesu-token")).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);

    // 正确 token → 200
    let (status, body) = request(&mut sender, "/api/stats", Some("test-token")).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"total_requests\""));
}

#[tokio::test]
async fn stats_reflects_published_alerts() {
    let (addr, bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    // 发一条告警：直接 publish（模拟拦截）
    let alert = rustgate::bus::Alert::new(
        "1.2.3.4",
        &hyper::Method::GET,
        "/?q=union+select",
        "sqli",
        "rule #1",
        1,
        20,
    );
    bus.publish(alert).await;
    bus.count_request().await;

    let (status, body) = request(&mut sender, "/api/stats", Some("test-token")).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"total_requests\":1"), "body: {body}");
    assert!(body.contains("\"blocked\":1"), "body: {body}");

    // alerts 端点应返回 1 条
    let (status, body) = request(&mut sender, "/api/alerts", Some("test-token")).await;
    assert_eq!(status, hyper::StatusCode::OK);
    assert!(body.contains("\"category\":\"sqli\""), "body: {body}");
}

#[tokio::test]
async fn rest_api_rejects_query_token() {
    // ?token= 只允许 /ws/alerts，REST 端点应 401
    let (addr, _bus) = spawn_api("test-token").await;
    let mut sender = connect(addr).await;

    let (status, _) = request(&mut sender, "/api/stats?token=test-token", None).await;
    assert_eq!(status, hyper::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ws_alerts_pushes_alert_to_subscriber() {
    let (addr, bus) = spawn_api("test-token").await;

    // 用 tokio-tungstenite 客户端连 WS
    let url = format!("ws://{addr}/ws/alerts?token=test-token");
    let (mut ws, _resp) = tokio_tungstenite::connect_async(url).await.unwrap();

    // 等握手稳定后发一条告警
    let alert = rustgate::bus::Alert::new(
        "5.6.7.8",
        &hyper::Method::POST,
        "/login",
        "xss",
        "rule #4",
        4,
        25,
    );
    bus.publish(alert).await;

    // 收一条消息
    let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("超时未收到 WS 告警")
        .expect("WS 流结束")
        .expect("WS 消息错误");
    if let tokio_tungstenite::tungstenite::Message::Text(text) = msg {
        assert!(text.contains("\"category\":\"xss\""), "text: {text}");
    } else {
        panic!("期望文本消息，收到 {msg:?}");
    }
}
